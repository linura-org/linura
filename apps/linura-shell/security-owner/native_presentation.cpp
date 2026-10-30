#include "native_presentation.h"
#include "secret_entry.h"

#include <QDir>
#include <QLibraryInfo>
#include <QQmlAbstractUrlInterceptor>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQuickRenderControl>
#include <QQuickRenderTarget>
#include <QQuickWindow>
#include <QQuickStyle>
#include <QThread>
#include <QTimer>

#include <array>
#include <cmath>
#include <mutex>
#include <tuple>

// Q_INIT_RESOURCE must resolve its generated symbol in the global namespace.
static void initializePresentationResources()
{
    Q_INIT_RESOURCE(linura_security_owner_presentation);
}

namespace Linura::SecurityOwner {
namespace {
class PresentationUrls final : public QQmlAbstractUrlInterceptor
{
  public:
    QString qtRoot = QDir(QLibraryInfo::path(QLibraryInfo::QmlImportsPath)).canonicalPath();
    QUrl intercept(const QUrl &url, DataType) override
    {
        if (url.scheme() == QStringLiteral("qrc") &&
            (url.path().startsWith(QStringLiteral("/linura/security-owner/")) ||
             url.path().startsWith(QStringLiteral("/qt-project.org/imports/"))))
            return url;
        // No source-relative/user import routes. Qt's immutable distribution
        // modules are the only filesystem imports; deployment attests that root.
        if (!qtRoot.isEmpty() && url.isLocalFile()) {
            const auto canonical = QFileInfo(url.toLocalFile()).canonicalFilePath();
            if (canonical.startsWith(qtRoot + QLatin1Char('/')))
                return url;
        }
        return QUrl(QStringLiteral("qrc:/linura/security-owner/denied"));
    }
};
} // namespace

class NativePresentation::Impl final
{
  public:
    NativePresentation &owner;
    PresentationUrls urls;
    std::unique_ptr<QQmlEngine> engine;
    std::unique_ptr<QQuickRenderControl> control;
    std::unique_ptr<QQuickWindow> window;
    std::unique_ptr<QQuickItem> root;
    SecretEntry entry;
    State state = State::Locked;
    ApprovalPurpose authenticationPurpose = ApprovalPurpose::AuthenticateUnlock;
    std::optional<NativeDisplayReviewPage> displayPage;
    QString displayPrimary;
    bool attempted = false;
    bool initialized = false;
    bool rendering = false;
    bool scheduled = false;
    bool faulted = false;
    quint64 interactionRevision = 1;

    explicit Impl(NativePresentation &instance) : owner(instance)
    {
        QObject::connect(&entry, &SecretEntry::inputChanged, &owner, [this] {
            advanceInteraction();
            schedule();
        });
        QObject::connect(&entry, &SecretEntry::styleChanged, &owner, [this] { schedule(); });
    }
    ~Impl()
    {
        entry.setParentItem(nullptr);
        root.reset();
        if (window)
            window->setRenderTarget({});
        if (control)
            control->invalidate();
        window.reset();
        control.reset();
        engine.reset();
    }
    void schedule()
    {
        if (scheduled)
            return;
        scheduled = true;
        QTimer::singleShot(0, &owner, [this] {
            scheduled = false;
            if (!rendering)
                Q_EMIT owner.repaintRequested();
            else
                schedule();
        });
    }
    bool correctThread() const
    {
        return owner.thread() == QThread::currentThread();
    }
    void advanceInteraction()
    {
        if (++interactionRevision == 0)
            faulted = true;
    }
    void setText()
    {
        if (!root)
            return;
        entry.setVisible(state == State::Authenticating);
        QString title;
        QString explanation;
        switch (state) {
        case State::Locked:
            title = QStringLiteral("Session locked");
            explanation =
                QStringLiteral("Press Enter or choose Request unlock. Authentication is required.");
            break;
        case State::ConfirmingLock:
            title = QStringLiteral("Lock this session?");
            explanation = QStringLiteral("Lock all displays in this session? Enter confirms; "
                                         "Escape cancels.");
            break;
        case State::Authenticating:
            if (displayPage) {
                title = QStringLiteral("Authenticate: ") + displayPage->heading;
                explanation = displayPage->explanation;
                break;
            }
            switch (authenticationPurpose) {
            case ApprovalPurpose::AuthenticateUnlock:
                title = QStringLiteral("Authenticate to unlock");
                explanation = QStringLiteral(
                    "Enter the session owner's response. Enter submits; Escape cancels.");
                break;
            case ApprovalPurpose::AuthenticateSuspend:
                title = QStringLiteral("Authorize suspend");
                explanation = QStringLiteral("Administrator authentication required to suspend. "
                                             "Your session stays locked. Escape cancels.");
                break;
            case ApprovalPurpose::AuthenticateLogout:
                title = QStringLiteral("Authorize logout");
                explanation = QStringLiteral("Administrator authentication required to log out. "
                                             "Unsaved work may be lost. Escape cancels.");
                break;
            case ApprovalPurpose::AuthenticateReboot:
                title = QStringLiteral("Authorize restart");
                explanation = QStringLiteral("Administrator authentication required to restart. "
                                             "Unsaved work may be lost. Escape cancels.");
                break;
            case ApprovalPurpose::AuthenticatePowerOff:
                title = QStringLiteral("Authorize shutdown");
                explanation = QStringLiteral("Administrator authentication required to shut down. "
                                             "Unsaved work may be lost. Escape cancels.");
                break;
            case ApprovalPurpose::EnableProtectiveLock:
                title = QStringLiteral("Enable protective lock?");
                explanation = QStringLiteral("Owner authentication allows pre-sleep locking for "
                                             "this login. Never unlocks. Failure may block sleep. "
                                             "Escape cancels.");
                break;
            case ApprovalPurpose::RevokeProtectiveLock:
                title = QStringLiteral("Revoke protective lock?");
                explanation = QStringLiteral("Owner authentication revokes pre-sleep locking for "
                                             "this login. Never unlocks or authorizes sleep. "
                                             "Escape cancels.");
                break;
            case ApprovalPurpose::ConfirmLock:
            default:
                faulted = true;
                return;
            }
            break;
        case State::ReviewingDisplay:
            if (!displayPage) {
                faulted = true;
                return;
            }
            title = displayPage->heading;
            explanation = displayPage->explanation;
            break;
        case State::PreparingDisplay:
            title = QStringLiteral("Preparing display change");
            explanation = QStringLiteral("Authentication completed. Linura is checking this "
                                         "display change before applying it.");
            break;
        case State::ApplyingDisplay:
            title = QStringLiteral("Applying display layout");
            explanation = QStringLiteral("Linura is checking each display. Recovery may be "
                                         "needed if the change cannot be verified.");
            break;
        case State::Denied:
            title = QStringLiteral("Authentication not completed");
            explanation =
                QStringLiteral("Your session remains locked. Wait briefly before trying again.");
            break;
        case State::Unavailable:
            title = QStringLiteral("Unlock unavailable");
            explanation = QStringLiteral("The protected authentication service is unavailable. "
                                         "Native recovery is required.");
            break;
        case State::Recovering:
            title = QStringLiteral("Checking session state");
            explanation = QStringLiteral("Linura is verifying recovery. Press Enter to check "
                                         "again. No action will be blindly replayed.");
            break;
        case State::SleepNotVerified:
            title = QStringLiteral("Sleep not verified");
            explanation =
                QStringLiteral("This computer may still be running. Keep it ventilated. "
                               "Your session stays locked; unlock requires authentication.");
            break;
        default:
            faulted = true;
            return;
        }
        const bool actionable = state == State::Locked || state == State::SleepNotVerified ||
                                state == State::ConfirmingLock || state == State::Recovering ||
                                state == State::ReviewingDisplay ||
                                (state == State::Authenticating && entry.acceptsInput());
        const bool cancellable = state == State::ConfirmingLock ||
                                 state == State::ReviewingDisplay ||
                                 (state == State::Authenticating && entry.acceptsInput());
        if (!root->setProperty("inputVisible", state == State::Authenticating) ||
            !root->setProperty("heading", title) ||
            !root->setProperty("explanation", explanation) ||
            !root->setProperty("primaryLabel",
                               state == State::ReviewingDisplay ? displayPrimary
                               : state == State::ConfirmingLock ? QStringLiteral("Lock session")
                               : state == State::Authenticating ? QStringLiteral("Submit response")
                               : state == State::Recovering     ? QStringLiteral("Check recovery")
                                                            : QStringLiteral("Request unlock")) ||
            !root->setProperty("primaryAvailable", actionable) ||
            !root->setProperty("cancelAvailable", cancellable))
            faulted = true;
    }
};

NativePresentation::NativePresentation(QObject *parent)
    : QObject(parent), impl_(std::make_unique<Impl>(*this))
{}
NativePresentation::~NativePresentation() = default;
bool NativePresentation::ready() const noexcept
{
    return impl_->initialized && !impl_->faulted;
}
SecretEntry &NativePresentation::protectedEntry()
{
    return impl_->entry;
}

NativeAssistiveProjection NativePresentation::assistiveProjection(bool nativelyVisible) const
{
    if (!impl_->correctThread() || !ready() || !impl_->root)
        return {};
    const bool accepting =
        nativelyVisible && impl_->state == State::Authenticating && impl_->entry.acceptsInput();
    return {impl_->root->property("heading").toString(),
            impl_->root->property("explanation").toString(),
            impl_->entry.nativeAccessibleName(),
            nativelyVisible,
            accepting,
            accepting && impl_->entry.nativeAccessibilityFocused()};
}

bool NativePresentation::initialize()
{
    if (!impl_->correctThread() || impl_->attempted || !impl_->entry.storageAvailable() ||
        QQuickWindow::sceneGraphBackend() != QStringLiteral("software") ||
        impl_->urls.qtRoot.isEmpty())
        return false;
    impl_->attempted = true;
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    static std::once_flag resources;
    static bool protectedModule = false;
    std::call_once(resources, [] {
        initializePresentationResources();
        // Embed the actual shared UI sources, not copies or a separately styled
        // lock UI. The private runtime cannot discover an extension/plugin copy.
        for (const auto &type : std::array<const char *, 4>{"LinuraTheme", "LinuraSurface",
                                                            "LinuraText", "LinuraButton"}) {
            qmlRegisterType(QUrl(QStringLiteral("qrc:/linura/security-owner/ui/") +
                                 QString::fromLatin1(type) + QStringLiteral(".qml")),
                            "org.linura.UI", 1, 0, type);
        }
        qmlRegisterModule("org.linura.UI", 1, 0);
        protectedModule = qmlProtectModule("org.linura.UI", 1);
    });
    if (!protectedModule)
        return false;
    impl_->engine = std::make_unique<QQmlEngine>();
    impl_->engine->setImportPathList(
        {impl_->urls.qtRoot, QStringLiteral("qrc:/qt-project.org/imports")});
    impl_->engine->setOutputWarningsToStandardError(false);
    impl_->engine->addUrlInterceptor(&impl_->urls);
    connect(impl_->engine.get(), &QQmlEngine::warnings, this, [this] { impl_->faulted = true; });
    impl_->control = std::make_unique<QQuickRenderControl>();
    impl_->window = std::make_unique<QQuickWindow>(impl_->control.get());
    if (impl_->window->rendererInterface()->graphicsApi() != QSGRendererInterface::Software)
        return false;
    impl_->window->setColor(Qt::black);
    connect(impl_->control.get(), &QQuickRenderControl::renderRequested, this,
            [this] { impl_->schedule(); });
    connect(impl_->control.get(), &QQuickRenderControl::sceneChanged, this,
            [this] { impl_->schedule(); });
    QQmlComponent component(
        impl_->engine.get(),
        QUrl(QStringLiteral("qrc:/linura/security-owner/LockPresentation.qml")));
    if (component.status() != QQmlComponent::Ready)
        return false;
    std::unique_ptr<QObject> object(component.create());
    auto *item = qobject_cast<QQuickItem *>(object.get());
    if (!item || impl_->faulted)
        return false;
    QQmlEngine::setObjectOwnership(item, QQmlEngine::CppOwnership);
    object.release();
    impl_->root.reset(item);
    item->setParentItem(impl_->window->contentItem());
    impl_->entry.setParentItem(impl_->window->contentItem());
    impl_->entry.setZ(10);
    impl_->entry.setClip(true);
    impl_->setText();
    impl_->initialized = !impl_->faulted;
    return ready();
}

void NativePresentation::present(State state)
{
    if (!impl_->correctThread() || impl_->rendering) {
        impl_->faulted = true;
        return;
    }
    impl_->state = state;
    impl_->displayPage.reset();
    impl_->displayPrimary.clear();
    impl_->advanceInteraction();
    impl_->setText();
    impl_->schedule();
}

void NativePresentation::presentAuthentication(ApprovalPurpose purpose)
{
    if (!impl_->correctThread() || impl_->rendering || purpose == ApprovalPurpose::ConfirmLock) {
        impl_->faulted = true;
        return;
    }
    impl_->authenticationPurpose = purpose;
    present(State::Authenticating);
}

bool NativePresentation::presentDisplayReview(const NativeApprovalScope &scope,
                                              const NativeDisplaySnapshot &snapshot,
                                              std::size_t page, bool authenticating)
{
    if (!impl_->correctThread() || !ready() || impl_->rendering)
        return false;
    const auto pages = nativeDisplayReviewPages(scope, snapshot);
    if (!pages || page >= pages->size() || (authenticating && page + 1 != pages->size()))
        return false;
    impl_->displayPage = pages->at(page);
    impl_->displayPage->heading += QStringLiteral(" (%1/%2)").arg(page + 1).arg(pages->size());
    impl_->displayPrimary =
        page + 1 == pages->size() ? QStringLiteral("Authenticate") : QStringLiteral("Next");
    impl_->authenticationPurpose = scope.purpose;
    impl_->state = authenticating ? State::Authenticating : State::ReviewingDisplay;
    impl_->advanceInteraction();
    impl_->setText();
    impl_->schedule();
    return ready();
}

bool NativePresentation::paint(QImage &frame)
{
    if (!impl_->correctThread() || !ready() || impl_->rendering || frame.isNull() ||
        frame.format() != QImage::Format_RGB32 || frame.width() > 8192 || frame.height() > 8192 ||
        frame.sizeInBytes() > 32 * 1024 * 1024)
        return false;
    impl_->setText();
    impl_->rendering = true;
    struct FrameScope final
    {
        Impl &impl;
        ~FrameScope()
        {
            impl.window->setRenderTarget({});
            impl.rendering = false;
        }
    } scope{*impl_};
    impl_->window->setGeometry(0, 0, frame.width(), frame.height());
    impl_->window->contentItem()->setSize(frame.size());
    impl_->root->setSize(frame.size());
    impl_->control->polishItems();
    const auto rectangle = impl_->root->property("inputRectangle").toRectF();
    if (!std::isfinite(rectangle.x()) || !std::isfinite(rectangle.y()) ||
        !std::isfinite(rectangle.width()) || !std::isfinite(rectangle.height()) ||
        rectangle.width() < 0 || rectangle.height() < 0 ||
        (impl_->state == State::Authenticating &&
         !QRectF(QPointF(0, 0), frame.size()).contains(rectangle)) ||
        !impl_->root->property("layoutFits").toBool())
        return false;
    impl_->entry.setPosition(rectangle.topLeft());
    impl_->entry.setSize(rectangle.size());
    impl_->entry.setForeground(impl_->root->property("inputForeground").value<QColor>());
    impl_->entry.setSurface(impl_->root->property("inputSurface").value<QColor>());
    impl_->entry.setFocusColor(impl_->root->property("inputFocusColor").value<QColor>());
    impl_->window->setRenderTarget(QQuickRenderTarget::fromPaintDevice(&frame));
    impl_->control->polishItems();
    (void)impl_->control->sync();
    impl_->control->render();
    return ready();
}

bool NativePresentation::primaryRequestAvailable() const
{
    if (!impl_->correctThread() || !ready() || impl_->rendering)
        return false;
    if (impl_->entry.acceptsInput() || !impl_->root)
        return false;
    // The sole no-prompt actions mirror the first-party primary button.
    // Authentication, denial, unavailability and confirmation have separate
    // native paths and may not start a new Control unlock request.
    switch (impl_->state) {
    case State::Locked:
    case State::Recovering:
    case State::SleepNotVerified:
    case State::ReviewingDisplay:
        break;
    default:
        return false;
    }
    return impl_->root->property("primaryAvailable").toBool() &&
           impl_->root->property("layoutFits").toBool();
}

NativePointerTarget NativePresentation::pointerTarget(QSize viewport, const QPointF &position)
{
    if (!impl_->correctThread() || !ready() || impl_->rendering || viewport.width() <= 0 ||
        viewport.height() <= 0 || viewport.width() > 8192 || viewport.height() > 8192 ||
        !std::isfinite(position.x()) || !std::isfinite(position.y()) ||
        !QRectF(QPointF(0, 0), viewport).contains(position))
        return {};
    // Each output has its own configure dimensions. Never hit-test against the
    // last-rendered monitor's layout. This updates presentation geometry only.
    impl_->setText();
    impl_->window->setGeometry(0, 0, viewport.width(), viewport.height());
    impl_->window->contentItem()->setSize(viewport);
    impl_->root->setSize(viewport);
    impl_->control->polishItems();
    if (!impl_->root->property("layoutFits").toBool())
        return {};
    for (const auto &[available, rectangle, action] :
         std::array{std::tuple{"primaryAvailable", "primaryRectangle",
                               NativePointerTarget::Action::Primary},
                    std::tuple{"cancelAvailable", "cancelRectangle",
                               NativePointerTarget::Action::Cancel}}) {
        const auto area = impl_->root->property(rectangle).toRectF();
        if (impl_->root->property(available).toBool() && area.isValid() &&
            QRectF(QPointF(0, 0), viewport).contains(area) && area.contains(position))
            return {action, impl_->interactionRevision};
    }
    return {};
}
} // namespace Linura::SecurityOwner
