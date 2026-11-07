#include "secret_entry.h"
#include "native_accessibility.h"

#include <QFocusEvent>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPalette>
#include <QThread>

#include <algorithm>
#include <limits>
#include <utility>
#include <time.h>

namespace Linura::SecurityOwner {
namespace {
std::optional<quint64> promptBootMs()
{
    timespec value{};
    if (clock_gettime(CLOCK_BOOTTIME, &value) != 0 || value.tv_sec < 0 || value.tv_nsec < 0 ||
        value.tv_nsec >= 1'000'000'000 ||
        static_cast<quint64>(value.tv_sec) > (std::numeric_limits<quint64>::max() - 30'999) / 1000)
        return std::nullopt;
    return static_cast<quint64>(value.tv_sec) * 1000 +
           static_cast<quint64>(value.tv_nsec) / 1'000'000;
}
} // namespace

SecretEntry::SecretEntry(QQuickItem *parent) : QQuickPaintedItem(parent)
{
    installProtectedInputAccessibility();
    const QPalette palette = QGuiApplication::palette();
    foreground_ = palette.color(QPalette::Text);
    surface_ = palette.color(QPalette::Base);
    focusColor_ = palette.color(QPalette::Highlight);
    setAcceptedMouseButtons(Qt::LeftButton);
    setActiveFocusOnTab(true);
    // No IME/preedit text, clipboard, selection, drag-and-drop, predictive text
    // or accessibility value store can retain a second copy of the response.
    setFlag(QQuickItem::ItemAcceptsInputMethod, false);
    promptTimer_.setSingleShot(true);
    promptTimer_.setInterval(30'000);
    connect(&promptTimer_, &QTimer::timeout, this, &SecretEntry::cancelFromInteraction);
    connect(this, &QQuickItem::enabledChanged, this, [this] {
        if (!isEnabled())
            cancelFromInteraction();
    });
    connect(this, &QQuickItem::visibleChanged, this, [this] {
        if (!isVisible())
            cancelFromInteraction();
    });
    connect(this, &QQuickItem::activeFocusChanged, this, [this] { update(); });
}

SecretEntry::~SecretEntry()
{
    cancelNativePrompt();
}

bool SecretEntry::storageAvailable() const noexcept
{
    return buffer_.available();
}
bool SecretEntry::acceptsInput() const noexcept
{
    return accepting_;
}
int SecretEntry::maskedLength() const noexcept
{
    return static_cast<int>(buffer_.length());
}
QColor SecretEntry::foreground() const
{
    return foreground_;
}
QColor SecretEntry::surface() const
{
    return surface_;
}
QColor SecretEntry::focusColor() const
{
    return focusColor_;
}

QString SecretEntry::nativeAccessibleName() const
{
    return (accepting_ || prepared_) && !promptLabel_.isEmpty()
               ? promptLabel_
               : QStringLiteral("Protected authentication response");
}
bool SecretEntry::nativeAccessibilityFocused() const noexcept
{
    return nativeFocused_ || hasActiveFocus();
}

void SecretEntry::setForeground(const QColor &color)
{
    if (color.isValid() && color != foreground_) {
        foreground_ = color;
        Q_EMIT styleChanged();
        update();
    }
}

void SecretEntry::setSurface(const QColor &color)
{
    if (color.isValid() && color != surface_) {
        surface_ = color;
        Q_EMIT styleChanged();
        update();
    }
}

void SecretEntry::setFocusColor(const QColor &color)
{
    if (color.isValid() && color != focusColor_) {
        focusColor_ = color;
        Q_EMIT styleChanged();
        update();
    }
}

void SecretEntry::paint(QPainter *painter)
{
    painter->setRenderHint(QPainter::Antialiasing);
    painter->setBrush(surface_);
    const bool focused = nativeFocused_ || hasActiveFocus();
    painter->setPen(QPen(focused ? focusColor_ : foreground_, focused ? 2 : 1));
    painter->drawRoundedRect(boundingRect().adjusted(1, 1, -1, -1), 10, 10);
    painter->setPen(foreground_);
    const QString mask(std::min(maskedLength(), 24), QChar(char16_t(0x2022)));
    const auto area = boundingRect().adjusted(12, 0, -12, 0);
    painter->drawText(
        area, Qt::AlignVCenter | Qt::AlignLeft,
        mask.isEmpty() && (accepting_ || prepared_)
            ? painter->fontMetrics().elidedText(promptLabel_, Qt::ElideRight, int(area.width()))
            : mask);
}

bool SecretEntry::beginNativePrompt(NativePromptKind kind, quint32 step, std::optional<quint32> uid)
{
    const auto token = preparePrompt(kind, step, uid, false);
    return token && activatePrepared(*token, false);
}

std::optional<quint64> SecretEntry::prepareNativePrompt(NativePromptKind kind, quint32 step,
                                                        std::optional<quint32> uid)
{
    return preparePrompt(kind, step, uid, true);
}

std::optional<quint64> SecretEntry::preparePrompt(NativePromptKind kind, quint32 step,
                                                  std::optional<quint32> uid, bool publish)
{
    const auto label = nativePromptLabel(kind, step, uid);
    const auto time = promptBootMs();
    if (QThread::currentThread() != thread() || !storageAvailable() || accepting_ || prepared_ ||
        responding_ || !isEnabled() || !isVisible() || !label ||
        preparationToken_ == std::numeric_limits<quint64>::max() || !time)
        return std::nullopt;
    buffer_.clear();
    promptLabel_ = *label;
    identityChoices_.clear();
    identityPresentationGated_ = false;
    prepared_ = true;
    ++preparationToken_;
    const auto token = preparationToken_;
    preparedBootStart_ = *time;
    preparedBootDeadline_ = *time + 30'000;
    promptTimer_.start();
    if (publish) {
        announceProtectedInputMetadata(*this);
        Q_EMIT inputChanged();
        update();
    }
    return token;
}

bool SecretEntry::activatePrepared(quint64 token, bool requireNativeFocus)
{
    if (QThread::currentThread() != thread() || !prepared_ || accepting_ || responding_ ||
        token == 0 || token != preparationToken_ || !storageAvailable() || !isEnabled() ||
        !isVisible() || !promptTimer_.isActive() ||
        (requireNativeFocus && (!nativeInputBound_ || !nativeFocused_)))
        return false;
    const auto time = promptBootMs();
    if (!time || *time < preparedBootStart_ || *time >= preparedBootDeadline_) {
        cancelFromInteraction();
        return false;
    }
    prepared_ = false;
    accepting_ = true;
    // Do not restart the original timer or replace the prepared label/token.
    announceProtectedInputMetadata(*this);
    Q_EMIT inputChanged();
    update();
    return accepting_ && token == preparationToken_;
}

bool SecretEntry::activatePreparedNativePrompt(quint64 token)
{
    return activatePrepared(token, true);
}

bool SecretEntry::preparedNativePromptMatches(quint64 token) const
{
    const auto time = promptBootMs();
    return QThread::currentThread() == thread() && prepared_ && !accepting_ && !responding_ &&
           token != 0 && token == preparationToken_ && storageAvailable() && isEnabled() &&
           isVisible() && promptTimer_.isActive() && time && *time >= preparedBootStart_ &&
           *time < preparedBootDeadline_;
}

void SecretEntry::showIdentityChoice(bool publish)
{
    if (identityChoices_.isEmpty())
        return;
    promptLabel_ = QStringLiteral("Admin %1/%2: UID %3 (Up/Down, Enter)")
                       .arg(identityIndex_ + 1)
                       .arg(identityChoices_.size())
                       .arg(identityChoices_[identityIndex_]);
    if (publish) {
        announceProtectedInputMetadata(*this);
        Q_EMIT inputChanged();
        update();
    }
}

bool SecretEntry::beginNativeIdentitySelection(const QVector<quint32> &uids)
{
    const auto token = prepareIdentity(uids, false);
    return token && activatePrepared(*token, false);
}

std::optional<quint64> SecretEntry::prepareNativeIdentitySelection(const QVector<quint32> &uids)
{
    return prepareIdentity(uids, true);
}

std::optional<quint64> SecretEntry::prepareIdentity(const QVector<quint32> &uids, bool publish)
{
    const auto time = promptBootMs();
    if (QThread::currentThread() != thread() || accepting_ || prepared_ || responding_ ||
        !storageAvailable() || !isEnabled() || !isVisible() || uids.size() < 2 || uids.size() > 8 ||
        preparationToken_ == std::numeric_limits<quint64>::max() || !time)
        return std::nullopt;
    for (int index = 0; index < static_cast<int>(uids.size()); ++index) {
        if (uids[index] > static_cast<quint32>(std::numeric_limits<int>::max()))
            return std::nullopt;
        for (int other = 0; other < index; ++other)
            if (uids[other] == uids[index])
                return std::nullopt;
    }
    buffer_.clear();
    identityChoices_ = uids;
    identityPresentationGated_ = publish;
    identityIndex_ = 0;
    prepared_ = true;
    ++preparationToken_;
    const auto token = preparationToken_;
    preparedBootStart_ = *time;
    preparedBootDeadline_ = *time + 30'000;
    promptTimer_.start();
    showIdentityChoice(publish);
    return token;
}

bool SecretEntry::respondToNativePrompt(const std::function<void(const char *)> &response)
{
    if (QThread::currentThread() != thread() || !accepting_ || responding_)
        return false;
    accepting_ = false;
    prepared_ = false;
    responding_ = true;
    promptTimer_.stop();
    try {
        const bool sent = buffer_.respond(response);
        responding_ = false;
        if (std::exchange(cancelAfterResponse_, false)) {
            cancelNativePrompt();
            Q_EMIT cancellationRequested();
            return sent;
        }
        Q_EMIT inputChanged();
        update();
        return sent;
    } catch (...) {
        buffer_.clear();
        responding_ = false;
        const bool cancelled = std::exchange(cancelAfterResponse_, false);
        Q_EMIT inputChanged();
        update();
        if (cancelled)
            Q_EMIT cancellationRequested();
        throw;
    }
}

void SecretEntry::cancelNativePrompt()
{
    if (responding_) {
        // A visibility/focus/native cancellation cannot wipe or release the
        // response pointer while the official helper still consumes it.
        cancelAfterResponse_ = true;
        return;
    }
    accepting_ = false;
    prepared_ = false;
    preparedBootStart_ = preparedBootDeadline_ = 0;
    promptTimer_.stop();
    buffer_.clear();
    promptLabel_.clear();
    identityChoices_.clear();
    identityPresentationGated_ = false;
    identityIndex_ = 0;
    announceProtectedInputMetadata(*this);
    Q_EMIT inputChanged();
    update();
}

void SecretEntry::cancelFromInteraction()
{
    if (responding_) {
        cancelAfterResponse_ = true;
        return;
    }
    const bool wasAccepting = accepting_ || prepared_;
    cancelNativePrompt();
    if (wasAccepting)
        Q_EMIT cancellationRequested();
}

void SecretEntry::suspendForExpectedPresentation()
{
    // Only zero-input prepared metadata may survive an expected frame revision.
    // Active input, actual focus loss and all ordinary cancellation still wipe.
    if (QThread::currentThread() != thread())
        return;
    if (prepared_ && !accepting_ && !responding_ && buffer_.length() == 0) {
        nativeFocused_ = false;
        return;
    }
    setNativeKeyboardFocus(false);
}

void SecretEntry::setNativeKeyboardFocus(bool focused)
{
    if (focused && nativeFocused_)
        return; // No repeated accessibility focus announcement for each press.
    // Every loss still cancels, including a prompt awaiting its first focus.
    nativeFocused_ = focused;
    if (!focused)
        cancelFromInteraction();
    else {
        announceProtectedInputFocus(*this);
        Q_EMIT inputChanged();
        update();
    }
}

void SecretEntry::keyPressEvent(QKeyEvent *event)
{
    // Never propagate typed password keys to a parent handler/ordinary shell.
    event->accept();
    if (!accepting_ || nativeInputBound_)
        return;
    if (!identityChoices_.isEmpty() && event->modifiers() != Qt::NoModifier)
        return;
    if (handleCommand(event->key()))
        return;
    if (!(event->modifiers() & (Qt::ControlModifier | Qt::MetaModifier)) ||
        (event->modifiers() & Qt::GroupSwitchModifier)) {
        const QString text = event->text();
        (void)buffer_.append(QStringView(text));
    }
    Q_EMIT inputChanged();
    update();
}

bool SecretEntry::bindNativeInput()
{
    if (QThread::currentThread() != thread() || nativeInputBound_ || accepting_ || prepared_ ||
        responding_)
        return false;
    nativeInputBound_ = true;
    return true;
}

void SecretEntry::nativeKey(int key, Qt::KeyboardModifiers modifiers, std::string_view text)
{
    if (!nativeInputBound_ || !nativeFocused_ || !accepting_ ||
        QThread::currentThread() != thread())
        return;
    if (!identityChoices_.isEmpty() && modifiers != Qt::NoModifier)
        return;
    if (handleCommand(key))
        return;
    if (!(modifiers & (Qt::ControlModifier | Qt::MetaModifier)) ||
        (modifiers & Qt::GroupSwitchModifier))
        (void)buffer_.appendUtf8(text);
    Q_EMIT inputChanged();
    update();
}

bool SecretEntry::handleCommand(int key)
{
    if (!identityChoices_.isEmpty()) {
        if (key == Qt::Key_Escape || key == Qt::Key_Tab || key == Qt::Key_Backtab) {
            cancelFromInteraction();
        } else if (key == Qt::Key_Up || key == Qt::Key_Down) {
            if (identityPresentationGated_ &&
                preparationToken_ == std::numeric_limits<quint64>::max()) {
                cancelFromInteraction();
                return true;
            }
            const auto count = static_cast<int>(identityChoices_.size());
            identityIndex_ = (identityIndex_ + count + (key == Qt::Key_Up ? -1 : 1)) % count;
            if (identityPresentationGated_) {
                accepting_ = false;
                prepared_ = true;
                const auto token = ++preparationToken_;
                // Preserve the original preparation BOOTTIME/timer window.
                showIdentityChoice();
                if (prepared_ && identityPresentationGated_ && token == preparationToken_)
                    Q_EMIT identityPresentationRequested(token);
                return true;
            }
            showIdentityChoice();
        } else if (key == Qt::Key_Return || key == Qt::Key_Enter) {
            // The native authentication owner must revalidate this candidate,
            // then transition to PAM; never treat selection as authentication.
            Q_EMIT identitySelected(identityChoices_[identityIndex_]);
        }
        return true; // No identity-selection keys enter protected response bytes.
    }
    if (key == Qt::Key_Escape) {
        cancelFromInteraction();
        return true;
    }
    if (key == Qt::Key_Return || key == Qt::Key_Enter) {
        // The native consumer must respond synchronously, before another key.
        Q_EMIT submissionRequested();
        return true;
    }
    if (key == Qt::Key_Backspace) {
        buffer_.eraseLast();
    } else if (key == Qt::Key_Delete) {
        buffer_.clear();
    } else if (key == Qt::Key_Tab || key == Qt::Key_Backtab) {
        cancelFromInteraction();
    } else
        return false;
    Q_EMIT inputChanged();
    update();
    return true;
}

void SecretEntry::focusOutEvent(QFocusEvent *event)
{
    cancelFromInteraction();
    QQuickPaintedItem::focusOutEvent(event);
}

void SecretEntry::keyReleaseEvent(QKeyEvent *event)
{
    // Key releases can carry the same native text as presses. They must not
    // bubble to a QML parent/general key logger merely because they do not edit.
    event->accept();
}

void SecretEntry::mousePressEvent(QMouseEvent *event)
{
    if ((accepting_ || prepared_) && !nativeInputBound_)
        forceActiveFocus(Qt::MouseFocusReason);
    event->accept();
}

} // namespace Linura::SecurityOwner
