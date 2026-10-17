// Software-renderer component checks, NOT visual/accessibility qualification.
#include "native_presentation.h"
#include "secret_entry.h"

#include <QGuiApplication>
#include <QKeyEvent>
#include <QQuickWindow>

#include <array>
#include <cassert>
#include <cstring>
#include <limits>

using namespace Linura::SecurityOwner;

int main(int argc, char **argv)
{
    QQuickWindow::setSceneGraphBackend(QStringLiteral("software"));
    QGuiApplication application(argc, argv);
    NativePresentation presentation;
    assert(presentation.initialize());
    assert(presentation.ready());
    assert(!presentation.initialize());
    assert(presentation.metaObject()->indexOfMethod("paint()") == -1);
    assert(presentation.metaObject()->indexOfMethod("protectedEntry()") == -1);
    assert(presentation.metaObject()->indexOfMethod("presentAuthentication(ApprovalPurpose)") ==
           -1);
    assert(presentation.metaObject()->indexOfMethod("pointerTarget(QSize,QPointF)") == -1);
    assert(presentation.metaObject()->indexOfMethod("assistiveProjection(bool)") == -1);
    auto &entry = presentation.protectedEntry();
    assert(entry.storageAvailable() && !entry.acceptsInput());
    assert(entry.metaObject()->indexOfProperty("text") == -1);
    assert(entry.metaObject()->indexOfProperty("password") == -1);

    QImage frame(640, 480, QImage::Format_RGB32);
    const auto *storage = frame.constBits();
    frame.fill(0xffff00ff);
    assert(presentation.paint(frame));
    assert(frame.constBits() == storage);
    assert(frame.pixel(0, 0) != 0xffff00ff);
    const auto findTarget = [&](QSize viewport, NativePointerTarget::Action wanted) {
        for (int y = 0; y < viewport.height(); y += 5)
            for (int x = 0; x < viewport.width(); x += 5) {
                const QPointF position(x, y);
                const auto target = presentation.pointerTarget(viewport, position);
                if (target.action == wanted)
                    return position;
            }
        assert(false);
        return QPointF();
    };
    const auto primary = findTarget(frame.size(), NativePointerTarget::Action::Primary);
    const auto originalTarget = presentation.pointerTarget(frame.size(), primary);
    assert(originalTarget.action == NativePointerTarget::Action::Primary &&
           originalTarget.revision != 0);
    assert(presentation.pointerTarget(frame.size(), QPointF(-1, 0)).action ==
           NativePointerTarget::Action::None);
    assert(presentation
               .pointerTarget(frame.size(), QPointF(std::numeric_limits<double>::quiet_NaN(), 0))
               .action == NativePointerTarget::Action::None);
    assert(presentation.pointerTarget(QSize(0, 480), primary).action ==
           NativePointerTarget::Action::None);
    presentation.present(NativePresentation::State::ConfirmingLock);
    const auto cancel = findTarget(frame.size(), NativePointerTarget::Action::Cancel);
    assert(presentation.pointerTarget(frame.size(), cancel).action ==
           NativePointerTarget::Action::Cancel);
    const auto confirm = findTarget(frame.size(), NativePointerTarget::Action::Primary);
    assert(presentation.pointerTarget(frame.size(), confirm).revision != originalTarget.revision);
    // Per-output hit testing cannot reuse the last rendered monitor geometry.
    const auto smallPrimary = findTarget(QSize(320, 240), NativePointerTarget::Action::Primary);
    assert(presentation.pointerTarget(QSize(320, 240), smallPrimary).action ==
           NativePointerTarget::Action::Primary);
    assert(presentation.pointerTarget(frame.size(), smallPrimary).action ==
           NativePointerTarget::Action::None);

    presentation.present(NativePresentation::State::Authenticating);
    assert(presentation.pointerTarget(frame.size(), primary).action ==
           NativePointerTarget::Action::None);
    QImage masked;
    for (unsigned character = 0; character < 2; ++character) {
        assert(entry.beginNativePrompt());
        const auto metadata = presentation.assistiveProjection(true);
        assert(metadata.visible && metadata.accepting);
        assert(!presentation.assistiveProjection(false).accepting);
        const auto promptPrimary = findTarget(frame.size(), NativePointerTarget::Action::Primary);
        const auto promptTarget = presentation.pointerTarget(frame.size(), promptPrimary);
        assert(promptTarget.action == NativePointerTarget::Action::Primary);
        const QString text(1, QChar(static_cast<char16_t>(0x61 + character)));
        QKeyEvent key(QEvent::KeyPress, Qt::Key_unknown, Qt::NoModifier, text);
        QCoreApplication::sendEvent(&entry, &key); // Component fixture only.
        assert(entry.maskedLength() == 1);
        assert(presentation.assistiveProjection(true) == metadata);
        assert(presentation.pointerTarget(frame.size(), promptPrimary).revision !=
               promptTarget.revision);
        assert(presentation.paint(frame));
        if (character == 0)
            masked = frame.copy();
        else
            assert(masked == frame); // Response values never change rendered text.
        assert(entry.respondToNativePrompt(
            [](const char *response) { assert(std::strlen(response) == 1); }));
        assert(entry.maskedLength() == 0 && !entry.acceptsInput());
    }
    QImage firstPrompt, firstMasked;
    for (const auto kind : {NativePromptKind::Password, NativePromptKind::VerificationCode}) {
        assert(entry.beginNativePrompt(kind, 2, 1000));
        assert(presentation.paint(frame));
        assert(firstPrompt.isNull() || firstPrompt != frame);
        firstPrompt = frame.copy();
        const QString generated(1, QChar(char16_t(0x78)));
        QKeyEvent key(QEvent::KeyPress, Qt::Key_unknown, Qt::NoModifier, generated);
        QCoreApplication::sendEvent(&entry, &key);
        assert(presentation.paint(frame));
        assert(firstMasked.isNull() || firstMasked == frame);
        firstMasked = frame.copy(); // Fixed metadata never renders response contents.
        entry.cancelNativePrompt();
    }
    for (auto state : std::array{
             NativePresentation::State::Locked, NativePresentation::State::ConfirmingLock,
             NativePresentation::State::Denied, NativePresentation::State::Unavailable,
             NativePresentation::State::Recovering, NativePresentation::State::SleepNotVerified}) {
        presentation.present(state);
        for (auto size : std::array{QSize(320, 240), QSize(1280, 720), QSize(1920, 1080)}) {
            QImage resized(size, QImage::Format_RGB32);
            const auto *pixels = resized.constBits();
            assert(presentation.paint(resized));
            assert(resized.constBits() == pixels && resized.size() == size);
        }
    }
    QImage invalid(640, 480, QImage::Format_ARGB32);
    assert(!presentation.paint(invalid));
    QImage empty;
    assert(!presentation.paint(empty));
    QImage previous;
    for (auto purpose :
         std::array{ApprovalPurpose::AuthenticateUnlock, ApprovalPurpose::AuthenticateSuspend,
                    ApprovalPurpose::AuthenticateLogout, ApprovalPurpose::AuthenticateReboot,
                    ApprovalPurpose::AuthenticatePowerOff, ApprovalPurpose::EnableProtectiveLock,
                    ApprovalPurpose::RevokeProtectiveLock}) {
        presentation.presentAuthentication(purpose);
        assert(presentation.ready() && presentation.paint(frame));
        assert(previous.isNull() || previous != frame);
        previous = frame.copy();
        assert(entry.beginNativePrompt());
        for (auto size :
             std::array{QSize(320, 240), QSize(480, 320), QSize(1280, 720), QSize(1920, 1080)}) {
            QImage resized(size, QImage::Format_RGB32);
            assert(presentation.paint(resized));
            const QRectF input(entry.position(), entry.size());
            assert(input.width() > 0 && input.height() > 0);
            assert(QRectF(QPointF(0, 0), size).contains(input));
            const auto submit = findTarget(size, NativePointerTarget::Action::Primary);
            const auto cancel = findTarget(size, NativePointerTarget::Action::Cancel);
            assert(submit.y() > input.bottom() && cancel.y() > input.bottom());
        }
        entry.cancelNativePrompt();
    }
    QImage tooSmall(160, 80, QImage::Format_RGB32);
    assert(!presentation.paint(tooSmall)); // No overlapping or clipped security prompt.
    assert(presentation.pointerTarget(tooSmall.size(), QPointF(80, 40)).action ==
           NativePointerTarget::Action::None);
    assert(presentation.ready() && presentation.paint(frame));
    presentation.present(static_cast<NativePresentation::State>(99));
    assert(!presentation.ready() && !presentation.paint(frame));
    return 0;
}
