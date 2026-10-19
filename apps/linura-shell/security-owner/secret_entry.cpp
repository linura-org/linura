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
#include <utility>

namespace Linura::SecurityOwner {

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
    return accepting_ && !promptLabel_.isEmpty()
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
        mask.isEmpty() && accepting_
            ? painter->fontMetrics().elidedText(promptLabel_, Qt::ElideRight, int(area.width()))
            : mask);
}

bool SecretEntry::beginNativePrompt(NativePromptKind kind, quint32 step, std::optional<quint32> uid)
{
    const auto label = nativePromptLabel(kind, step, uid);
    if (QThread::currentThread() != thread() || !storageAvailable() || accepting_ || responding_ ||
        !isEnabled() || !isVisible() || !label)
        return false;
    buffer_.clear();
    promptLabel_ = *label;
    accepting_ = true;
    announceProtectedInputMetadata(*this);
    promptTimer_.start();
    Q_EMIT inputChanged();
    update();
    return true;
}

bool SecretEntry::respondToNativePrompt(const std::function<void(const char *)> &response)
{
    if (QThread::currentThread() != thread() || !accepting_ || responding_)
        return false;
    accepting_ = false;
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
    promptTimer_.stop();
    buffer_.clear();
    promptLabel_.clear();
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
    const bool wasAccepting = accepting_;
    cancelNativePrompt();
    if (wasAccepting)
        Q_EMIT cancellationRequested();
}

void SecretEntry::setNativeKeyboardFocus(bool focused)
{
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
    if (QThread::currentThread() != thread() || nativeInputBound_ || accepting_ || responding_)
        return false;
    nativeInputBound_ = true;
    return true;
}

void SecretEntry::nativeKey(int key, Qt::KeyboardModifiers modifiers, std::string_view text)
{
    if (!nativeInputBound_ || !nativeFocused_ || !accepting_ ||
        QThread::currentThread() != thread())
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
    if (accepting_ && !nativeInputBound_)
        forceActiveFocus(Qt::MouseFocusReason);
    event->accept();
}

} // namespace Linura::SecurityOwner
