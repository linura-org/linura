#pragma once

#include "secret_buffer.h"
#include "native_prompt.h"

#include <QColor>
#include <QQuickPaintedItem>
#include <QTimer>

#include <functional>

namespace Linura::SecurityOwner {

// Native protected input, not TextInput.text/echoMode. QML can style it and see
// generic input availability, but cannot read, set, copy or submit its contents.
// Submission carries no data; only the native authentication handler responds.
class SecretEntry final : public QQuickPaintedItem
{
    Q_OBJECT
    Q_PROPERTY(bool storageAvailable READ storageAvailable CONSTANT)
    Q_PROPERTY(bool acceptsInput READ acceptsInput NOTIFY inputChanged)
    Q_PROPERTY(int maskedLength READ maskedLength NOTIFY inputChanged)
    Q_PROPERTY(QColor foreground READ foreground WRITE setForeground NOTIFY styleChanged)
    Q_PROPERTY(QColor surface READ surface WRITE setSurface NOTIFY styleChanged)
    Q_PROPERTY(QColor focusColor READ focusColor WRITE setFocusColor NOTIFY styleChanged)

  public:
    explicit SecretEntry(QQuickItem *parent = nullptr);
    ~SecretEntry() override;
    [[nodiscard]] bool storageAvailable() const noexcept;
    [[nodiscard]] bool acceptsInput() const noexcept;
    [[nodiscard]] int maskedLength() const noexcept;
    [[nodiscard]] QColor foreground() const;
    [[nodiscard]] QColor surface() const;
    [[nodiscard]] QColor focusColor() const;
    // Fixed prompt/UID/step metadata only, never a text/value authority surface.
    [[nodiscard]] QString nativeAccessibleName() const;
    [[nodiscard]] bool nativeAccessibilityFocused() const noexcept;
    void setForeground(const QColor &color);
    void setSurface(const QColor &color);
    void setFocusColor(const QColor &color);
    void paint(QPainter *painter) override;

    // C++ only; never declared Q_INVOKABLE, a slot or a writable QML property.
    [[nodiscard]] bool beginNativePrompt(NativePromptKind kind = NativePromptKind::Response,
                                         quint32 step = 1,
                                         std::optional<quint32> uid = std::nullopt);
    [[nodiscard]] bool respondToNativePrompt(const std::function<void(const char *)> &response);
    void cancelNativePrompt();

  Q_SIGNALS:
    void inputChanged();
    void styleChanged();
    void submissionRequested();
    void cancellationRequested();

  protected:
    void keyPressEvent(QKeyEvent *event) override;
    void keyReleaseEvent(QKeyEvent *event) override;
    void focusOutEvent(QFocusEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;

  private:
    friend class NativeKeyboard;
    [[nodiscard]] bool bindNativeInput();
    void nativeKey(int key, Qt::KeyboardModifiers modifiers, std::string_view text);
    [[nodiscard]] bool handleCommand(int key);
    void setNativeKeyboardFocus(bool focused);
    void cancelFromInteraction();
    SecretBuffer buffer_;
    QTimer promptTimer_;
    bool accepting_ = false;
    bool responding_ = false;
    bool cancelAfterResponse_ = false;
    bool nativeFocused_ = false;
    bool nativeInputBound_ = false;
    QColor foreground_;
    QColor surface_;
    QColor focusColor_;
    QString promptLabel_; // Fixed labels plus numeric metadata, never native question/response.
};

} // namespace Linura::SecurityOwner
