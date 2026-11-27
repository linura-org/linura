#pragma once

#include "secret_buffer.h"
#include "native_prompt.h"

#include <QColor>
#include <QQuickPaintedItem>
#include <QTimer>
#include <QVector>

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
    // Display-only first-frame staging. Preparation exposes only fixed metadata,
    // accepts no input and starts the ORIGINAL prompt timeout. The native owner
    // activates the exact token after its matching protected hardware frame.
    // Tokens are comparison data, never authentication or an execution grant.
    [[nodiscard]] std::optional<quint64> prepareNativePrompt(NativePromptKind kind, quint32 step,
                                                             std::optional<quint32> uid);
    [[nodiscard]] std::optional<quint64>
    prepareNativeIdentitySelection(const QVector<quint32> &uids);
    [[nodiscard]] bool activatePreparedNativePrompt(quint64 token);
    [[nodiscard]] bool preparedNativePromptMatches(quint64 token) const;
    [[nodiscard]] bool respondToNativePrompt(const std::function<void(const char *)> &response);
    void cancelNativePrompt();
    // Official Polkit provides the identities; selection is native-keyboard-only.
    [[nodiscard]] bool beginNativeIdentitySelection(const QVector<quint32> &uids);

  Q_SIGNALS:
    void inputChanged();
    void styleChanged();
    void submissionRequested();
    void cancellationRequested();
    void identitySelected(quint32 uid);
    void identityPresentationRequested(quint64 token);

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
    void suspendForExpectedPresentation();
    [[nodiscard]] bool activatePrepared(quint64 token, bool requireNativeFocus);
    [[nodiscard]] std::optional<quint64> preparePrompt(NativePromptKind, quint32 step,
                                                       std::optional<quint32> uid, bool publish);
    [[nodiscard]] std::optional<quint64> prepareIdentity(const QVector<quint32> &, bool publish);
    void cancelFromInteraction();
    void showIdentityChoice(bool publish = true);
    SecretBuffer buffer_;
    QTimer promptTimer_;
    bool accepting_ = false;
    bool responding_ = false;
    bool cancelAfterResponse_ = false;
    bool nativeFocused_ = false;
    bool nativeInputBound_ = false;
    bool prepared_ = false;
    bool identityPresentationGated_ = false;
    quint64 preparationToken_ = 0;
    quint64 preparedBootStart_ = 0, preparedBootDeadline_ = 0;
    QColor foreground_;
    QColor surface_;
    QColor focusColor_;
    QString promptLabel_; // Fixed labels plus numeric metadata, never native question/response.
    QVector<quint32> identityChoices_;
    int identityIndex_ = 0;
};

} // namespace Linura::SecurityOwner
