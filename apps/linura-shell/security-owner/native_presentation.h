#pragma once

#include <QObject>
#include <QImage>
#include <memory>
#include "native_scope.h"
#include "native_keyboard.h"
#include "native_assistive.h"
#include "native_display_review.h"

namespace Linura::SecurityOwner {
class SecretEntry;

// Fixed first-party presentation only. Owns neither the native connection nor
// policy/approval/effect handles. Never accepts QML source, URLs or secret text.
class NativePresentation final : public QObject
{
    Q_OBJECT
  public:
    enum class State {
        Locked,
        ConfirmingLock,
        Authenticating,
        Denied,
        Unavailable,
        Recovering,
        SleepNotVerified,
        ReviewingDisplay
    };
    explicit NativePresentation(QObject *parent = nullptr);
    ~NativePresentation() override;
    [[nodiscard]] bool initialize();
    [[nodiscard]] bool ready() const noexcept;
    [[nodiscard]] SecretEntry &protectedEntry();
    [[nodiscard]] NativeAssistiveProjection assistiveProjection(bool nativelyVisible) const;
    void present(State state);
    void presentAuthentication(ApprovalPurpose purpose);
    [[nodiscard]] bool presentDisplayReview(const NativeApprovalScope &,
                                            const NativeDisplaySnapshot &, std::size_t page,
                                            bool authenticating = false);
    // Render synchronously into the backend's existing opaque bounded storage.
    // False means the owner must retain native blank coverage, never unlock.
    [[nodiscard]] bool paint(QImage &opaqueFrame);
    // C++ native hit testing only; never a Qt/QML event or authority handle.
    [[nodiscard]] NativePointerTarget pointerTarget(QSize viewport, const QPointF &position);
    // Native-only actionability for Return requests, distinct from PAM submission.
    // Must be checked again at each key press; never a sticky prior render flag.
    [[nodiscard]] bool primaryRequestAvailable() const;

  Q_SIGNALS:
    void repaintRequested();

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace Linura::SecurityOwner
