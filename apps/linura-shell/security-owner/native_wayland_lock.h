#pragma once

#include "native_managed_lock_backend.h"
#include "native_keyboard.h"
#include <QImage>
#include <QSize>
#include <cstddef>
#include <memory>

struct wl_display;

namespace Linura::SecurityOwner {

class SecretEntry;

// Owns its exclusive actual Wayland connection. The private runtime factory must
// attest this SAME connection/session and secure-exec protection before binding
// managed dispatch or accepting input. No externally supplied transport DTO.
// Rendering is presentation only; its failure cannot issue an unlock.
class NativeWaylandLock final : public NativeManagedLockBackend
{
  public:
    using Painter = std::function<bool(quint32 output, QImage &opaqueFrame)>;
    static constexpr std::size_t MaximumOutputs = 16;
    static constexpr std::size_t MaximumFrameBytes = 32U * 1024U * 1024U;
    static constexpr std::size_t MaximumRetainedBytes = 256U * 1024U * 1024U;

    NativeWaylandLock(wl_display *ownedDisplay, Painter painter);
    ~NativeWaylandLock() override;
    [[nodiscard]] bool initialize();
    [[nodiscard]] int actualDisplayFd() const noexcept;
    [[nodiscard]] bool available() const noexcept;
    // Native runtime only, before initialization. Entry must outlive the backend;
    // process/session protection must already hold. No QML input route is added.
    using UnlockRequest = std::function<void()>;
    using PrimaryRequestAvailable = std::function<bool()>;
    using PointerHitTest = std::function<NativePointerTarget(QSize, const QPointF &)>;
    [[nodiscard]] bool bindProtectedInput(SecretEntry &entry, UnlockRequest request,
                                          PrimaryRequestAvailable primaryAvailable,
                                          PointerHitTest hitTest = {});
    [[nodiscard]] bool protectedInputAvailable() const noexcept;
    [[nodiscard]] bool protectedInputFocused() const;
    // Bounded observation of already available native events; no effect dispatch.
    void refreshNativeState();
    // Progress already queued native replies between bounded metadata reads.
    // Skip nested native callbacks/rendering; never process Qt/D-Bus/timer events.
    void progressNativeState();
    // Private native interaction, not an effect/approval credential. The runtime
    // arms the exact reviewed NativeApprovalScope first and consumes its fresh
    // confirmation through Control separately. Closing/expiry means denial.
    using LockConfirmation = std::function<void(bool)>;
    [[nodiscard]] bool showLockConfirmation(LockConfirmation completion);
    void cancelLockConfirmation();
    [[nodiscard]] bool lockConfirmationVisible() const noexcept;
    // Native presentation repaint only. No acquisition/release or authority.
    void repaint();
    [[nodiscard]] static bool boundedFrame(quint32 width, quint32 height) noexcept;

  protected:
    [[nodiscard]] bool applyNative(bool secure) override;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::SecurityOwner
