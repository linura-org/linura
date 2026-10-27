#pragma once

#include <functional>
#include <memory>
#include <QPointF>
#include <QtGlobal>

class QImage;
struct wl_seat;
struct wl_surface;

namespace Linura::SecurityOwner {

class SecretEntry;

// Presentation hit target, not an approval/effect credential. The revision
// prevents a held click from migrating into a different state or prompt.
struct NativePointerTarget final
{
    enum class Action { None, Primary, Cancel };
    Action action = Action::None;
    quint64 revision = 0;
    quint32 configureSerial = 0;
    bool operator==(const NativePointerTarget &) const = default;
};

// Adapter-private input on the lock backend's exclusive Wayland connection.
// No QML event delivery, clipboard, IME, text callback or general input sink.
// Construction/binding belongs to the attested protected runtime, not the shell.
class NativeKeyboard final
{
  public:
    using SurfaceGuard = std::function<bool(wl_surface *)>;
    using CoverageGuard = std::function<bool()>;
    using UnlockRequest = std::function<void()>;
    // Native presentation must attest the current displayed primary action.
    // Missing/stale state never permits an unlock request.
    using PrimaryRequestAvailable = std::function<bool()>;
    using PointerHitTest = std::function<NativePointerTarget(wl_surface *, const QPointF &)>;
    using Repaint = std::function<void()>;
    NativeKeyboard(SecretEntry &entry, SurfaceGuard guard, CoverageGuard coverage,
                   UnlockRequest request, PrimaryRequestAvailable primaryAvailable,
                   PointerHitTest hitTest = {}, Repaint repaint = {});
    ~NativeKeyboard();
    NativeKeyboard(const NativeKeyboard &) = delete;
    NativeKeyboard &operator=(const NativeKeyboard &) = delete;

    // Takes ownership, including on failure. One seat per qualified owner.
    [[nodiscard]] bool bind(wl_seat *ownedSeat);
    [[nodiscard]] bool available() const noexcept;
    [[nodiscard]] bool focused() const;
    [[nodiscard]] quint64 interactionGeneration() const noexcept;
    void forgetSurface(wl_surface *surface);
    void resetFocus();
    // Recheck only the bound compositor focus and coverage; never synthesize input.
    void refreshProtectedFocus();
    // Drop the live prompt/compose/click state without inventing a new enter
    // or forgetting physically held keys. Coverage may settle on the same
    // native focus, but an old response or held submit cannot migrate there.
    void invalidateOutputConfiguration();
    void paintPointer(wl_surface *surface, QImage &frame) const;
    // Private pre-lock confirmation only. No text is decoded or delivered while
    // this target is selected. A new unmodified Enter/Escape press is required;
    // generic Qt events, held keys and repeat do not confirm anything.
    using Confirmation = std::function<void(bool)>;
    [[nodiscard]] bool setConfirmationTarget(wl_surface *surface, Confirmation completion);
    void clearConfirmationTarget();

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::SecurityOwner
