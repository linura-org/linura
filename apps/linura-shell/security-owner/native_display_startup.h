#pragma once

namespace Linura::SecurityOwner {
class PeerGuard;
class NativeWaylandLock;
struct NativeSessionBinding;

// Fixed startup transfer only: no policy, lock operation, display layout or
// restoration authority. The compositor remains independently opaque on loss.
enum class NativeDisplayStartupAdmission {
    Ready,
    NativeSample,
    Session,
    NativeImage,
    OriginalGuard,
    GuardReply,
    GuardChanged,
    SessionChanged,
    KernelPeer,
    NativeTransfer,
};
// Fixed closed stages only; no raw reply, path or private identity is logged.
[[nodiscard]] NativeDisplayStartupAdmission
admitNativeDisplayStartup(PeerGuard &, const NativeSessionBinding &, NativeWaylandLock &);
} // namespace Linura::SecurityOwner
