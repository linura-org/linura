#pragma once

namespace Linura::SecurityOwner {
class PeerGuard;
class NativeWaylandLock;
struct NativeSessionBinding;

// Fixed startup transfer only: no policy, lock operation, display layout or
// restoration authority. The compositor remains independently opaque on loss.
[[nodiscard]] bool admitNativeDisplayStartup(PeerGuard &, const NativeSessionBinding &,
                                             NativeWaylandLock &);
} // namespace Linura::SecurityOwner
