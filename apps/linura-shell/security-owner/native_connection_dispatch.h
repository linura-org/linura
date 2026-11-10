#pragma once

#include "native_connection_method.h"
#include "native_scope.h"
#include "peer_guard.h"

#include <optional>

namespace Linura::SecurityOwner {

// Transport result only. Neither Dispatched nor an NM method reply establishes
// a verified network postcondition or permits a durable Control commit.
enum class NativeConnectionDispatchDisposition {
    RejectedBeforeDispatch,
    Dispatched,
    Indeterminate
};

// Future private native-runtime composition only. No public D-Bus, QML or
// Control endpoint may construct one. The original durably spent Control grant,
// specific approval and source-pinned preflight are STILL required at that
// future construction site; this type is not a substitute for any of them.
class NativeConnectionDispatchAttempt final
{
    friend class NativeRuntime;
    friend struct NativeConnectionDispatchTestAccess;

  public:
    NativeConnectionDispatchAttempt(const NativeConnectionDispatchAttempt &) = delete;
    NativeConnectionDispatchAttempt &operator=(const NativeConnectionDispatchAttempt &) = delete;
    NativeConnectionDispatchAttempt(NativeConnectionDispatchAttempt &&other) noexcept;
    NativeConnectionDispatchAttempt &operator=(NativeConnectionDispatchAttempt &&) = delete;

    [[nodiscard]] bool spent() const noexcept
    {
        return spent_;
    }

    // Only the security owner's own already-connected system bus can send.
    // Spend precedes every transport/permission check, including failures.
    // A reply does not establish DHCP, routing, DNS or remote-control survival.
    [[nodiscard]] NativeConnectionDispatchDisposition
    dispatch(const PeerGuard &peers, const NativeLockIdentity &liveLock,
             const NativePeerIdentity &liveNetworkManager);

  private:
    NativeConnectionDispatchAttempt(NativeLockIdentity lock, NativePeerIdentity manager,
                                    NativeConnectionMethod method);
    [[nodiscard]] std::optional<NativeConnectionMethod> spend(const NativeLockIdentity &lock,
                                                              const NativePeerIdentity &manager);

    NativeLockIdentity lock_;
    NativePeerIdentity manager_;
    NativeConnectionMethod method_;
    bool spent_ = false;
};

} // namespace Linura::SecurityOwner
