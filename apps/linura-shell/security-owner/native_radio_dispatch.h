#pragma once

#include "native_radio_method.h"
#include "native_scope.h"
#include "peer_guard.h"

#include <QMap>

#include <optional>

namespace Linura::SecurityOwner {

// The returned state is an execution transport disposition, never independent
// verification of a network postcondition or a durable Control commit.
enum class NativeRadioDispatchDisposition { RejectedBeforeDispatch, Dispatched, Indeterminate };

// The actual sending subject must be permitted by NetworkManager's own
// read-only permission inventory. This is never Control dispatch authority.
[[nodiscard]] bool nativeRadioPermissionGranted(const QMap<QString, QString> &permissions,
                                                NativeRadioMutation mutation);

// Exactly bind the spent protected original-user review to one change and
// direction. A generic AuthenticateNetworkRadio scope is not a reusable grant
// for every other toggle or its inverse.
[[nodiscard]] bool nativeRadioConsentMatches(const NativeApprovalScope &consent,
                                             const NativeLockIdentity &lock,
                                             NativeRadioMutation mutation, bool enabled);

// An original-user native sender's *single* possible transmission. Only the
// native security-owning runtime may construct this object after a future
// separately qualified, spent Control authorization and original-user consent.
// It is not exported via D-Bus, QML, a public factory, or a user-provided bool.
//
// Moving a ticket burns the source. Every attempt spends before any external
// transport call, including when the owner disappears or the call times out.
class NativeRadioDispatchAttempt final
{
    friend class NativeRuntime;
    friend struct NativeRadioDispatchTestAccess;

  public:
    NativeRadioDispatchAttempt(const NativeRadioDispatchAttempt &) = delete;
    NativeRadioDispatchAttempt &operator=(const NativeRadioDispatchAttempt &) = delete;
    NativeRadioDispatchAttempt(NativeRadioDispatchAttempt &&other) noexcept;
    NativeRadioDispatchAttempt &operator=(NativeRadioDispatchAttempt &&) = delete;

    [[nodiscard]] bool spent() const noexcept
    {
        return spent_;
    }

    // Uses only the private original user's already-connected, kernel-attested
    // system bus and the exact supervised NetworkManager *unique* owner. The
    // owner is reattested before/after the one call. Unknown replies, daemon
    // replacement and transport failure are indeterminate and never retried.
    [[nodiscard]] NativeRadioDispatchDisposition
    dispatch(const PeerGuard &peers, const NativeLockIdentity &liveLock,
             const NativePeerIdentity &liveNetworkManager);

  private:
    NativeRadioDispatchAttempt(NativeApprovalScope consumedConsent, NativeLockIdentity lock,
                               NativePeerIdentity manager, NativeRadioMutation mutation,
                               bool enabled);
    [[nodiscard]] std::optional<NativeRadioMethod> spend(const NativeLockIdentity &lock,
                                                         const NativePeerIdentity &manager);

    NativeApprovalScope consumedConsent_;
    NativeLockIdentity lock_;
    NativePeerIdentity manager_;
    NativeRadioMutation mutation_;
    bool enabled_ = false;
    bool spent_ = false;
};

} // namespace Linura::SecurityOwner
