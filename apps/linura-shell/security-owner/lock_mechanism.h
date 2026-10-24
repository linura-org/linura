#pragma once

#include "native_scope.h"

namespace Linura::SecurityOwner {

// Native compositor mechanism state, independent of approval state. The sealed
// transport may call dispatch only after its executor/control peer attestation;
// authentication completion never calls it. Events are fed by the lock protocol,
// not by an ordinary shell DTO, LockedHint, screen counts or cached evidence.
class LockMechanism final
{
  public:
    enum class State { Ready, Acquiring, Secure, Releasing, Released, Faulted };

    explicit LockMechanism(NativeLockIdentity identity);
    [[nodiscard]] State state() const noexcept;
    [[nodiscard]] bool requestedSecure() const noexcept;
    [[nodiscard]] bool secureCoverage() const noexcept;
    [[nodiscard]] const NativeLockIdentity &identity() const noexcept;
    [[nodiscard]] bool dispatch(const NativeLockIdentity &identity, bool secure);
    void compositorCoverage(bool secure);
    // Independent native postcondition, not the local requested=false state or
    // the protocol unlock acknowledgement. The adapter attests the compositor.
    [[nodiscard]] bool independentlyVerifiedReleased(const NativeLockIdentity &identity);
    // Read the proof left by the one-shot independent verification. Ready and
    // any replaced generation never supply evidence of a release.
    [[nodiscard]] bool retainedVerifiedRelease(const NativeLockIdentity &identity) const;
    // Retain the old resource for verification/recovery until trusted Control
    // acknowledges its durable verified commit. This advances only native
    // bookkeeping, never dispatches a compositor effect. No client/QML caller.
    [[nodiscard]] bool commitVerifiedRelease(const NativeLockIdentity &identity);
    void ownerLost();

  private:
    void fault();
    NativeLockIdentity identity_;
    State state_ = State::Ready;
    bool requested_ = false;
    bool coverage_ = false;
};

} // namespace Linura::SecurityOwner
