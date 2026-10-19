#include "lock_mechanism.h"

#include <limits>
#include <utility>

namespace Linura::SecurityOwner {

LockMechanism::LockMechanism(NativeLockIdentity identity) : identity_(std::move(identity))
{
    const auto parsed = NativeLockIdentity::parse(identity_.resource);
    if (!parsed || *parsed != identity_)
        fault();
}

LockMechanism::State LockMechanism::state() const noexcept
{
    return state_;
}
bool LockMechanism::requestedSecure() const noexcept
{
    return requested_;
}
bool LockMechanism::secureCoverage() const noexcept
{
    return coverage_;
}
const NativeLockIdentity &LockMechanism::identity() const noexcept
{
    return identity_;
}

bool LockMechanism::dispatch(const NativeLockIdentity &identity, bool secure)
{
    if (identity != identity_ || state_ == State::Faulted)
        return false;
    if (secure && state_ == State::Ready) {
        requested_ = true;
        state_ = State::Acquiring;
        return true;
    }
    if (!secure && state_ == State::Secure && coverage_) {
        requested_ = false;
        state_ = State::Releasing;
        return true;
    }
    // No duplicate dispatch acceptance: retries/recovery belong to Control's
    // durable transaction path, not a process-local native replay heuristic.
    return false;
}

void LockMechanism::compositorCoverage(bool secure)
{
    if (state_ == State::Faulted)
        return;
    if (secure && (state_ == State::Acquiring || state_ == State::Secure ||
                   (state_ == State::Releasing && coverage_))) {
        coverage_ = true;
        if (state_ != State::Releasing)
            state_ = State::Secure;
    } else if (!secure && (state_ == State::Ready || state_ == State::Acquiring ||
                           state_ == State::Releasing || state_ == State::Released)) {
        coverage_ = false;
    } else {
        // Losing secure coverage while still requested is not an unlock. The
        // adapter must terminate without sending unlock-and-destroy; a qualified
        // compositor then remains blank. Retain fail-closed requested=true.
        fault();
    }
}

bool LockMechanism::independentlyVerifiedReleased(const NativeLockIdentity &identity)
{
    if (state_ != State::Releasing || identity != identity_ || coverage_ || requested_)
        return false;
    state_ = State::Released;
    return true;
}

bool LockMechanism::commitVerifiedRelease(const NativeLockIdentity &identity)
{
    if (state_ != State::Released || identity != identity_ || coverage_ || requested_)
        return false;
    if (identity_.generation == std::numeric_limits<quint64>::max()) {
        fault();
        return false;
    }
    coverage_ = false;
    requested_ = false;
    ++identity_.generation;
    const qsizetype colon = identity_.resource.lastIndexOf(QLatin1Char(':'));
    identity_.resource = identity_.resource.left(colon + 1) + QString::number(identity_.generation);
    state_ = State::Ready;
    return true;
}

void LockMechanism::fault()
{
    state_ = State::Faulted;
    requested_ = true;
    coverage_ = false;
}

void LockMechanism::ownerLost()
{
    fault();
}

} // namespace Linura::SecurityOwner
