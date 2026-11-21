#pragma once

#include "native_display_layout.h"

namespace Linura::SecurityOwner {
// Bounded LNOR comparison for fresh protected presentation. These fields are
// never an approval, Root credential, completed frame, or cleanup authority.
struct NativeDisplayOrdinaryReleaseIntent final
{
    static constexpr qsizetype MaxBytes = 6 * 1024;
    enum class Outcome { Keep, Revert, Expired };
    QString originalRequest, originalDispatch, terminalRecord, originalCheckpoint, signedBinding,
        sourceGuard;
    quint64 generation = 0, stateVersion = 0;
    Outcome outcome = Outcome::Keep;
    NativeLockIdentity currentLock;
    NativeDisplayIntent original;

    [[nodiscard]] static std::optional<NativeDisplayOrdinaryReleaseIntent> parse(const QString &);
    [[nodiscard]] QString encode() const;
    [[nodiscard]] NativeDisplayIntent presentation() const;
    // Normal display-management wire phases. The separate original-restoration
    // adapter's phase 3 must never certify an ordinary terminal state.
    [[nodiscard]] quint32 expectedAttemptPhase() const noexcept
    {
        return outcome == Outcome::Keep ? 4U : 5U;
    }
    [[nodiscard]] static bool terminalAttemptPhase(quint32 phase) noexcept
    {
        return phase == 4U || phase == 5U;
    }
    [[nodiscard]] static bool retainedAttemptPhase(quint32 phase) noexcept
    {
        return phase >= 2U && phase <= 5U;
    }
    [[nodiscard]] bool matchesCurrent(const NativeDisplaySnapshot &, const QString &exactTopology,
                                      const NativeLockIdentity &exactLock) const;
};
} // namespace Linura::SecurityOwner
