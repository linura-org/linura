#pragma once

#include "native_display_restoration.h"

namespace Linura::SecurityOwner {

// Untrusted terminal comparison material, distinct from LNRI:1. Decoding does
// not authenticate linked history, a human, a prepared effect or current frames.
// No approval purpose, native write or protection-release endpoint is armed here.
struct NativeDisplayFinalizationIntent final
{
    static constexpr qsizetype MaxBytes = 14 * 1024;
    QString restorationRequest, restorationDispatch, terminalLink, restoredSourceGuard;
    quint64 postWriteEpoch = 0;
    NativeLockIdentity currentLock;
    NativeDisplayRestorationIntent restoration;

    [[nodiscard]] static std::optional<NativeDisplayFinalizationIntent> parse(const QString &);
    [[nodiscard]] QString encode() const;
    // Supplied facts must come from the current bounded native mechanism. This
    // comparison cannot substitute for Root continuity or independent KMS proof.
    [[nodiscard]] bool matchesRestored(const NativeDisplaySnapshot &, const QString &exactTopology,
                                       const NativeLockIdentity &exactLock,
                                       quint64 currentPostWriteEpoch) const;
};

} // namespace Linura::SecurityOwner
