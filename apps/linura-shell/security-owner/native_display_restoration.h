#pragma once

#include "native_display_layout.h"
#include <map>

namespace Linura::SecurityOwner {

// Private comparison material for a NEW protected Recovery interaction. These
// values prove neither original kernel continuity nor canonical authorization.
// Control owns history/planning/approval/prepare; the compositor must separately
// consume the original Guard's one-use endpoint before any restoration write.
struct NativeDisplayRestorationIntent final
{
    using Output = std::pair<quint64, quint64>;
    QString originalRequest, originalDispatch, originalCheckpoint, replacementBaselineGuard;
    NativeDisplayIntent original, replacement;
    std::map<Output, Output> outputs;

    [[nodiscard]] static std::optional<NativeDisplayRestorationIntent> parse(const QString &);
    [[nodiscard]] QString encode() const;
    // Only freshly acquired replacement facts may satisfy this comparison.
    // Historical material does not become a current observation here.
    [[nodiscard]] bool nativeOptions(const NativeDisplaySnapshot &, const QString &exactTopology,
                                     const NativeLockIdentity &exactLock) const;
};

} // namespace Linura::SecurityOwner
