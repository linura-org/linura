#pragma once

#include "native_display_layout.h"

namespace Linura::SecurityOwner {
// Fixed first-party, non-executable projection. The caller must bind each page
// to a fresh protected configure/presentation before accepting native input.
// Pages never carry a handle to authentication, policy or display execution.
struct NativeDisplayReviewPage final
{
    QString heading, explanation;
};
[[nodiscard]] std::optional<std::vector<NativeDisplayReviewPage>>
nativeDisplayReviewPages(const NativeApprovalScope &, const NativeDisplaySnapshot &);
} // namespace Linura::SecurityOwner
