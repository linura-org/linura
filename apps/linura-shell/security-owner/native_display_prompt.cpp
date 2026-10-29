#include "native_display_prompt.h"
#include <algorithm>

namespace Linura::SecurityOwner {
bool NativeDisplayPromptScope::valid() const noexcept
{
    return digest.size() == 64 &&
           std::any_of(digest.begin(), digest.end(),
                       [](QChar c) { return c != QLatin1Char('0'); }) &&
           std::all_of(digest.begin(), digest.end(),
                       [](QChar c) {
                           return (c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                                  (c >= QLatin1Char('a') && c <= QLatin1Char('f'));
                       }) &&
           deadlineUnixMs != 0 &&
           (purpose == Purpose::Apply || purpose == Purpose::Keep || purpose == Purpose::Revert);
}
} // namespace Linura::SecurityOwner
