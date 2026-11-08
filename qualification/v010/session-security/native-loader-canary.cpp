// Disposable-guest fixture only. No production installation or authority.
// A positive control must load this into an ordinary unprivileged process;
// the pinned secure-entry compositor must reject the same LD_PRELOAD input.
#include <unistd.h>

namespace {
[[maybe_unused]] const bool loaded = [] {
    if (getuid() == 0 || getuid() != geteuid())
        return false;
    constexpr char marker[] = "linura-loader-canary:loaded\n";
    return write(STDERR_FILENO, marker, sizeof(marker) - 1) ==
           static_cast<ssize_t>(sizeof(marker) - 1);
}();
} // namespace
