#include "native_transition_fence.h"

#include <array>
#include <charconv>
#include <limits>
#include <string>
#include <string_view>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace Linura::SecurityOwner {
namespace {
std::optional<std::string> sysfsRead(const char *path)
{
    const int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0)
        return std::nullopt;
    struct stat metadata
    {};
    struct statfs filesystem
    {};
    std::array<char, 129> bytes{};
    const bool trusted = fstat(descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
                         metadata.st_uid == 0 && (metadata.st_mode & 022) == 0 &&
                         metadata.st_nlink == 1 && fstatfs(descriptor, &filesystem) == 0 &&
                         filesystem.f_type == SYSFS_MAGIC;
    const auto count = trusted ? read(descriptor, bytes.data(), bytes.size()) : -1;
    close(descriptor);
    if (count <= 0 || static_cast<std::size_t>(count) >= bytes.size())
        return std::nullopt;
    return std::string(bytes.data(), static_cast<std::size_t>(count));
}
} // namespace

std::optional<quint64> nativeSuccessfulSuspendCycles()
{
    const auto testMode = sysfsRead("/sys/power/pm_test");
    const auto counter = sysfsRead("/sys/power/suspend_stats/success");
    if (!testMode || !counter)
        return std::nullopt;
    return decodeNativeSuspendCycles(*testMode, *counter);
}

std::optional<quint64> decodeNativeSuspendCycles(std::string_view testMode, std::string_view text)
{
    if (testMode.empty() || testMode.size() > 128 || !testMode.ends_with('\n') || text.empty() ||
        text.size() > 21)
        return std::nullopt;
    testMode.remove_suffix(1);
    constexpr std::array<std::string_view, 6> Modes{"[none]",   "core",    "processors",
                                                    "platform", "devices", "freezer"};
    std::array<bool, Modes.size()> seen{};
    while (!testMode.empty()) {
        const auto start = testMode.find_first_not_of(' ');
        if (start == std::string_view::npos)
            break;
        testMode.remove_prefix(start);
        const auto end = testMode.find(' ');
        const auto field = testMode.substr(0, end);
        bool found = false;
        for (std::size_t i = 0; i < Modes.size(); ++i) {
            if (field != Modes[i])
                continue;
            if (seen[i])
                return std::nullopt;
            found = seen[i] = true;
            break;
        }
        if (!found)
            return std::nullopt;
        if (end == std::string_view::npos)
            break;
        testMode.remove_prefix(end + 1);
    }
    if (!seen[0])
        return std::nullopt; // Any selected debug/test mode fails closed.
    if (!text.ends_with('\n'))
        return std::nullopt;
    text.remove_suffix(1);
    if (text.empty() || (text.size() > 1 && text.front() == '0'))
        return std::nullopt;
    quint64 cycles = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), cycles);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size())
        return std::nullopt;
    return cycles;
}

bool NativeTransitionFence::arm(const NativeTransitionIdentity &target,
                                const NativeLockIdentity &current, bool independentlySecure,
                                std::optional<quint64> successfulCycles)
{
    if (pending_ || !independentlySecure || target.lock != current ||
        NativeTransitionIdentity::parse(target.resource) != target ||
        (committed_ && *committed_ == target))
        return false;
    if (target.transition == NativeSessionTransition::Suspend &&
        (!successfulCycles || *successfulCycles != target.successfulCyclesBefore ||
         *successfulCycles == std::numeric_limits<quint64>::max()))
        return false;
    pending_ = target;
    return true;
}

bool NativeTransitionFence::cancelUndispatched(const NativeTransitionIdentity &target)
{
    if (!pending_ || *pending_ != target)
        return false;
    pending_.reset();
    return true;
}

bool NativeTransitionFence::commitSuspend(const NativeTransitionIdentity &target,
                                          const NativeLockIdentity &current,
                                          bool independentlySecure,
                                          std::optional<quint64> successfulCycles)
{
    if (target.transition != NativeSessionTransition::Suspend || target.lock != current ||
        !independentlySecure || !successfulCycles ||
        target.successfulCyclesBefore == std::numeric_limits<quint64>::max() ||
        *successfulCycles != target.successfulCyclesBefore + 1)
        return false;
    // Lost commit replies are idempotent and cannot retire another pending
    // transition, rotate a lock generation, or unlock anything.
    if (committed_ && *committed_ == target)
        return true;
    if (!pending_ || *pending_ != target)
        return false;
    committed_ = target;
    pending_.reset();
    return true;
}
} // namespace Linura::SecurityOwner
