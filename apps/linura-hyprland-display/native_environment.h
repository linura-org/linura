#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <unistd.h>

namespace Linura::HyprlandDisplay {
// No allocation, application singleton or dynamic initialization: called by
// the executable's ELF preinit entry before dependency/C++ constructors. Secure
// exec separately protects the dynamic loader before preinit can run.
inline constexpr std::array NativeEnvironmentNames{"HOME",
                                                   "USER",
                                                   "LOGNAME",
                                                   "SHELL",
                                                   "PATH",
                                                   "LANG",
                                                   "LC_ALL",
                                                   "LC_CTYPE",
                                                   "LC_COLLATE",
                                                   "LC_MESSAGES",
                                                   "LC_NUMERIC",
                                                   "LC_TIME",
                                                   "LC_MONETARY",
                                                   "LC_PAPER",
                                                   "LC_NAME",
                                                   "LC_ADDRESS",
                                                   "LC_TELEPHONE",
                                                   "LC_MEASUREMENT",
                                                   "LC_IDENTIFICATION",
                                                   "TERM",
                                                   "COLORTERM",
                                                   "XDG_RUNTIME_DIR",
                                                   "XDG_CONFIG_HOME",
                                                   "XDG_CACHE_HOME",
                                                   "XDG_SESSION_ID",
                                                   "XDG_SESSION_TYPE",
                                                   "XDG_SESSION_CLASS",
                                                   "XDG_CURRENT_DESKTOP",
                                                   "XDG_SESSION_DESKTOP",
                                                   "XDG_SEAT",
                                                   "XDG_VTNR",
                                                   "DBUS_SESSION_BUS_ADDRESS",
                                                   "LIBSEAT_BACKEND",
                                                   "LIBGL_ALWAYS_SOFTWARE",
                                                   "WLR_RENDERER_ALLOW_SOFTWARE",
                                                   "AQ_NO_KMS_REQUIREMENT",
                                                   "QT_QUICK_BACKEND"};

[[nodiscard]] inline bool nativeEnvironmentValue(std::string_view name,
                                                 std::string_view value) noexcept
{
    if (name == "LIBSEAT_BACKEND")
        return value == "logind";
    if (name == "QT_QUICK_BACKEND")
        return value == "software";
    if (name == "LIBGL_ALWAYS_SOFTWARE" || name == "WLR_RENDERER_ALLOW_SOFTWARE" ||
        name == "AQ_NO_KMS_REQUIREMENT")
        return value == "0" || value == "1";
    return true;
}

[[nodiscard]] inline bool sanitizeNativeEnvironment(char **environment) noexcept
{
    if (!environment)
        return false;
    std::array<char *, NativeEnvironmentNames.size()> retained{};
    std::array<bool, NativeEnvironmentNames.size()> present{};
    std::size_t count = 0, consumed = 0, total = 0;
    for (; consumed < 256 && environment[consumed]; ++consumed) {
        const auto length = strnlen(environment[consumed], 8193);
        if (length > 8192 || total + length + 1 > 65536)
            return false;
        total += length + 1;
        const std::string_view entry(environment[consumed], length);
        const auto delimiter = entry.find('=');
        if (delimiter == std::string_view::npos || delimiter == 0)
            return false;
        const auto name = entry.substr(0, delimiter);
        for (std::size_t key = 0; key < NativeEnvironmentNames.size(); ++key) {
            if (name != NativeEnvironmentNames[key])
                continue;
            if (present[key] || !nativeEnvironmentValue(name, entry.substr(delimiter + 1)))
                return false;
            present[key] = true;
            retained[count++] = environment[consumed];
            break;
        }
    }
    if (consumed == 256)
        return false;
    // Rewrite the original vector too: constructors receiving envp directly
    // must see the same filtered environment as libc getenv. Validate first,
    // so malformed/ambiguous input never leaves a partially filtered vector.
    for (std::size_t index = 0; index <= consumed; ++index)
        environment[index] = index < count ? retained[index] : nullptr;
    return true;
}

inline void initializeNativeEnvironment(int, char **, char **environment) noexcept
{
    if (!sanitizeNativeEnvironment(environment)) {
        constexpr char diagnostic[] = "Linura native environment unavailable\n";
        const auto written = write(STDERR_FILENO, diagnostic, sizeof(diagnostic) - 1);
        (void)written;
        _exit(78);
    }
    ::environ = environment;
}
} // namespace Linura::HyprlandDisplay
