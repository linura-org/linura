// Disposable-guest read-only qualification client, never a product effector.
// Calls the exact admission predicate linked into the pinned compositor.
#include "native_owner_admission.h"

#include <charconv>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string_view>
#include <unistd.h>

using namespace Linura::HyprlandDisplay;

int main(int argc, char **argv)
{
    if (argc != 2 || getuid() == 0 || getuid() != geteuid())
        return 1;
    const std::string_view value(argv[1]);
    if (value.empty() || value.size() > 10 || value.front() == '0')
        return 1;
    unsigned long supplied = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), supplied);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || supplied <= 1 ||
        supplied > static_cast<unsigned long>(std::numeric_limits<pid_t>::max()))
        return 1;
    const auto owner = static_cast<pid_t>(supplied);
    const auto admitted = attestDisplayOwner(owner, getuid());
    if (!admitted || attestDisplayOwner(getpid(), getuid()) || attestDisplayOwner(owner, 0) ||
        attestDisplayOwner(0, getuid()))
        return 1;
    std::cout << "schema_version=1\nnative_owner_pid=" << owner << "\nnative_owner_uid=" << getuid()
              << "\nnative_owner_invocation=";
    for (const auto byte : *admitted)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    std::cout << "\nroot-supervised-owner-admitted=true\nsame-uid-probe-denied=true\n"
                 "root-uid-denied=true\ninvalid-pid-denied=true\n";
    return std::cout.good() ? 0 : 1;
}
