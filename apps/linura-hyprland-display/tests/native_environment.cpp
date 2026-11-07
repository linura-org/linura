#include "native_environment.h"

#include <cassert>
#include <cstdlib>
#include <string>
#include <vector>

using namespace Linura::HyprlandDisplay;
namespace {
using Preinit = void (*)(int, char **, char **);
[[gnu::used, gnu::section(".preinit_array")]]
Preinit const initialize = &initializeNativeEnvironment;
const bool filteredBeforeCppConstructor =
    std::getenv("__EGL_VENDOR_LIBRARY_FILENAMES") == nullptr &&
    std::getenv("LINURA_NATIVE_ENV_TEST") == nullptr;

void expectRefusal(std::vector<std::string> values)
{
    std::vector<char *> entries;
    for (auto &value : values)
        entries.push_back(value.data());
    entries.push_back(nullptr);
    const auto before = entries;
    assert(!sanitizeNativeEnvironment(entries.data()));
    assert(entries == before); // Validate every input before rewriting envp.
}
} // namespace
extern "C" bool linuraEnvironmentFilteredBeforeDependencyConstructor();
int main()
{
    assert(filteredBeforeCppConstructor);
    assert(linuraEnvironmentFilteredBeforeDependencyConstructor());
    assert(std::getenv("LANG") && std::string_view(std::getenv("LANG")) == "C");
    assert(!sanitizeNativeEnvironment(nullptr));
    expectRefusal({"HOME=/safe", "malformed"});
    expectRefusal({"=value"});
    expectRefusal({"HOME=/first", "HOME=/second"});
    expectRefusal({"LIBSEAT_BACKEND=seatd"});
    expectRefusal({"QT_QUICK_BACKEND=../plugin"});
    expectRefusal({"LIBGL_ALWAYS_SOFTWARE=true"});
    expectRefusal({"WLR_RENDERER_ALLOW_SOFTWARE=2"});
    expectRefusal({"AQ_NO_KMS_REQUIREMENT=-1"});
    expectRefusal({"HOME=" + std::string(8193, 'x')});
    expectRefusal(std::vector<std::string>(256, "UNKNOWN=value"));
    expectRefusal(std::vector<std::string>(9, "UNKNOWN=" + std::string(8000, 'x')));
    std::array<char *, 1> empty{nullptr};
    assert(sanitizeNativeEnvironment(empty.data()) && !empty[0]);
    char home[] = "HOME=/user";
    char locale[] = "LANG=C";
    char injection[] = "__EGL_VENDOR_LIBRARY_FILENAMES=/untrusted/vendor.json";
    char backend[] = "LIBSEAT_BACKEND=logind";
    char software[] = "LIBGL_ALWAYS_SOFTWARE=1";
    std::array<char *, 7> environment{injection, home,     locale, injection,
                                      backend,   software, nullptr};
    assert(sanitizeNativeEnvironment(environment.data()));
    assert(environment[0] == home && environment[1] == locale && environment[2] == backend &&
           environment[3] == software);
    for (std::size_t index = 4; index < environment.size(); ++index)
        assert(!environment[index]);
    assert(sanitizeNativeEnvironment(environment.data()));
}
