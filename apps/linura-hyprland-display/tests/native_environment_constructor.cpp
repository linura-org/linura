#include <cstdlib>
#include <cstring>

namespace {
bool filtered = false;
[[gnu::constructor]] void inspectBeforeMain()
{
    const auto language = std::getenv("LANG");
    filtered = language && std::strcmp(language, "C") == 0 &&
               !std::getenv("__EGL_VENDOR_LIBRARY_FILENAMES") &&
               !std::getenv("__EGL_VENDOR_LIBRARY_DIRS") && !std::getenv("GBM_BACKENDS_PATH") &&
               !std::getenv("LD_LIBRARY_PATH") && !std::getenv("LINURA_NATIVE_ENV_TEST");
}
} // namespace
extern "C" bool linuraEnvironmentFilteredBeforeDependencyConstructor()
{
    return filtered;
}
