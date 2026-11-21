// Disposable-guest positive control for libglvnd vendor override loading.
// No surface, device, GL context, mutation or production linkage.
#include <dlfcn.h>
#include <unistd.h>

int main()
{
    if (getuid() == 0 || getuid() != geteuid())
        return 78;
    void *library = dlopen("libEGL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library)
        return 78;
    using QueryString = const char *(*)(void *, int);
    const auto query = reinterpret_cast<QueryString>(dlsym(library, "eglQueryString"));
    if (!query) {
        dlclose(library);
        return 78;
    }
    // EGL_NO_DISPLAY / EGL_EXTENSIONS invokes real vendor discovery. The
    // canary's constructor runs even though it supplies no EGL vendor API.
    (void)query(nullptr, 0x3055);
    return dlclose(library) == 0 ? 0 : 78;
}
