#include "native_process_privilege.h"

#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <string>
#include <sys/wait.h>

using namespace Linura::HyprlandDisplay;
int main()
{
    if (getuid() == 0) {
        assert(!dropNativeProcessCapabilities());
        return 0;
    }
    const auto uid = getuid(), effective = geteuid();
    const int dumpable = prctl(PR_GET_DUMPABLE);
    const int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL);
    const int bound = prctl(PR_CAPBSET_READ, CAP_WAKE_ALARM, 0UL, 0UL, 0UL);
    assert(dumpable >= 0 && nnp >= 0 && bound >= 0);
    assert(dropNativeProcessCapabilities());
    assert(getuid() == uid && geteuid() == effective);
    assert(prctl(PR_GET_DUMPABLE) == 0);
    assert(prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL) == nnp);
    assert(prctl(PR_CAPBSET_READ, CAP_WAKE_ALARM, 0UL, 0UL, 0UL) == bound);
    assert(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_WAKE_ALARM, 0UL, 0UL) == 0);
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    std::array<__user_cap_data_struct, 2> caps{};
    assert(syscall(SYS_capget, &header, caps.data()) == 0);
    for (const auto &set : caps)
        assert(set.effective == 0 && set.permitted == 0 && set.inheritable == 0);
    assert(dropNativeProcessCapabilities()); // Already empty remains empty.

    // Even a parent with matching UID and no Yama child restriction cannot
    // inspect the protected child's actual image after capability removal.
    std::array<int, 2> ready{}, finish{};
    assert(pipe2(ready.data(), O_CLOEXEC) == 0 && pipe2(finish.data(), O_CLOEXEC) == 0);
    const auto child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(ready[0]);
        close(finish[1]);
        assert(prctl(PR_SET_DUMPABLE, 1UL, 0UL, 0UL, 0UL) == 0);
        assert(dropNativeProcessCapabilities());
        const char byte = '1';
        assert(write(ready[1], &byte, 1) == 1);
        char finished = 0;
        const auto count = read(finish[0], &finished, 1);
        _exit(count == 1 && finished == '1' ? 0 : 1);
    }
    close(ready[1]);
    close(finish[0]);
    char byte = 0;
    assert(read(ready[0], &byte, 1) == 1 && byte == '1');
    const auto path = "/proc/" + std::to_string(child) + "/exe";
    errno = 0;
    const int image = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    assert(image == -1 && (errno == EACCES || errno == EPERM));
    assert(write(finish[1], &byte, 1) == 1);
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(close(ready[0]) == 0 && close(finish[1]) == 0);
}
