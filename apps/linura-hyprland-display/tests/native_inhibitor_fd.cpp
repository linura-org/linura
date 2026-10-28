#include "native_inhibitor_fd.h"

#include <array>
#include <cassert>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace Linura::HyprlandDisplay;

int main()
{
    assert(!nativeInhibitorFdAlive(-1));
    const int regular = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(regular >= 0);
    assert(!nativeInhibitorFdAlive(regular));
    assert(close(regular) == 0);
    assert(!nativeInhibitorFdAlive(regular));

    // Detect loss regardless of which end a native service supplies. A live
    // descriptor on our side must never stand in for the departed native peer.
    for (const int retained : {0, 1}) {
        std::array<int, 2> pipe{};
        assert(pipe2(pipe.data(), O_CLOEXEC | O_NONBLOCK) == 0);
        assert(nativeInhibitorFdAlive(pipe[0]));
        assert(nativeInhibitorFdAlive(pipe[1]));
        const int peer = retained == 0 ? 1 : 0;
        assert(close(pipe[static_cast<std::size_t>(peer)]) == 0);
        assert(!nativeInhibitorFdAlive(pipe[static_cast<std::size_t>(retained)]));
        assert(close(pipe[static_cast<std::size_t>(retained)]) == 0);
    }
    std::array<int, 2> pipe{};
    assert(pipe2(pipe.data(), O_CLOEXEC | O_NONBLOCK) == 0);
    const int duplicate = fcntl(pipe[1], F_DUPFD_CLOEXEC, 3);
    assert(duplicate >= 0 && nativeInhibitorFdAlive(duplicate));
    assert(fcntl(duplicate, F_SETFD, 0) == 0);
    assert(!nativeInhibitorFdAlive(duplicate));
    assert(fcntl(duplicate, F_SETFD, FD_CLOEXEC) == 0);
    assert(nativeInhibitorFdAlive(duplicate));
    const char unexpected = 'x';
    assert(write(pipe[1], &unexpected, 1) == 1);
    assert(!nativeInhibitorFdAlive(pipe[0]));
    char observed = '\0';
    assert(read(pipe[0], &observed, 1) == 1 && observed == unexpected);
    assert(nativeInhibitorFdAlive(pipe[0]));
    assert(close(pipe[0]) == 0);
    assert(!nativeInhibitorFdAlive(duplicate));
    assert(close(pipe[1]) == 0);
    assert(close(duplicate) == 0);

    // A FIFO can acquire another peer after HUP. The local descriptor then
    // looks live again, but it is not the original service's inhibition lease.
    char directory[] = "/tmp/linura-inhibitor-XXXXXX";
    assert(mkdtemp(directory) != nullptr);
    const std::string fifo = std::string(directory) + "/lease";
    assert(mkfifo(fifo.c_str(), 0600) == 0);
    const int receiver = open(fifo.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    assert(receiver >= 0);
    int writer = open(fifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    assert(writer >= 0);
    NativeInhibitorFd lease;
    assert(!lease.retained() && !lease.held());
    assert(!lease.retain(-1));
    assert(lease.retain(receiver));
    assert(lease.retained() && lease.held());
    assert(!lease.retain(writer)); // Cannot replace an active or lost lease.
    assert(close(writer) == 0);
    assert(!lease.held() && lease.retained());
    writer = open(fifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    assert(writer >= 0);
    assert(nativeInhibitorFdAlive(receiver)); // Stateless check would revive it.
    assert(!lease.held());
    assert(!lease.retain(writer));
    lease.release();
    assert(!lease.retained() && !lease.held());
    assert(fcntl(receiver, F_GETFD) == -1);
    assert(close(writer) == 0);
    assert(unlink(fifo.c_str()) == 0);
    assert(rmdir(directory) == 0);

    // Destruction closes its sole retained reference; repeated release is safe.
    assert(pipe2(pipe.data(), O_CLOEXEC | O_NONBLOCK) == 0);
    {
        NativeInhibitorFd scoped;
        assert(scoped.retain(pipe[0]) && scoped.held());
    }
    assert(fcntl(pipe[0], F_GETFD) == -1);
    assert(close(pipe[1]) == 0);
}
