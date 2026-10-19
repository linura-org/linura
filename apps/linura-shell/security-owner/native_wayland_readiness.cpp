#include "native_wayland_readiness.h"
#include "native_startup.h"

#include <wayland-client.h>
#include <poll.h>
#include <cerrno>

namespace Linura::SecurityOwner {

bool waitForNativeWaylandReady(wl_display *display, std::chrono::milliseconds budget)
{
    using Clock = std::chrono::steady_clock;
    if (!display || budget <= std::chrono::milliseconds::zero() ||
        budget > NativeCompositorReadinessContract::maximumWait ||
        wl_display_get_error(display) != 0)
        return false;
    const auto deadline = Clock::now() + budget;
    bool completed = false;
    wl_callback *callback = wl_display_sync(display);
    if (!callback)
        return false;
    struct Cleanup final
    {
        wl_callback *callback;
        ~Cleanup()
        {
            wl_callback_destroy(callback);
        }
    } cleanup{callback};
    static const wl_callback_listener listener{
        [](void *data, wl_callback *, uint32_t) { *static_cast<bool *>(data) = true; }};
    if (wl_callback_add_listener(callback, &listener, &completed) != 0)
        return false;
    while (Clock::now() < deadline) {
        if (wl_display_dispatch_pending(display) < 0 || wl_display_get_error(display) != 0)
            return false;
        if (completed)
            return Clock::now() < deadline;
        if (wl_display_prepare_read(display) != 0)
            continue;
        const int flushed = wl_display_flush(display);
        if (flushed < 0 && errno != EAGAIN) {
            wl_display_cancel_read(display);
            return false;
        }
        const auto remaining =
            std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now());
        if (remaining <= std::chrono::milliseconds::zero()) {
            wl_display_cancel_read(display);
            return false;
        }
        pollfd pending{wl_display_get_fd(display),
                       static_cast<short>(POLLIN | (flushed < 0 ? POLLOUT : 0)), 0};
        const int ready = poll(&pending, 1, static_cast<int>(remaining.count()));
        const int error = errno;
        if (ready > 0 && (pending.revents & POLLIN) != 0) {
            if (wl_display_read_events(display) < 0)
                return false;
        } else {
            wl_display_cancel_read(display);
        }
        if (ready < 0 && error == EINTR)
            continue; // Original monotonic deadline, no restart or new request.
        if (ready <= 0 || (pending.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            return false;
    }
    return false;
}

} // namespace Linura::SecurityOwner
