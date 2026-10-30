#include "compositor_display_service.h"

#include <cassert>
#include <csignal>
#include <functional>
#include <sys/wait.h>
#include <unistd.h>
#include <wayland-server-core.h>

using namespace Linura::HyprlandDisplay;

namespace {
class NativeFixture final : public Backend
{
  public:
    const Mode full{1920, 1080, 60'000}, small{1280, 720, 60'000};
    Target current{OutputKey{0, 1}, true, full, 1000, 0, 0, 0, {}};
    int writes = 0;
    bool inhibited = false;
    std::function<void()> duringInhibition, duringWrite;
    [[nodiscard]] bool restoredOwnedState() override
    {
        return true;
    }
    [[nodiscard]] bool restoreOwnedLayout(const Layout &layout, const Snapshot &expected) override
    {
        return applyOwnedLayout(layout, expected);
    }
    [[nodiscard]] bool inhibitPowerTransitions() override
    {
        assert(!inhibited);
        if (duringInhibition)
            duringInhibition();
        return inhibited = true;
    }
    void releasePowerInhibitor() noexcept override
    {
        assert(inhibited);
        inhibited = false;
    }
    [[nodiscard]] std::optional<ClockSample> clock() override
    {
        return compositorClock();
    }
    [[nodiscard]] std::optional<Snapshot> snapshot() override
    {
        return Snapshot{
            1, 1, {{current.output, {full, small}, current, true, true}}, Coverage::Secure};
    }
    [[nodiscard]] bool applyOwnedLayout(const Layout &targets, const Snapshot &) override
    {
        ++writes;
        assert(inhibited);
        if (duringWrite)
            duringWrite();
        current = targets[0];
        return true;
    }
};
Correlation bound(const char *name, std::uint64_t window)
{
    const auto now = compositorClock();
    assert(now);
    return {name, std::string(64, 'a'), std::string(64, 'b'), now->unixMs + window};
}
CompositorDisplayService::Begin begin(CompositorDisplayService &service, NativeFixture &native,
                                      const Correlation &correlation, const Layout &baseline,
                                      const Layout &desired)
{
    const auto captured = compositorClock();
    assert(captured);
    return service.begin(correlation, baseline, desired, *native.snapshot(), *captured);
}
void independentTimerAfterClientDeath()
{
    auto *loop = wl_event_loop_create();
    assert(loop);
    {
        NativeFixture native;
        CompositorDisplayService service(*loop, native);
        const Layout baseline{native.current};
        auto desired = baseline;
        desired[0].mode = native.small;
        const auto correlation = bound("transaction:client-death", 500);
        int ready[2]{};
        assert(pipe(ready) == 0);
        const auto client = fork();
        assert(client >= 0);
        if (client == 0) {
            close(ready[0]);
            const char byte = 'r';
            if (write(ready[1], &byte, 1) != 1)
                _exit(2);
            close(ready[1]);
            for (;;)
                pause();
        }
        close(ready[1]);
        char byte = 0;
        assert(read(ready[0], &byte, 1) == 1 && byte == 'r');
        close(ready[0]);
        assert(begin(service, native, correlation, baseline, desired) ==
               CompositorDisplayService::Begin::Started);
        assert(native.current == desired[0] && native.writes == 1);
        assert(kill(client, SIGKILL) == 0);
        int status = 0;
        assert(waitpid(client, &status, 0) == client && WIFSIGNALED(status));
        // No surviving client, Control, Qt/QML or request handler drives
        // recovery. Only the compositor-owned BOOTTIME timer runs here.
        const auto deadline = compositorClock()->bootMs + 3000;
        while (service.fenced() && compositorClock()->bootMs < deadline)
            assert(wl_event_loop_dispatch(loop, 100) == 0);
        assert(!service.fenced() && native.writes == 2 && native.current == baseline[0]);
        assert(service.status(correlation) == CompositorDisplayService::Phase::Restored);
        assert(begin(service, native, correlation, baseline, desired) ==
               CompositorDisplayService::Begin::Existing);
        assert(native.writes == 2);
        auto substitute = correlation;
        substitute.dispatchDigest[0] = 'c';
        assert(!service.status(substitute));
        assert(!service.confirm(substitute));
        assert(!service.restore(substitute));
        assert(begin(service, native, substitute, baseline, desired) ==
               CompositorDisplayService::Begin::Rejected);
        assert(native.writes == 2);
    }
    wl_event_loop_destroy(loop);
}
void admissionAndReservationLimits()
{
    auto *loop = wl_event_loop_create();
    assert(loop);
    {
        NativeFixture native;
        CompositorDisplayService service(*loop, native);
        const Layout baseline{native.current};
        auto desired = baseline;
        desired[0].mode = native.small;
        auto correlation = bound("transaction:first", 15'000);
        assert(begin(service, native, correlation, baseline, desired) ==
               CompositorDisplayService::Begin::Started);
        auto another = correlation;
        another.transaction = "transaction:second";
        assert(begin(service, native, another, desired, baseline) ==
               CompositorDisplayService::Begin::Rejected);
        assert(native.writes == 1);
        assert(begin(service, native, correlation, baseline, desired) ==
               CompositorDisplayService::Begin::Existing);
        assert(service.confirm(correlation));
        assert(!service.fenced() && native.writes == 1);
        assert(!service.restore(correlation));
        assert(!service.confirm(correlation));
        assert(begin(service, native, another, desired, baseline) ==
               CompositorDisplayService::Begin::Rejected);
        assert(!service.status(another)); // Same dispatch under a different ID.
        auto changed = desired;
        changed[0].x = 100;
        assert(begin(service, native, correlation, baseline, changed) ==
               CompositorDisplayService::Begin::Rejected);
        // A rejection also consumes its reserved identifier. Retry cannot turn
        // it into a new native effect after changing its material.
        another.effectDigest = std::string(64, '0');
        another.dispatchDigest[0] = 'c';
        assert(begin(service, native, another, desired, baseline) ==
               CompositorDisplayService::Begin::Rejected);
        assert(service.status(another) == CompositorDisplayService::Phase::RejectedBeforeDispatch);
        assert(begin(service, native, another, desired, baseline) ==
               CompositorDisplayService::Begin::Existing);
        assert(native.writes == 1);
        for (std::size_t i = 2; i < CompositorDisplayService::MaxReservations; ++i) {
            auto rejected = bound(("transaction:rejected-" + std::to_string(i)).c_str(), 15'000);
            rejected.effectDigest = std::string(64, '0');
            // Distinct reserved dispatches; reuse is rejected before insertion.
            rejected.dispatchDigest = std::string(60, 'd') + std::to_string(1000 + i);
            assert(begin(service, native, rejected, desired, baseline) ==
                   CompositorDisplayService::Begin::Rejected);
            assert(service.status(rejected) ==
                   CompositorDisplayService::Phase::RejectedBeforeDispatch);
        }
        another = bound("transaction:overflow", 15'000);
        another.dispatchDigest = std::string(64, 'e');
        assert(begin(service, native, another, desired, baseline) ==
               CompositorDisplayService::Begin::Rejected);
        assert(!service.status(another) && native.writes == 1);
    }
    wl_event_loop_destroy(loop);
}
void exclusionPrecedesEveryInitialBackendCallback()
{
    auto *loop = wl_event_loop_create();
    assert(loop);
    {
        NativeFixture native;
        CompositorDisplayService service(*loop, native);
        const Layout baseline{native.current};
        auto desired = baseline;
        desired[0].mode = native.small;
        const auto original = bound("transaction:initial-native-exclusion", 15'000);
        auto nested = bound("transaction:reentrant-native-exclusion", 15'000);
        nested.dispatchDigest = std::string(64, 'c');
        unsigned calls = 0;
        auto inspect = [&] {
            assert(service.fenced());
            ++calls;
            assert(begin(service, native, nested, baseline, desired) ==
                   CompositorDisplayService::Begin::Rejected);
            assert(!service.status(nested));
        };
        native.duringInhibition = inspect;
        native.duringWrite = inspect;
        assert(begin(service, native, original, baseline, desired) ==
               CompositorDisplayService::Begin::Started);
        assert(calls == 2 && native.writes == 1 && service.fenced());
        assert(service.confirm(original));
        assert(!service.fenced() && !native.inhibited && native.writes == 1);
    }
    wl_event_loop_destroy(loop);
}
} // namespace

int main()
{
    independentTimerAfterClientDeath();
    admissionAndReservationLimits();
    exclusionPrecedesEveryInitialBackendCallback();
}
