#include "native_wayland_lock.h"
#include "native_deadline.h"
#include "native_lock_protocol.h"
#include "native_keyboard.h"
#include "native_display_connection.h"
#include "native_display_watchdog.h"
#include "native_wayland_readiness.h"
#include "secret_entry.h"
#include "ext-session-lock-v1-client-protocol.h"
#include "xdg-shell-client-protocol.h"
#include "linura-protected-display-v1-client-protocol.h"

#include <QSocketNotifier>
#include <QThread>
#include <QTimer>
#include <QUuid>
#include <wayland-client.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <map>
#include <limits>
#include <set>
#include <string_view>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

namespace Linura::SecurityOwner {
namespace {
[[noreturn]] void failClosed()
{
    _exit(NativeLockProtocol::NativeLockFaultExit);
}
template <class F> void nativeCallback(F &&function) noexcept
{
    try {
        function();
    } catch (...) {
        failClosed();
    }
}
void suppressNativeDiagnostic(const char *, va_list) {}
enum class LockProgress {
    Requested,
    Configured,
    FrameFlushed,
    AllSurfacesFlushed,
    Acknowledged,
    Released
};
void reportLockProgress(LockProgress progress) noexcept
{
    std::string_view message;
    switch (progress) {
    case LockProgress::Requested:
        message = "native-owner-lock-progress stage=requested\n";
        break;
    case LockProgress::Configured:
        message = "native-owner-lock-progress stage=surface-configured\n";
        break;
    case LockProgress::FrameFlushed:
        message = "native-owner-lock-progress stage=frame-flushed\n";
        break;
    case LockProgress::AllSurfacesFlushed:
        message = "native-owner-lock-progress stage=all-surfaces-flushed\n";
        break;
    case LockProgress::Acknowledged:
        message = "native-owner-lock-progress stage=acknowledged\n";
        break;
    case LockProgress::Released:
        message = "native-owner-lock-progress stage=released\n";
        break;
    }
    // Closed protocol milestones only, once per acquisition phase. Never log
    // input, dimensions, peers or payloads; unavailable/full stderr is ignored.
    const int savedError = errno;
    const auto written =
        ::send(STDERR_FILENO, message.data(), message.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
    (void)written;
    errno = savedError;
}
quint64 bootMilliseconds()
{
    timespec now{};
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0)
        failClosed();
    return static_cast<quint64>(now.tv_sec) * 1000U +
           static_cast<quint64>(now.tv_nsec) / 1'000'000U;
}
} // namespace

class NativeWaylandLock::Impl final
{
  public:
    struct Buffer final
    {
        Impl *owner = nullptr;
        wl_buffer *native = nullptr;
        void *mapping = MAP_FAILED;
        std::size_t bytes = 0;
        quint32 width = 0;
        quint32 height = 0;
        bool busy = false;
        ~Buffer()
        {
            if (native)
                wl_buffer_destroy(native);
            if (mapping != MAP_FAILED)
                munmap(mapping, bytes);
            if (owner)
                owner->retainedBytes -= bytes;
        }
    };
    struct Output final
    {
        Impl *owner = nullptr;
        quint32 id = 0;
        wl_output *native = nullptr;
        wl_surface *surface = nullptr;
        ext_session_lock_surface_v1 *lockSurface = nullptr;
        linura_protected_display_surface_v1 *displayRole = nullptr;
        quint64 displayHandle = 0, displayGeneration = 0;
        xdg_surface *confirmationRole = nullptr;
        xdg_toplevel *confirmationWindow = nullptr;
        quint32 width = 0;
        quint32 height = 0;
        quint32 serial = 0;
        QString nativeName;
        bool configured = false;
        bool needsAck = false;
        bool pending = false;
        bool acquisitionFrameQueued = false; // Diagnostic milestone only.
        quint64 configureGeneration = 0, committedConfigureGeneration = 0;
        quint64 flushedConfigureGeneration = 0;
        std::vector<std::unique_ptr<Buffer>> buffers;
        ~Output()
        {
            if (owner && owner->keyboard)
                owner->keyboard->forgetSurface(surface);
            if (displayRole)
                linura_protected_display_surface_v1_destroy(displayRole);
            if (lockSurface)
                ext_session_lock_surface_v1_destroy(lockSurface);
            if (confirmationWindow)
                xdg_toplevel_destroy(confirmationWindow);
            if (confirmationRole)
                xdg_surface_destroy(confirmationRole);
            if (surface)
                wl_surface_destroy(surface);
            buffers.clear();
            if (native)
                wl_output_release(native);
        }
        void clearSurface()
        {
            if (owner && owner->keyboard)
                owner->keyboard->forgetSurface(surface);
            if (displayRole)
                linura_protected_display_surface_v1_destroy(displayRole);
            if (lockSurface)
                ext_session_lock_surface_v1_destroy(lockSurface);
            if (surface)
                wl_surface_destroy(surface);
            lockSurface = nullptr;
            displayRole = nullptr;
            surface = nullptr;
            buffers.clear();
            configured = needsAck = pending = false;
            acquisitionFrameQueued = false;
            configureGeneration = committedConfigureGeneration = 0;
            flushedConfigureGeneration = 0;
        }
    };

    NativeWaylandLock &owner;
    wl_display *display;
    Painter painter;
    wl_registry *registry = nullptr;
    wl_compositor *compositor = nullptr;
    wl_shm *shm = nullptr;
    ext_session_lock_manager_v1 *manager = nullptr;
    xdg_wm_base *desktop = nullptr;
    quint32 desktopGlobal = 0;
    ext_session_lock_v1 *lock = nullptr;
    wl_callback *releaseAck = nullptr;
    std::map<quint32, std::unique_ptr<Output>> outputs;
    std::unique_ptr<NativeDisplayTopology> displayTopology =
        std::make_unique<NativeDisplayTopology>();
    QString displayInvocation;
    std::unique_ptr<NativeDisplayConnection> displayConnection;
    linura_protected_display_manager_v1 *protectedManager = nullptr;
    linura_protected_display_interaction_v1 *protectedInteraction = nullptr;
    quint32 protectedGlobal = 0;
    std::optional<NativeDisplayPromptScope> protectedScope;
    std::optional<NativeDisplayPromptStatus> protectedStatus;
    NativeDisplayClock protectedLast{};
    quint64 protectedBootDeadline = 0, protectedStatusBootMs = 0, protectedPollBootMs = 0;
    quint64 protectedTopology = 0;
    quint64 protectedRevisionEpoch = 0;
    quint64 protectedReviewEpochUsed = 0;
    bool protectedPollPending = false, protectedConsumed = false;
    bool protectedRevisionPending = false;
    std::map<quint64, std::unique_ptr<Output>> protectedOutputs;
    QTimer protectedTimer;

    bool protectedWindow()
    {
        if (!protectedScope)
            return false;
        const auto now = NativeDisplayClock::sample();
        if (!now || now->unixMs < protectedLast.unixMs || now->bootMs < protectedLast.bootMs ||
            now->unixMs >= protectedScope->deadlineUnixMs || now->bootMs >= protectedBootDeadline)
            return false;
        protectedLast = *now;
        return true;
    }
    bool protectedCovered()
    {
        return protectedInteraction && protectedScope && protectedStatus && protectedWindow() &&
               protectedStatus->phase == NativeDisplayPromptStatus::Phase::Ready &&
               protectedLast.bootMs >= protectedStatusBootMs &&
               protectedLast.bootMs - protectedStatusBootMs <= 250 && !protectedOutputs.empty() &&
               std::all_of(protectedOutputs.begin(), protectedOutputs.end(), [](const auto &item) {
                   const auto &output = *item.second;
                   return output.displayRole && output.configured && !output.needsAck &&
                          !output.pending;
               });
    }
    void cancelProtected()
    {
        if (!protectedInteraction && !protectedScope && protectedOutputs.empty())
            return;
        protectedTimer.stop();
        if (keyboard)
            keyboard->resetFocus();
        protectedStatus.reset();
        protectedScope.reset();
        protectedPollPending = protectedConsumed = protectedRevisionPending = false;
        protectedOutputs.clear();
        if (protectedInteraction)
            linura_protected_display_interaction_v1_destroy(protectedInteraction);
        protectedInteraction = nullptr;
        protectedTopology = protectedBootDeadline = protectedStatusBootMs = protectedPollBootMs =
            protectedRevisionEpoch = protectedReviewEpochUsed = 0;
        protectedLast = {};
    }
    void pollProtected()
    {
        if (!protectedInteraction)
            return;
        if (!protectedWindow() ||
            (protectedPollPending && (protectedLast.bootMs < protectedPollBootMs ||
                                      protectedLast.bootMs - protectedPollBootMs >= 250))) {
            cancelProtected();
            flush();
            return;
        }
        if (!protectedPollPending) {
            protectedPollPending = true;
            protectedPollBootMs = protectedLast.bootMs;
            linura_protected_display_interaction_v1_get_status(protectedInteraction);
            flush();
        }
    }
    static void protectedDenied(void *data, linura_protected_display_interaction_v1 *native)
    {
        nativeCallback([&] {
            auto &self = *static_cast<Impl *>(data);
            if (native != self.protectedInteraction)
                failClosed();
            self.cancelProtected();
        });
    }
    static void protectedState(void *data, linura_protected_display_interaction_v1 *native,
                               const char *instance, quint32 topologyHi, quint32 topologyLo,
                               quint32 epochHi, quint32 epochLo, quint32 phase)
    {
        nativeCallback([&] {
            auto &self = *static_cast<Impl *>(data);
            const auto topology = (static_cast<quint64>(topologyHi) << 32U) | topologyLo;
            const auto epoch = (static_cast<quint64>(epochHi) << 32U) | epochLo;
            if (native != self.protectedInteraction || !self.protectedScope || !instance ||
                strnlen(instance, 37) != 36 ||
                QString::fromLatin1(instance) != self.displayInvocation ||
                topology != self.protectedTopology || epoch == 0 ||
                epoch == std::numeric_limits<quint64>::max() || phase > 3 ||
                (self.protectedRevisionEpoch != 0 && epoch != self.protectedRevisionEpoch) ||
                !self.protectedWindow() || (self.protectedConsumed && phase != 2) ||
                (!self.protectedConsumed && phase == 2)) {
                self.cancelProtected();
                return;
            }
            if (self.protectedStatus && self.protectedStatus->epoch != epoch)
                self.invalidateOutputConfiguration(self.protectedRevisionPending);
            self.protectedStatus = NativeDisplayPromptStatus{
                topology, epoch, static_cast<NativeDisplayPromptStatus::Phase>(phase)};
            self.protectedStatusBootMs = self.protectedLast.bootMs;
            self.protectedPollPending = false;
            if (phase == 1)
                self.protectedRevisionPending = false;
            if (phase == 3)
                self.cancelProtected();
        });
    }
    static void protectedConfigured(void *data, linura_protected_display_surface_v1 *native,
                                    quint32 serial, quint32 width, quint32 height)
    {
        nativeCallback([&] {
            auto &output = *static_cast<Output *>(data);
            auto &self = *output.owner;
            if (native != output.displayRole || !self.protectedInteraction ||
                !self.protectedWindow() || serial == 0 || !boundedFrame(width, height) ||
                (output.configured && serial <= output.serial)) {
                self.cancelProtected();
                return;
            }
            self.invalidateOutputConfiguration(self.protectedRevisionPending);
            self.protectedStatus.reset();
            output.serial = serial;
            output.width = width;
            output.height = height;
            output.configured = output.needsAck = output.pending = true;
            self.paint(output);
        });
    }
    std::unique_ptr<QSocketNotifier> reader;
    std::unique_ptr<QSocketNotifier> writer;
    std::unique_ptr<NativeKeyboard> keyboard;
    std::unique_ptr<Output> confirmation;
    LockConfirmation confirmationCompleted;
    QTimer confirmationTimer;
    quint64 confirmationDeadline = 0;
    quint64 lastConfirmationClock = 0;
    quint32 seatGlobal = 0;
    std::array<quint32, 3> requiredGlobals{};
    std::size_t retainedBytes = 0;
    std::size_t announcedGlobals = 0;
    bool initialized = false;
    bool initializationAttempted = false;
    bool pumping = false;
    bool painting = false;
    bool acquisitionConfigured = false;
    bool acquisitionFrameQueued = false;
    bool acquisitionFrameFlushed = false;
    bool acquisitionAllSurfacesFlushed = false;
    quint64 inputGeneration = 1;

    void invalidateOutputConfiguration(bool preservePreparedPrompt = false)
    {
        if (inputGeneration == std::numeric_limits<quint64>::max())
            failClosed();
        ++inputGeneration;
        if (keyboard)
            keyboard->invalidateOutputConfiguration(preservePreparedPrompt);
    }
    bool inputCovered() const
    {
        return lock && owner.requestedSecure() && owner.secureCoverage() && !outputs.empty() &&
               std::all_of(outputs.begin(), outputs.end(), [](const auto &item) {
                   const auto &output = *item.second;
                   return output.lockSurface && output.configured && !output.needsAck &&
                          !output.pending && output.configureGeneration != 0 &&
                          output.committedConfigureGeneration == output.configureGeneration &&
                          output.flushedConfigureGeneration == output.configureGeneration;
               });
    }

    Impl(NativeWaylandLock &instance, wl_display *connection, Painter paint)
        : owner(instance), display(connection), painter(std::move(paint)),
          displayConnection(std::make_unique<NativeDisplayConnection>(connection))
    {
        protectedTimer.setInterval(50);
        QObject::connect(&protectedTimer, &QTimer::timeout, &owner,
                         [this] { nativeCallback([&] { pollProtected(); }); });
        confirmationTimer.setInterval(100);
        QObject::connect(&confirmationTimer, &QTimer::timeout, &owner, [this] {
            nativeCallback([&] {
                const auto now = bootMilliseconds();
                if (now < lastConfirmationClock || now >= confirmationDeadline)
                    finishConfirmation(false);
                else
                    lastConfirmationClock = now;
            });
        });
    }
    ~Impl()
    {
        // Never destroy or release an active lock through cleanup. No renderer,
        // hotplug, native error, destructor or timeout has an unlock path.
        if (lock || releaseAck || owner.requestedSecure() || owner.secureCoverage())
            failClosed();
        reader.reset();
        writer.reset();
        confirmationTimer.stop();
        cancelProtected();
        if (protectedManager)
            linura_protected_display_manager_v1_destroy(protectedManager);
        confirmation.reset();
        outputs.clear();
        displayConnection.reset();
        displayTopology.reset();
        keyboard.reset();
        if (desktop)
            xdg_wm_base_destroy(desktop);
        if (manager)
            ext_session_lock_manager_v1_destroy(manager);
        if (shm)
            wl_shm_destroy(shm);
        if (compositor)
            wl_compositor_destroy(compositor);
        if (registry)
            wl_registry_destroy(registry);
        if (display)
            wl_display_disconnect(display);
    }

    void flush()
    {
        if (wl_display_flush(display) < 0) {
            if (errno != EAGAIN)
                failClosed();
            if (writer)
                writer->setEnabled(true);
        } else {
            if (writer)
                writer->setEnabled(false);
            for (auto &[id, output] : outputs) {
                (void)id;
                if (output->lockSurface && !output->pending && !output->needsAck)
                    output->flushedConfigureGeneration = output->committedConfigureGeneration;
            }
            if (keyboard)
                keyboard->refreshProtectedFocus(protectedRevisionPending);
            if (acquisitionFrameQueued && !acquisitionFrameFlushed) {
                acquisitionFrameFlushed = true;
                reportLockProgress(LockProgress::FrameFlushed);
            }
            if (lock && !acquisitionAllSurfacesFlushed && !outputs.empty() &&
                std::all_of(outputs.begin(), outputs.end(), [](const auto &item) {
                    const auto &output = *item.second;
                    return output.configured && output.acquisitionFrameQueued && !output.pending;
                })) {
                acquisitionAllSurfacesFlushed = true;
                reportLockProgress(LockProgress::AllSurfacesFlushed);
            }
        }
    }

    void pump()
    {
        if (painting)
            failClosed();
        if (pumping)
            return;
        NativeDeadline deadline(std::chrono::milliseconds(500), NativeDeadline::Stage::WaylandPump);
        pumping = true;
        // Exclusive connection: never mix toolkit readers or blocking dispatch
        // with poll. Every prepare_read is matched by read_events/cancel_read.
        unsigned retries = 0;
        while (wl_display_prepare_read(display) != 0) {
            if (++retries > 8 || wl_display_dispatch_pending(display) < 0)
                failClosed();
        }
        pollfd descriptor{wl_display_get_fd(display), POLLIN, 0};
        const int ready = poll(&descriptor, 1, 0);
        if (ready < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            wl_display_cancel_read(display);
            failClosed();
        }
        if (ready > 0 && (descriptor.revents & POLLIN) != 0) {
            if (wl_display_read_events(display) < 0)
                failClosed();
        } else
            wl_display_cancel_read(display);
        if (wl_display_dispatch_pending(display) < 0 || wl_display_get_error(display) != 0)
            failClosed();
        pumping = false;
        flush();
    }

    static void global(void *data, wl_registry *, uint32_t name, const char *interface,
                       uint32_t version)
    {
        nativeCallback([&] {
            auto &self = *static_cast<Impl *>(data);
            if (++self.announcedGlobals > 512 || !interface || version == 0)
                failClosed();
            if (std::strcmp(interface, "wl_compositor") == 0) {
                if (self.compositor || version < 4)
                    failClosed();
                self.requiredGlobals[0] = name;
                self.compositor = static_cast<wl_compositor *>(
                    wl_registry_bind(self.registry, name, &wl_compositor_interface, 4));
            } else if (std::strcmp(interface, "wl_shm") == 0) {
                if (self.shm)
                    failClosed();
                self.requiredGlobals[1] = name;
                self.shm = static_cast<wl_shm *>(
                    wl_registry_bind(self.registry, name, &wl_shm_interface, 1));
            } else if (std::strcmp(interface, "ext_session_lock_manager_v1") == 0) {
                if (self.manager)
                    failClosed();
                self.requiredGlobals[2] = name;
                self.manager = static_cast<ext_session_lock_manager_v1 *>(wl_registry_bind(
                    self.registry, name, &ext_session_lock_manager_v1_interface, 1));
            } else if (std::strcmp(interface, "xdg_wm_base") == 0) {
                if (self.desktop)
                    failClosed();
                self.desktopGlobal = name;
                self.desktop = static_cast<xdg_wm_base *>(
                    wl_registry_bind(self.registry, name, &xdg_wm_base_interface, 1));
                static const xdg_wm_base_listener listener{desktopPing};
                if (!self.desktop || xdg_wm_base_add_listener(self.desktop, &listener, &self) != 0)
                    failClosed();
            } else if (std::strcmp(interface, "zwlr_output_manager_v1") == 0) {
                self.displayTopology->announce(self.registry, name, version);
            } else if (std::strcmp(interface, "linura_display_manager_v1") == 0) {
                self.displayConnection->announce(self.registry, name, version);
            } else if (std::strcmp(interface, "linura_protected_display_manager_v1") == 0) {
                if (self.protectedManager)
                    failClosed();
                self.protectedGlobal = name;
                self.protectedManager =
                    static_cast<linura_protected_display_manager_v1 *>(wl_registry_bind(
                        self.registry, name, &linura_protected_display_manager_v1_interface, 1));
                if (!self.protectedManager)
                    failClosed();
            } else if (std::strcmp(interface, "wl_output") == 0) {
                if (version < 3 || self.outputs.size() >= MaximumOutputs ||
                    self.outputs.contains(name))
                    failClosed();
                self.invalidateOutputConfiguration();
                auto output = std::make_unique<Output>();
                output->owner = &self;
                output->id = name;
                output->native = static_cast<wl_output *>(wl_registry_bind(
                    self.registry, name, &wl_output_interface, std::min(version, 4U)));
                if (!output->native)
                    failClosed();
                static const wl_output_listener listener{outputGeometry, outputMode,
                                                         outputDone,     outputScale,
                                                         outputName,     outputDescription};
                if (wl_output_add_listener(output->native, &listener, output.get()) != 0)
                    failClosed();
                auto *record = output.get();
                self.outputs.emplace(name, std::move(output));
                if (self.lock)
                    self.createSurface(*record);
            } else if (std::strcmp(interface, "wl_seat") == 0 && self.keyboard) {
                if (version < 5 || self.seatGlobal != 0)
                    failClosed();
                self.seatGlobal = name;
                auto *seat = static_cast<wl_seat *>(
                    wl_registry_bind(self.registry, name, &wl_seat_interface, 5));
                if (!self.keyboard->bind(seat))
                    failClosed();
            }
        });
    }

    static void outputGeometry(void *, wl_output *, int32_t, int32_t, int32_t, int32_t, int32_t,
                               const char *, const char *, int32_t)
    {}
    static void outputMode(void *, wl_output *, uint32_t, int32_t, int32_t, int32_t) {}
    static void outputDone(void *, wl_output *) {}
    static void outputScale(void *, wl_output *, int32_t scale)
    {
        if (scale < 1 || scale > 16)
            failClosed();
    }
    static void outputName(void *data, wl_output *, const char *name)
    {
        nativeCallback([&] {
            auto &output = *static_cast<Output *>(data);
            if (!name || !output.nativeName.isEmpty() || strnlen(name, 129) > 128)
                failClosed();
            output.nativeName = QString::fromUtf8(name);
        });
    }
    static void outputDescription(void *, wl_output *, const char *) {}
    static void desktopPing(void *data, xdg_wm_base *native, uint32_t serial)
    {
        nativeCallback([&] {
            auto &self = *static_cast<Impl *>(data);
            if (native != self.desktop)
                failClosed();
            xdg_wm_base_pong(native, serial);
        });
    }

    static void removed(void *data, wl_registry *, uint32_t name)
    {
        nativeCallback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.displayTopology->removed(name);
            self.displayConnection->removed(name);
            if (std::find(self.requiredGlobals.begin(), self.requiredGlobals.end(), name) !=
                self.requiredGlobals.end())
                failClosed();
            if (name == self.seatGlobal && self.keyboard)
                failClosed();
            if (name == self.desktopGlobal)
                failClosed();
            if (name == self.protectedGlobal) {
                self.cancelProtected();
                linura_protected_display_manager_v1_destroy(self.protectedManager);
                self.protectedManager = nullptr;
                self.protectedGlobal = 0;
            }
            if (self.outputs.contains(name)) {
                if (self.protectedInteraction)
                    self.cancelProtected();
                self.invalidateOutputConfiguration();
            }
            self.outputs.erase(
                name); // Surface destruction leaves compositor blank, never unlocked.
        });
    }

    static void locked(void *data, ext_session_lock_v1 *native)
    {
        nativeCallback([&] {
            auto &self = *static_cast<Impl *>(data);
            if (native != self.lock || !self.owner.requestedSecure() || self.owner.secureCoverage())
                failClosed();
            reportLockProgress(LockProgress::Acknowledged);
            self.owner.publishNativeState(
                true, true); // Actual protocol acknowledgement, not surface count.
        });
    }
    static void finished(void *, ext_session_lock_v1 *)
    {
        failClosed();
    }
    static void acknowledged(void *data, wl_callback *callback, uint32_t)
    {
        nativeCallback([&] {
            auto &self = *static_cast<Impl *>(data);
            if (callback != self.releaseAck || self.lock || !self.owner.requestedSecure())
                failClosed();
            wl_callback_destroy(callback);
            self.releaseAck = nullptr;
            for (auto &[id, output] : self.outputs) {
                (void)id;
                output->clearSurface();
            }
            reportLockProgress(LockProgress::Released);
            self.owner.publishNativeState(false, false); // Not independent global release evidence.
        });
    }
    static void configured(void *data, ext_session_lock_surface_v1 *native, uint32_t serial,
                           uint32_t width, uint32_t height)
    {
        nativeCallback([&] {
            auto &output = *static_cast<Output *>(data);
            if (native != output.lockSurface || !boundedFrame(width, height))
                failClosed();
            if (!output.owner->acquisitionConfigured) {
                output.owner->acquisitionConfigured = true;
                reportLockProgress(LockProgress::Configured);
            }
            output.width = width;
            output.height = height;
            if (output.configureGeneration == std::numeric_limits<quint64>::max())
                failClosed();
            ++output.configureGeneration;
            output.owner->invalidateOutputConfiguration();
            output.serial = serial;
            output.configured = true;
            output.needsAck = true;
            output.pending = true;
            output.owner->paint(output);
        });
    }
    static void released(void *data, wl_buffer *native)
    {
        nativeCallback([&] {
            auto &buffer = *static_cast<Buffer *>(data);
            if (native != buffer.native || !buffer.busy)
                failClosed();
            buffer.busy = false;
            // paint may retire this now-idle old-size buffer. Do not access its
            // callback storage again after repainting starts.
            auto *owner = buffer.owner;
            for (auto &[id, output] : owner->outputs) {
                (void)id;
                if (output->pending)
                    owner->paint(*output);
            }
            for (auto &[id, output] : owner->protectedOutputs) {
                (void)id;
                if (output->pending)
                    owner->paint(*output);
            }
            if (owner->confirmation && owner->confirmation->pending)
                owner->paint(*owner->confirmation);
        });
    }

    void finishConfirmation(bool confirmed)
    {
        if (!confirmation)
            return;
        const auto now = bootMilliseconds();
        confirmed = confirmed && now >= lastConfirmationClock && now < confirmationDeadline &&
                    !lock && !releaseAck && !owner.requestedSecure() && !owner.secureCoverage();
        auto completion = std::move(confirmationCompleted);
        confirmationTimer.stop();
        if (keyboard)
            keyboard->clearConfirmationTarget();
        confirmation.reset();
        confirmationDeadline = lastConfirmationClock = 0;
        flush();
        if (completion)
            completion(confirmed); // No acquisition/release here.
    }

    static void confirmationConfigured(void *data, xdg_surface *native, uint32_t serial)
    {
        nativeCallback([&] {
            auto &output = *static_cast<Output *>(data);
            if (native != output.confirmationRole || output.lockSurface)
                failClosed();
            output.serial = serial;
            output.configured = true;
            output.needsAck = true;
            output.pending = true;
            output.owner->paint(output);
        });
    }
    static void confirmationSize(void *data, xdg_toplevel *native, int32_t width, int32_t height,
                                 wl_array *states)
    {
        nativeCallback([&] {
            auto &output = *static_cast<Output *>(data);
            if (native != output.confirmationWindow || width < 0 || height < 0 || !states ||
                states->size > 64 || states->size % sizeof(uint32_t) != 0 ||
                (states->size != 0 && !states->data))
                failClosed();
            // Fixed bounded dialog; a compositor's zero dimension means the
            // client chooses its default, not a zero-sized confirmation.
            output.width = width == 0 ? 640U : static_cast<quint32>(width);
            output.height = height == 0 ? 360U : static_cast<quint32>(height);
            if (!boundedFrame(output.width, output.height))
                failClosed();
        });
    }
    static void confirmationClose(void *data, xdg_toplevel *native)
    {
        nativeCallback([&] {
            auto &output = *static_cast<Output *>(data);
            if (native != output.confirmationWindow)
                failClosed();
            output.owner->finishConfirmation(false);
        });
    }
    static void confirmationBounds(void *, xdg_toplevel *, int32_t, int32_t) {}
    static void confirmationCapabilities(void *, xdg_toplevel *, wl_array *) {}

    void createSurface(Output &output)
    {
        if (!lock || !compositor || output.surface || output.lockSurface)
            failClosed();
        output.surface = wl_compositor_create_surface(compositor);
        if (!output.surface)
            failClosed();
        output.lockSurface =
            ext_session_lock_v1_get_lock_surface(lock, output.surface, output.native);
        if (!output.lockSurface)
            failClosed();
        static const ext_session_lock_surface_v1_listener listener{configured};
        if (ext_session_lock_surface_v1_add_listener(output.lockSurface, &listener, &output) != 0)
            failClosed();
    }

    std::unique_ptr<Buffer> allocate(quint32 width, quint32 height)
    {
        if (!boundedFrame(width, height))
            failClosed();
        const auto bytes = static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4;
        if (bytes > MaximumRetainedBytes - retainedBytes)
            failClosed();
        const int descriptor = memfd_create("linura-lock-frame", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (descriptor < 0)
            failClosed();
        if (ftruncate(descriptor, static_cast<off_t>(bytes)) != 0 ||
            fcntl(descriptor, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) != 0) {
            close(descriptor);
            failClosed();
        }
        auto buffer = std::make_unique<Buffer>();
        buffer->mapping = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
        if (buffer->mapping == MAP_FAILED) {
            close(descriptor);
            failClosed();
        }
        buffer->owner = this;
        buffer->bytes = bytes;
        buffer->width = width;
        buffer->height = height;
        retainedBytes += bytes;
        auto *pool = wl_shm_create_pool(shm, descriptor, static_cast<int32_t>(bytes));
        close(descriptor);
        if (!pool)
            failClosed();
        buffer->native = wl_shm_pool_create_buffer(
            pool, 0, static_cast<int32_t>(width), static_cast<int32_t>(height),
            static_cast<int32_t>(width * 4), WL_SHM_FORMAT_XRGB8888);
        wl_shm_pool_destroy(pool);
        if (!buffer->native)
            failClosed();
        static const wl_buffer_listener listener{released};
        if (wl_buffer_add_listener(buffer->native, &listener, buffer.get()) != 0)
            failClosed();
        return buffer;
    }

    void paint(Output &output)
    {
        if (!output.configured || !output.pending || !output.surface)
            return;
        std::erase_if(output.buffers, [&](const auto &buffer) {
            return !buffer->busy &&
                   (buffer->width != output.width || buffer->height != output.height);
        });
        Buffer *selected = nullptr;
        for (const auto &buffer : output.buffers) {
            if (!buffer->busy && buffer->width == output.width && buffer->height == output.height) {
                selected = buffer.get();
                break;
            }
        }
        if (!selected) {
            // Coalesce presentation while every bounded slot is in flight;
            // the compositor retains the preceding opaque image/blank cover.
            // Never reuse busy storage or unlock to recover buffer pressure.
            if (output.buffers.size() >= 4)
                return;
            auto buffer = allocate(output.width, output.height);
            selected = buffer.get();
            output.buffers.push_back(std::move(buffer));
        }
        QImage frame(static_cast<uchar *>(selected->mapping), static_cast<int>(output.width),
                     static_cast<int>(output.height), static_cast<qsizetype>(output.width) * 4,
                     QImage::Format_RGB32);
        if (frame.isNull())
            failClosed();
        frame.fill(0xff101018U); // Opaque storage; no secret text enters rendered frames.
        if (painting)
            failClosed();
        painting = true;
        if (!painter || !painter(output.id, frame) || frame.constBits() != selected->mapping ||
            frame.size() !=
                QSize(static_cast<int>(output.width), static_cast<int>(output.height)) ||
            frame.format() != QImage::Format_RGB32)
            failClosed();
        painting = false;
        if (keyboard)
            keyboard->paintPointer(output.surface, frame);
        // A configure serial is consumed exactly once, not on every repaint.
        if (output.needsAck) {
            if (output.lockSurface)
                ext_session_lock_surface_v1_ack_configure(output.lockSurface, output.serial);
            else if (output.confirmationRole)
                xdg_surface_ack_configure(output.confirmationRole, output.serial);
            else if (output.displayRole)
                linura_protected_display_surface_v1_ack_configure(output.displayRole,
                                                                  output.serial);
            else
                failClosed();
            output.needsAck = false;
        }
        wl_surface_attach(output.surface, selected->native, 0, 0);
        wl_surface_damage_buffer(output.surface, 0, 0, static_cast<int32_t>(output.width),
                                 static_cast<int32_t>(output.height));
        selected->busy = true;
        output.pending = false;
        wl_surface_commit(output.surface);
        if (output.lockSurface)
            output.committedConfigureGeneration = output.configureGeneration;
        if (output.lockSurface)
            output.acquisitionFrameQueued = true;
        if (output.lockSurface && !acquisitionFrameFlushed)
            acquisitionFrameQueued = true;
    }
};

bool NativeWaylandLock::showProtectedDisplay(const NativeDisplayPromptScope &scope,
                                             const NativeDisplayIntent &intent)
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !scope.valid() || !impl_->protectedManager || !impl_->keyboard ||
        !impl_->keyboard->available() || impl_->confirmation || impl_->protectedInteraction ||
        impl_->releaseAck || requestedSecure() != secureCoverage() ||
        !NativeDisplayIntent::parse(intent.encode()))
        return false;
    const auto current = impl_->displayConnection->sample();
    const auto now = NativeDisplayClock::sample();
    const auto maximum =
        scope.purpose == NativeDisplayPromptScope::Purpose::Apply ? 60'000U : 15'000U;
    if (!current || !now || current->compositor != impl_->displayInvocation ||
        current->coverage != (secureCoverage() ? 1U : 0U) ||
        intent.baseline.topology.section(QLatin1Char(':'), 7, 7) != current->compositor ||
        intent.baseline.topology.section(QLatin1Char(':'), 8, 8) !=
            QString::number(current->topology.generation) ||
        !intent.baseline.nativeOptions(current->topology) ||
        !intent.desired.nativeOptions(current->topology) || scope.deadlineUnixMs <= now->unixMs ||
        scope.deadlineUnixMs - now->unixMs > maximum ||
        now->bootMs > std::numeric_limits<quint64>::max() - (scope.deadlineUnixMs - now->unixMs))
        return false;
    const NativeDisplayLayout *expected = nullptr;
    if (scope.purpose == NativeDisplayPromptScope::Purpose::Apply) {
        if (current->fenced)
            return false;
        expected = &intent.baseline;
    } else {
        if (!current->fenced)
            return false;
        if (scope.purpose == NativeDisplayPromptScope::Purpose::Keep)
            expected = &intent.desired;
    }
    if (expected) {
        if (expected->outputs.size() != current->current.outputs.size())
            return false;
        for (std::size_t i = 0; i < expected->outputs.size(); ++i)
            if (expected->outputs[i].encode() != current->current.outputs[i].encode())
                return false;
    }
    std::map<quint64, std::unique_ptr<Impl::Output>> pendingOutputs;
    for (const auto &head : current->topology.heads) {
        if (!head.enabled)
            continue;
        const auto native =
            std::find_if(impl_->outputs.begin(), impl_->outputs.end(),
                         [&](const auto &item) { return item.second->nativeName == head.name; });
        if (native == impl_->outputs.end())
            return false;
        auto output = std::make_unique<Impl::Output>();
        output->owner = impl_.get();
        output->id = native->first;
        output->nativeName = head.name;
        output->displayHandle = head.handle;
        output->displayGeneration = head.generation;
        pendingOutputs.emplace(head.handle, std::move(output));
    }
    if (pendingOutputs.empty())
        return false;
    impl_->protectedOutputs = std::move(pendingOutputs);
    impl_->protectedScope = scope;
    impl_->protectedLast = *now;
    impl_->protectedBootDeadline = now->bootMs + (scope.deadlineUnixMs - now->unixMs);
    impl_->protectedTopology = current->topology.generation;
    impl_->invalidateOutputConfiguration();
    const auto digest = scope.digest.toLatin1();
    impl_->protectedInteraction = linura_protected_display_manager_v1_begin(
        impl_->protectedManager, digest.constData(), static_cast<quint32>(scope.purpose),
        static_cast<quint32>(scope.deadlineUnixMs >> 32U),
        static_cast<quint32>(scope.deadlineUnixMs));
    static const linura_protected_display_interaction_v1_listener listener{Impl::protectedState,
                                                                           Impl::protectedDenied};
    if (!impl_->protectedInteraction ||
        linura_protected_display_interaction_v1_add_listener(impl_->protectedInteraction, &listener,
                                                             impl_.get()) != 0) {
        impl_->cancelProtected();
        return false;
    }
    static const linura_protected_display_surface_v1_listener surfaceListener{
        Impl::protectedConfigured};
    for (auto &[handle, output] : impl_->protectedOutputs) {
        output->surface = wl_compositor_create_surface(impl_->compositor);
        if (!output->surface) {
            impl_->cancelProtected();
            return false;
        }
        output->displayRole = linura_protected_display_interaction_v1_get_surface(
            impl_->protectedInteraction, output->surface, static_cast<quint32>(handle >> 32U),
            static_cast<quint32>(handle), static_cast<quint32>(output->displayGeneration >> 32U),
            static_cast<quint32>(output->displayGeneration));
        if (!output->displayRole || linura_protected_display_surface_v1_add_listener(
                                        output->displayRole, &surfaceListener, output.get()) != 0) {
            impl_->cancelProtected();
            return false;
        }
    }
    impl_->protectedTimer.start();
    impl_->pollProtected();
    return impl_->protectedInteraction != nullptr;
}
std::optional<NativeDisplayPromptStatus> NativeWaylandLock::protectedDisplayStatus()
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !impl_->protectedInteraction || !impl_->protectedWindow())
        return std::nullopt;
    impl_->pollProtected();
    if (!waitForNativeWaylandReady(impl_->display, std::chrono::milliseconds(250)) ||
        !impl_->protectedInteraction || !impl_->protectedWindow() || !impl_->protectedStatus)
        return std::nullopt;
    if (impl_->keyboard)
        impl_->keyboard->refreshProtectedFocus(impl_->protectedRevisionPending);
    return impl_->protectedStatus;
}
bool NativeWaylandLock::refreshProtectedDisplay(const NativeDisplayPromptScope &scope,
                                                quint64 originalEpoch)
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !impl_->protectedScope || *impl_->protectedScope != scope ||
        impl_->protectedConsumed)
        return false;
    const auto fresh = protectedDisplayStatus();
    if (!fresh || fresh->phase != NativeDisplayPromptStatus::Phase::Ready ||
        fresh->epoch != originalEpoch || !impl_->protectedInteraction)
        return false;
    const auto outputs = static_cast<quint64>(impl_->protectedOutputs.size());
    if (outputs == 0 || originalEpoch >= std::numeric_limits<quint64>::max() - outputs - 1)
        return false;
    impl_->protectedRevisionEpoch = originalEpoch + outputs;
    impl_->protectedRevisionPending = true;
    impl_->invalidateOutputConfiguration(true);
    impl_->protectedStatus.reset();
    linura_protected_display_interaction_v1_refresh_presentation(impl_->protectedInteraction);
    impl_->flush();
    // No old Ready reply may be reused for the new content. Readiness is
    // subsequently established by a fresh status and matching configure/frame.
    return waitForNativeWaylandReady(impl_->display, std::chrono::milliseconds(250)) &&
           impl_->protectedInteraction && impl_->protectedWindow();
}

bool NativeWaylandLock::armProtectedDisplayReview(const NativeDisplayPromptScope &scope,
                                                  quint64 originalEpoch,
                                                  LockConfirmation completion)
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !completion || !impl_->keyboard || !impl_->protectedScope ||
        *impl_->protectedScope != scope || impl_->protectedConsumed ||
        originalEpoch == impl_->protectedReviewEpochUsed)
        return false;
    const auto fresh = protectedDisplayStatus();
    if (!fresh || fresh->phase != NativeDisplayPromptStatus::Phase::Ready ||
        fresh->epoch != originalEpoch || !impl_->protectedCovered() || !impl_->keyboard->focused())
        return false;
    impl_->protectedReviewEpochUsed = originalEpoch;
    return impl_->keyboard->setDisplayReviewTarget(
        [this, scope, originalEpoch, completion = std::move(completion)](bool accepted) {
            // Retire native input before deferring work out of the Wayland
            // callback. A page action cannot migrate across queued UI changes.
            QTimer::singleShot(0, this, [this, scope, originalEpoch, accepted, completion] {
                const bool same = impl_->protectedScope && *impl_->protectedScope == scope &&
                                  !impl_->protectedConsumed;
                const auto fresh = same ? protectedDisplayStatus() : std::nullopt;
                completion(
                    accepted && fresh && fresh->phase == NativeDisplayPromptStatus::Phase::Ready &&
                    fresh->epoch == originalEpoch && impl_->keyboard && impl_->keyboard->focused());
            });
        });
}

bool NativeWaylandLock::consumeProtectedDisplay(const NativeDisplayPromptScope &scope,
                                                quint64 originalEpoch)
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !impl_->protectedInteraction || !impl_->protectedScope ||
        *impl_->protectedScope != scope || impl_->protectedConsumed || !impl_->protectedCovered() ||
        !impl_->protectedStatus || impl_->protectedStatus->epoch != originalEpoch ||
        !impl_->keyboard || !impl_->keyboard->focused())
        return false;
    // Fence pending poll replies before reserving consumption; otherwise an old
    // Ready response could be confused with the subsequent Consumed response.
    const auto inputGeneration = protectedInteractionGeneration();
    const auto fresh = protectedDisplayStatus();
    if (!fresh || fresh->phase != NativeDisplayPromptStatus::Phase::Ready ||
        fresh->epoch != originalEpoch || protectedInteractionGeneration() != inputGeneration ||
        !impl_->protectedInteraction || !impl_->protectedCovered() || !impl_->keyboard->focused())
        return false;
    // Reserve before any wire call. A lost reply never permits another consume.
    impl_->protectedConsumed = true;
    impl_->protectedStatus.reset();
    const auto digest = scope.digest.toLatin1();
    linura_protected_display_interaction_v1_consume(impl_->protectedInteraction, digest.constData(),
                                                    static_cast<quint32>(originalEpoch >> 32U),
                                                    static_cast<quint32>(originalEpoch));
    impl_->flush();
    if (!waitForNativeWaylandReady(impl_->display, std::chrono::milliseconds(250)) ||
        !impl_->protectedInteraction || !impl_->protectedWindow() || !impl_->protectedStatus ||
        impl_->protectedStatus->phase != NativeDisplayPromptStatus::Phase::Consumed ||
        impl_->protectedStatus->epoch != originalEpoch) {
        impl_->cancelProtected();
        return false;
    }
    return true;
}
void NativeWaylandLock::cancelProtectedDisplay()
{
    if (thread() != QThread::currentThread() || impl_->painting)
        failClosed();
    impl_->cancelProtected();
    if (impl_->display)
        impl_->flush();
}

NativeWaylandLock::NativeWaylandLock(wl_display *ownedDisplay, Painter painter)
    : impl_(std::make_unique<Impl>(*this, ownedDisplay, std::move(painter)))
{}
NativeWaylandLock::~NativeWaylandLock() = default;
const QString &NativeWaylandLock::displayInvocation() const noexcept
{
    return impl_->displayInvocation;
}
bool NativeWaylandLock::displayAllowsSecurityTransition()
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !impl_->displayConnection || impl_->protectedInteraction)
        return false;
    const bool secure = secureCoverage();
    if (requestedSecure() != secure || !impl_->displayConnection->securityTransitionAllowed(secure))
        return false;
    // The fresh read can deliver hotplug/configure events. Global compositor
    // coverage does not prove our newly configured output frames are ready.
    // Reuse the protected-input predicate AFTER that read, without requiring a
    // keyboard or focus for an automatic sleep fence.
    return requestedSecure() == secure && secureCoverage() == secure &&
           (!secure || impl_->inputCovered());
}
std::optional<NativeDisplaySnapshot> NativeWaylandLock::observeDisplayTopology()
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping ||
        !waitForNativeWaylandReady(impl_->display, std::chrono::milliseconds(250)))
        return std::nullopt;
    const auto independent = impl_->displayTopology->snapshotAfterSync();
    auto pinned = impl_->displayConnection->sample();
    if (!independent || !pinned || independent->heads.size() != pinned->topology.heads.size() ||
        (!impl_->displayInvocation.isEmpty() && impl_->displayInvocation != pinned->compositor))
        return std::nullopt;
    for (const auto &head : pinned->topology.heads) {
        const auto corroborating =
            std::find_if(independent->heads.begin(), independent->heads.end(),
                         [&](const auto &other) { return other.name == head.name; });
        if (corroborating == independent->heads.end() || corroborating->enabled != head.enabled ||
            !std::is_permutation(corroborating->modes.begin(), corroborating->modes.end(),
                                 head.modes.begin(), head.modes.end()) ||
            corroborating->current != head.current ||
            (head.enabled && (corroborating->x != head.x || corroborating->y != head.y ||
                              corroborating->transform != head.transform ||
                              corroborating->scaleFixed != head.scaleFixed)))
            return std::nullopt;
    }
    impl_->displayInvocation = pinned->compositor;
    std::vector<NativeLockOutputCoverage> surfaces;
    for (const auto &[id, output] : impl_->outputs) {
        (void)id;
        // A flushed opaque frame and native protocol acknowledgement are
        // separate requirements. Newly hotplugged/configuring outputs remain
        // uncovered until both hold; counts/Qt screens cannot satisfy this.
        const bool covered = secureCoverage() && requestedSecure() && impl_->lock &&
                             output->lockSurface && output->configured && !output->needsAck &&
                             !output->pending && output->configureGeneration != 0 &&
                             output->committedConfigureGeneration == output->configureGeneration &&
                             output->flushedConfigureGeneration == output->configureGeneration;
        surfaces.push_back({output->nativeName, covered});
    }
    return projectOwnerDisplayCoverage(std::move(pinned->topology), surfaces);
}
int NativeWaylandLock::actualDisplayFd() const noexcept
{
    return impl_->display ? wl_display_get_fd(impl_->display) : -1;
}
std::optional<quint32> NativeWaylandLock::dispatchPreparedDisplay(
    const NativeDisplayIntent &intent, const NativeDisplayCorrelation &correlation,
    quint64 validatedSampledBootMs, const QString &nativeBaselineGuard)
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !correlation.valid() || requestedSecure() != secureCoverage())
        return std::nullopt;
    const bool secure = secureCoverage();
    const auto current = impl_->displayConnection->sample();
    const auto nowBootMs = bootMilliseconds();
    if (!current || validatedSampledBootMs == 0 || nowBootMs < validatedSampledBootMs ||
        nowBootMs - validatedSampledBootMs >= 2000 || current->fenced ||
        current->coverage != (secure ? 1U : 0U) || requestedSecure() != secure ||
        secureCoverage() != secure || (secure && !impl_->inputCovered()) ||
        current->compositor != impl_->displayInvocation || current->topology.generation == 0 ||
        intent.baseline.topology.section(QLatin1Char(':'), 8, 8) !=
            QString::number(current->topology.generation) ||
        current->topology.baselineGuard(intent.baseline.encode()) !=
            std::optional{nativeBaselineGuard})
        return std::nullopt;
    // apply revalidates the complete exact baseline (including mirrors) and
    // native inventory against this same retained immutable snapshot. It
    // reserves the one-use wire attempt before any potentially effectful call.
    return impl_->displayConnection->apply(correlation, intent.baseline, intent.desired);
}
std::optional<quint32>
NativeWaylandLock::continuePreparedDisplay(const NativeDisplayIntent &intent,
                                           const NativeDisplayDecision &decision,
                                           quint64 originalSampledBootMs)
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !decision.valid() || requestedSecure() != secureCoverage())
        return std::nullopt;
    const bool secure = secureCoverage();
    const auto current = impl_->displayConnection->sample();
    const auto clock = NativeDisplayClock::sample();
    if (!current || !clock ||
        !decision.correlation.dispatchWindow(originalSampledBootMs, clock->bootMs, clock->unixMs) ||
        !current->fenced || current->coverage != (secure ? 1U : 0U) ||
        requestedSecure() != secure || secureCoverage() != secure ||
        (secure && !impl_->inputCovered()) || current->compositor != impl_->displayInvocation ||
        intent.baseline.topology.section(QLatin1Char(':'), 8, 8) !=
            QString::number(current->topology.generation) ||
        !intent.baseline.nativeOptions(current->topology) ||
        !intent.desired.nativeOptions(current->topology))
        return std::nullopt;
    if (decision.confirm) {
        // Include mirroring and disabled rows, not merely rounded wlr geometry.
        if (intent.desired.outputs.size() != current->current.outputs.size())
            return std::nullopt;
        for (std::size_t i = 0; i < intent.desired.outputs.size(); ++i)
            if (intent.desired.outputs[i].encode() != current->current.outputs[i].encode())
                return std::nullopt;
    }
    // decide retains the ORIGINAL connection-only one-use reservation and
    // checks both native clocks again. No Qt events/callbacks intervene here.
    return impl_->displayConnection->decide(decision.correlation, decision.confirm);
}
std::optional<quint32>
NativeWaylandLock::observeDisplayAttempt(const NativeDisplayCorrelation &correlation)
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting ||
        impl_->pumping || !correlation.valid())
        return std::nullopt;
    return impl_->displayConnection->status(correlation);
}
bool NativeWaylandLock::available() const noexcept
{
    return impl_->initialized;
}
bool NativeWaylandLock::bindProtectedInput(SecretEntry &entry, UnlockRequest request,
                                           PrimaryRequestAvailable primaryAvailable,
                                           PointerHitTest hitTest)
{
    if (thread() != QThread::currentThread() || entry.thread() != thread() ||
        impl_->initializationAttempted || impl_->keyboard || !entry.storageAvailable() ||
        !primaryAvailable)
        return false;
    impl_->keyboard = std::make_unique<NativeKeyboard>(
        entry,
        [this](wl_surface *surface) {
            if (impl_->confirmation && impl_->confirmation->surface == surface &&
                impl_->confirmation->configured)
                return true;
            if (impl_->protectedInteraction)
                return std::any_of(impl_->protectedOutputs.begin(), impl_->protectedOutputs.end(),
                                   [surface](const auto &item) {
                                       return item.second->surface == surface &&
                                              item.second->displayRole && item.second->configured;
                                   });
            return std::any_of(
                impl_->outputs.begin(), impl_->outputs.end(), [surface](const auto &item) {
                    const auto &output = item.second;
                    return output->surface == surface && output->lockSurface && output->configured;
                });
        },
        [this] {
            return impl_->protectedInteraction ? impl_->protectedCovered() : impl_->inputCovered();
        },
        std::move(request),
        [this, primaryAvailable = std::move(primaryAvailable)] {
            // The private display conversation owns its actions even between
            // page callbacks. Unarmed/retired review input must never request
            // an unrelated lock/unlock operation through the generic surface.
            return !impl_->protectedInteraction && primaryAvailable();
        },
        hitTest ? NativeKeyboard::PointerHitTest([this, hitTest](wl_surface *surface,
                                                                 const QPointF &position) {
            const Impl::Output *output = nullptr;
            if (impl_->confirmation && impl_->confirmation->surface == surface)
                output = impl_->confirmation.get();
            else
                for (const auto &item : impl_->outputs) {
                    if (item.second->surface == surface) {
                        output = item.second.get();
                        break;
                    }
                }
            if (impl_->protectedInteraction)
                for (const auto &item : impl_->protectedOutputs)
                    if (item.second->surface == surface) {
                        output = item.second.get();
                        break;
                    }
            if (!output || !output->configured || !boundedFrame(output->width, output->height))
                return NativePointerTarget{};
            auto target = hitTest(
                QSize(static_cast<int>(output->width), static_cast<int>(output->height)), position);
            target.configureSerial = output->serial;
            return target;
        })
                : NativeKeyboard::PointerHitTest{},
        [this] { QTimer::singleShot(0, this, &NativeWaylandLock::repaint); });
    // Coverage may arrive after keyboard enter, without a second enter or key.
    // Publish the same fresh native focus to protected accessibility metadata.
    connect(
        this, &NativeManagedLockBackend::nativeStateChanged, this,
        [this] { impl_->keyboard->refreshProtectedFocus(impl_->protectedRevisionPending); },
        Qt::DirectConnection);
    return true;
}
void NativeWaylandLock::refreshNativeState()
{
    if (thread() != QThread::currentThread() || !impl_->initialized || impl_->painting)
        failClosed();
    // Drain available events on our exclusive connection before comparing its
    // acknowledgement with an independent compositor sample. No wait or retry.
    impl_->pump();
}
void NativeWaylandLock::progressNativeState()
{
    if (thread() != QThread::currentThread() || !impl_->initialized)
        failClosed();
    if (!impl_->pumping && !impl_->painting)
        impl_->pump();
}
bool NativeWaylandLock::protectedInputAvailable() const noexcept
{
    return impl_->initialized && impl_->keyboard && impl_->keyboard->available();
}
bool NativeWaylandLock::protectedInputFocused() const
{
    if (thread() != QThread::currentThread())
        failClosed();
    return impl_->initialized && impl_->keyboard && impl_->keyboard->focused();
}
quint64 NativeWaylandLock::protectedInputGeneration() const noexcept
{
    return impl_->inputGeneration;
}
quint64 NativeWaylandLock::protectedInteractionGeneration() const noexcept
{
    return impl_->keyboard ? impl_->keyboard->interactionGeneration() : 0;
}
bool NativeWaylandLock::lockConfirmationVisible() const noexcept
{
    return impl_->confirmation && impl_->confirmation->configured;
}
bool NativeWaylandLock::showLockConfirmation(LockConfirmation completion)
{
    if (thread() != QThread::currentThread() || impl_->painting || !impl_->initialized ||
        !impl_->desktop || !impl_->keyboard || !impl_->keyboard->available() || !completion ||
        impl_->confirmation || impl_->lock || impl_->releaseAck || requestedSecure() ||
        secureCoverage())
        return false;
    auto output = std::make_unique<Impl::Output>();
    output->owner = impl_.get();
    output->width = 640;
    output->height = 360;
    output->surface = wl_compositor_create_surface(impl_->compositor);
    if (!output->surface)
        failClosed();
    output->confirmationRole = xdg_wm_base_get_xdg_surface(impl_->desktop, output->surface);
    if (!output->confirmationRole)
        failClosed();
    static const xdg_surface_listener roleListener{Impl::confirmationConfigured};
    if (xdg_surface_add_listener(output->confirmationRole, &roleListener, output.get()) != 0)
        failClosed();
    output->confirmationWindow = xdg_surface_get_toplevel(output->confirmationRole);
    if (!output->confirmationWindow)
        failClosed();
    static const xdg_toplevel_listener windowListener{
        Impl::confirmationSize, Impl::confirmationClose, Impl::confirmationBounds,
        Impl::confirmationCapabilities};
    if (xdg_toplevel_add_listener(output->confirmationWindow, &windowListener, output.get()) != 0)
        failClosed();
    xdg_toplevel_set_title(output->confirmationWindow, "Linura — Lock this session?");
    xdg_toplevel_set_app_id(output->confirmationWindow, "org.linura.SecurityOwner");
    xdg_toplevel_set_min_size(output->confirmationWindow, 320, 280);
    xdg_toplevel_set_max_size(output->confirmationWindow, 640, 360);
    impl_->confirmationCompleted = std::move(completion);
    impl_->lastConfirmationClock = bootMilliseconds();
    impl_->confirmationDeadline = impl_->lastConfirmationClock + 60'000;
    impl_->confirmation = std::move(output);
    if (!impl_->keyboard->setConfirmationTarget(
            impl_->confirmation->surface,
            [this](bool confirmed) { impl_->finishConfirmation(confirmed); }))
        failClosed();
    impl_->confirmationTimer.start();
    wl_surface_commit(impl_->confirmation->surface); // Initial bufferless xdg configure handshake.
    impl_->flush();
    return true;
}
void NativeWaylandLock::cancelLockConfirmation()
{
    if (thread() != QThread::currentThread() || impl_->painting)
        failClosed();
    impl_->finishConfirmation(false);
}
bool NativeWaylandLock::boundedFrame(quint32 width, quint32 height) noexcept
{
    return width > 0 && height > 0 && width <= 8192 && height <= 8192 &&
           static_cast<std::uint64_t>(width) * height * 4 <= MaximumFrameBytes;
}

bool NativeWaylandLock::initialize()
{
    if (thread() != QThread::currentThread() || !impl_->display || impl_->initializationAttempted ||
        !impl_->painter)
        return false;
    impl_->initializationAttempted = true;
    NativeDeadline deadline(std::chrono::milliseconds(2'000),
                            NativeDeadline::Stage::WaylandInitialization);
    wl_log_set_handler_client(suppressNativeDiagnostic);
    impl_->registry = wl_display_get_registry(impl_->display);
    if (!impl_->registry)
        return false;
    static const wl_registry_listener listener{Impl::global, Impl::removed};
    if (wl_registry_add_listener(impl_->registry, &listener, impl_.get()) != 0 ||
        wl_display_roundtrip(impl_->display) < 0 || wl_display_roundtrip(impl_->display) < 0 ||
        !impl_->compositor || !impl_->shm || !impl_->manager || impl_->outputs.empty())
        return false;
    if (impl_->keyboard && (impl_->seatGlobal == 0 || wl_display_roundtrip(impl_->display) < 0 ||
                            !impl_->keyboard->available()))
        return false;
    const int descriptor = actualDisplayFd();
    if (descriptor < 0)
        return false;
    impl_->reader = std::make_unique<QSocketNotifier>(descriptor, QSocketNotifier::Read, this);
    impl_->writer = std::make_unique<QSocketNotifier>(descriptor, QSocketNotifier::Write, this);
    impl_->writer->setEnabled(false);
    QObject::connect(impl_->reader.get(), &QSocketNotifier::activated, this,
                     [this] { nativeCallback([&] { impl_->pump(); }); });
    QObject::connect(impl_->writer.get(), &QSocketNotifier::activated, this,
                     [this] { nativeCallback([&] { impl_->flush(); }); });
    impl_->initialized = true;
    return true;
}

bool NativeWaylandLock::applyNative(bool secure)
{
    if (impl_->painting)
        failClosed();
    if (!impl_->initialized)
        return false;
    if (secure) {
        if (impl_->lock || impl_->releaseAck || requestedSecure() || secureCoverage())
            return false;
        // An effect may follow only after the private confirmation was consumed
        // by Control. Never acquire while an interactive dialog remains live.
        if (impl_->confirmation || impl_->protectedInteraction)
            return false;
        consumeNativeEffectGate(true);
        impl_->lock = ext_session_lock_manager_v1_lock(impl_->manager);
        if (!impl_->lock)
            failClosed();
        static const ext_session_lock_v1_listener listener{Impl::locked, Impl::finished};
        if (ext_session_lock_v1_add_listener(impl_->lock, &listener, impl_.get()) != 0)
            failClosed();
        impl_->acquisitionConfigured = false;
        impl_->acquisitionFrameQueued = false;
        impl_->acquisitionFrameFlushed = false;
        impl_->acquisitionAllSurfacesFlushed = false;
        reportLockProgress(LockProgress::Requested);
        publishNativeState(true, false);
        for (auto &[id, output] : impl_->outputs) {
            (void)id;
            impl_->createSurface(*output);
        }
    } else {
        if (!impl_->lock || impl_->releaseAck || !requestedSecure() || !secureCoverage())
            return false;
        if (impl_->keyboard)
            impl_->keyboard->resetFocus();
        consumeNativeEffectGate(false); // The ONE protocol release site; no cleanup fallback.
        ext_session_lock_v1_unlock_and_destroy(impl_->lock);
        impl_->lock = nullptr;
        impl_->releaseAck = wl_display_sync(impl_->display);
        if (!impl_->releaseAck)
            failClosed();
        static const wl_callback_listener listener{Impl::acknowledged};
        if (wl_callback_add_listener(impl_->releaseAck, &listener, impl_.get()) != 0)
            failClosed();
    }
    impl_->flush();
    return true;
}

void NativeWaylandLock::repaint()
{
    if (thread() != QThread::currentThread() || impl_->painting)
        failClosed();
    NativeDeadline deadline(std::chrono::milliseconds(500), NativeDeadline::Stage::WaylandRepaint);
    nativeCallback([&] {
        for (auto &[id, output] : impl_->outputs) {
            (void)id;
            output->pending = true;
            impl_->paint(*output);
        }
        for (auto &[id, output] : impl_->protectedOutputs) {
            (void)id;
            output->pending = true;
            impl_->paint(*output);
        }
        if (impl_->confirmation) {
            impl_->confirmation->pending = true;
            impl_->paint(*impl_->confirmation);
        }
        if (impl_->display)
            impl_->flush();
    });
}

} // namespace Linura::SecurityOwner
