#include "pinned_protected.h"
#include "pinned_integration.h"
#include "protected_wire.h"
#include "protected_input_retirement.h"
#include "native_owner_admission.h"

#include "src/Compositor.hpp"
#include "src/config/ConfigValue.hpp"
#include "src/plugins/PluginSystem.hpp"
#include "src/managers/input/InputManager.hpp"
#include "src/managers/SeatManager.hpp"
#include "src/managers/eventLoop/EventLoopManager.hpp"
#include "src/output/Monitor.hpp"
#include "src/pointer/PointerManager.hpp"
#include "src/protocols/core/Compositor.hpp"
#include "src/render/Renderer.hpp"
#include "src/render/pass/RectPassElement.hpp"
#include "src/render/pass/SurfacePassElement.hpp"
#include "src/state/MonitorState.hpp"

#include <aquamarine/input/Input.hpp>
#include <libinput.h>
#include <libudev.h>
#include <cstring>
#include <string_view>
#include <algorithm>
#include <cmath>
#include <limits>
#include <linux/input-event-codes.h>
#include <map>
#include <memory>
#include <set>
#include <wayland-server-core.h>

namespace Linura::HyprlandDisplay {
namespace {
class PrivateRole final : public ISurfaceRole
{
  public:
    eSurfaceRole role() override
    {
        return SURFACE_ROLE_LINURA_PROTECTED;
    }
};
struct NativeData;
std::weak_ptr<NativeData> active;
NativeData *activeNative = nullptr;
ProtectedInputRetirement inputRetirement;
std::unique_ptr<ProtectedWireEndpoint> endpoint;
std::uint64_t nextEpoch = 1;
std::set<std::string> scopes;
wl_event_source *drainTimer = nullptr;
std::map<std::pair<IPointer *, std::uint32_t>, WP<IPointer>> heldButtons;

bool nativeInputOrigin(libinput_device *device)
{
    if (!device)
        return false;
    auto *native = libinput_device_get_udev_device(device);
    if (!native)
        return false;
    const char *path = udev_device_get_syspath(native);
    const auto length = path ? strnlen(path, 4097) : 0;
    const std::string_view value =
        path && length <= 4096 ? std::string_view(path, length) : std::string_view{};
    // This is the live libinput device's udev object, not a client-supplied
    // name or a lookup which can adopt a recycled event node. Guest virtio/USB
    // devices remain native guest input; this makes no physical Q11 claim.
    const bool accepted =
        value.starts_with("/sys/devices/") && value.find("/virtual/") == std::string_view::npos;
    udev_device_unref(native);
    return accepted;
}
bool nativeKeyboardDevice(const SP<IKeyboard> &keyboard)
{
    const auto native = keyboard && !keyboard->isVirtual() ? keyboard->aq() : nullptr;
    return native && nativeInputOrigin(native->getLibinputHandle());
}
bool nativePointerDevice(const SP<IPointer> &pointer)
{
    const auto native = pointer && !pointer->isVirtual() ? pointer->aq() : nullptr;
    return native && nativeInputOrigin(native->getLibinputHandle());
}
ProtectedInputRetirement::Held heldInput()
{
    ProtectedInputRetirement::Held held{!heldButtons.empty(), false, !heldButtons.empty()};
    if (!g_pInputManager)
        return {true, false, true};
    for (const auto &keyboard : g_pInputManager->m_keyboards) {
        if (!nativeKeyboardDevice(keyboard))
            continue;
        for (std::uint32_t key = 0; key <= KEY_MAX; ++key) {
            if (!keyboard->getPressed(key))
                continue;
            held.any = true;
            if (key == KEY_ESC)
                held.escape = true;
            else
                held.other = true;
        }
    }
    return held;
}
bool keysHeld()
{
    return heldInput().any;
}
bool supportedPresentation()
{
    static auto shader = CConfigValue<std::string>("decoration:screen_shader");
    return g_pPluginSystem && g_pPluginSystem->pluginCount() == 0 &&
           ((*shader).empty() || *shader == STRVAL_EMPTY);
}
bool draining()
{
    return inputRetirement.blocked() || !heldButtons.empty();
}
void scheduleRefocus()
{
    if (g_pEventLoopManager)
        g_pEventLoopManager->doLater([] {
            if (!active.expired() || draining() || !g_pInputManager)
                return;
            g_pInputManager->refocus();
        });
}
struct NativeData final : std::enable_shared_from_this<NativeData>
{
    struct Surface final
    {
        OutputKey output;
        PHLMONITORREF monitor;
        WP<CWLSurfaceResource> resource;
        SP<ISurfaceRole> role;
        ProtectedScene::Configure configure;
        std::uint32_t serial = 0;
        bool acknowledged = false, selectedFrame = false, pendingFrame = false, submitted = false;
        SP<Aquamarine::IBuffer> renderedBuffer;
        std::uint64_t commitId = 0;
        CHyprSignalListener commit, destroy, present, result;
    };
    ProtectedInteraction interaction;
    std::map<OutputKey, Surface> surfaces;
    struct Keyboard final
    {
        WP<IKeyboard> device;
        std::shared_ptr<xkb_keymap> keymap;
        bool enabled = false, allowed = false;
        CHyprSignalListener changed;
    };
    std::vector<Keyboard> keyboards;
    std::vector<WP<IPointer>> pointers;
    bool closed = false;
    bool escapeDown = false;
    std::uint64_t exitBootMs = 0, exitEpoch = 0;
    wl_event_source *timer = nullptr;
    NativeData(ProtectedInteraction value) : interaction(std::move(value))
    {
        for (const auto &keyboard : g_pInputManager->m_keyboards) {
            std::shared_ptr<xkb_keymap> retained;
            if (keyboard->m_xkbKeymap)
                retained = {xkb_keymap_ref(keyboard->m_xkbKeymap), xkb_keymap_unref};
            keyboards.push_back(
                {keyboard, std::move(retained), keyboard->m_enabled, keyboard->m_allowed, {}});
        }
        for (const auto &pointer : g_pInputManager->m_pointers)
            pointers.emplace_back(pointer);
    }
    bool refresh()
    {
        if (closed || !supportedPresentation() || !Pointer::mgr() ||
            !Pointer::mgr()->protectedCursorFenceReady())
            return false;
        auto *backend = nativeBackend();
        const auto facts = backend ? backend->snapshot() : std::nullopt;
        const auto clock = compositorClock();
        bool devices = g_pInputManager && keyboards.size() == g_pInputManager->m_keyboards.size() &&
                       pointers.size() == g_pInputManager->m_pointers.size();
        if (devices) {
            for (std::size_t i = 0; i < keyboards.size(); ++i) {
                const auto keyboard = keyboards[i].device.lock();
                devices = devices && keyboard && keyboard == g_pInputManager->m_keyboards[i] &&
                          keyboard->m_xkbKeymap == keyboards[i].keymap.get() &&
                          keyboard->m_enabled == keyboards[i].enabled &&
                          keyboard->m_allowed == keyboards[i].allowed;
            }
            for (std::size_t i = 0; i < pointers.size(); ++i)
                devices = devices && pointers[i].lock() &&
                          pointers[i].lock() == g_pInputManager->m_pointers[i];
        }
        if (!devices || !facts || !clock || !interaction.refresh(*facts, *clock)) {
            interaction.cancel();
            return false;
        }
        return true;
    }
    void damage()
    {
        if (!State::monitorState() || !g_pHyprRenderer)
            return;
        for (const auto &monitor : State::monitorState()->monitors())
            if (monitor && monitor->m_enabled)
                g_pHyprRenderer->damageMonitor(monitor);
    }
    void close() noexcept
    {
        if (closed)
            return;
        closed = true;
        if (timer) {
            wl_event_source_remove(timer);
            timer = nullptr;
        }
        if (activeNative == this) {
            const auto clock = compositorClock();
            const bool explicitExit = exitBootMs != 0 && clock && clock->bootMs >= exitBootMs &&
                                      clock->bootMs - exitBootMs <= 500 &&
                                      exitEpoch == interaction.epoch() &&
                                      interaction.phase() != ProtectedInteraction::Phase::Cancelled;
            inputRetirement.close(explicitExit, heldInput());
            activeNative = nullptr;
            active.reset();
            // Unknown loss also quarantines subsequent typing. Returning to an
            // ordinary focus needs a new physical Escape and a complete drain.
            if (drainTimer && draining())
                wl_event_source_timer_update(drainTimer, 100);
            if (g_pSeatManager) {
                g_pSeatManager->setKeyboardFocus(nullptr);
                g_pSeatManager->setPointerFocus(nullptr, {});
            }
        }
        interaction.cancel();
        if (Pointer::mgr())
            Pointer::mgr()->refreshProtectedCursorFence();
        for (auto &[key, surface] : surfaces) {
            (void)key;
            surface.commit.reset();
            surface.destroy.reset();
            surface.present.reset();
            surface.result.reset();
            if (const auto resource = surface.resource.lock();
                resource && resource->m_role == surface.role) {
                resource->unmap();
                // The private role remains assigned for the wl_surface lifetime.
                // A closed authentication surface cannot become an application.
            }
        }
        keyboards.clear();
        pointers.clear();
        damage();
        if (!draining())
            scheduleRefocus();
    }
    ~NativeData()
    {
        close();
    }
    Surface *forMonitor(Monitor::CMonitor *monitor)
    {
        for (auto &[key, surface] : surfaces) {
            (void)key;
            if (surface.monitor.lock().get() == monitor)
                return &surface;
        }
        return nullptr;
    }
    SP<CWLSurfaceResource> focused()
    {
        if (!refresh())
            return nullptr;
        for (auto &[key, surface] : surfaces) {
            const auto resource = surface.resource.lock();
            const auto monitor = surface.monitor.lock();
            if (resource && monitor && monitor->m_dpmsStatus && !monitor->isMirror() &&
                surface.acknowledged) {
                interaction.focus(key);
                return resource;
            }
        }
        interaction.focus(std::nullopt);
        return nullptr;
    }
    bool inputReady()
    {
        if (!refresh())
            return false;
        const auto resource = focused();
        if (!resource || !g_pSeatManager || g_pSeatManager->m_state.keyboardFocus != resource) {
            interaction.focus(std::nullopt);
            return false;
        }
        auto *backend = nativeBackend();
        const auto facts = backend ? backend->snapshot() : std::nullopt;
        const auto clock = compositorClock();
        return facts && clock && interaction.eligible(interaction.epoch(), *facts, *clock);
    }
};
class PinnedScene final : public ProtectedScene
{
  public:
    std::shared_ptr<NativeData> data;
    explicit PinnedScene(std::shared_ptr<NativeData> native) : data(std::move(native)) {}
    ~PinnedScene() override
    {
        close();
    }
    void close() noexcept override
    {
        data->close();
    }
    bool attach(OutputKey key, wl_resource *wire, Configure configure) override
    {
        if (!data->refresh() || !configure || data->surfaces.contains(key))
            return false;
        const auto resource = CWLSurfaceResource::fromResource(wire);
        const auto monitor = nativeOutputMonitor(key);
        if (!resource || !monitor || !monitor->m_enabled || !monitor->m_output ||
            (resource->m_role && resource->m_role->role() != SURFACE_ROLE_UNASSIGNED) ||
            resource->m_current.buffer || resource->m_pending.buffer || resource->m_mapped ||
            !resource->m_subsurfaces.empty() || monitor->m_size.x < 1 || monitor->m_size.y < 1 ||
            monitor->m_size.x > 32768 || monitor->m_size.y > 32768 ||
            monitor->m_size.x != std::floor(monitor->m_size.x) ||
            monitor->m_size.y != std::floor(monitor->m_size.y) ||
            !(monitor->m_output->commitCapabilities() &
              Aquamarine::IOutput::AQ_OUTPUT_COMMIT_CAPABILITY_QUEUED))
            return false;
        auto [at, inserted] = data->surfaces.try_emplace(key);
        if (!inserted)
            return false;
        auto &surface = at->second;
        surface.output = key;
        surface.monitor = monitor->m_self;
        surface.resource = resource;
        surface.role = makeShared<PrivateRole>();
        resource->m_role = surface.role;
        surface.configure = std::move(configure);
        surface.serial = wl_display_next_serial(g_pCompositor->m_wlDisplay);
        if (!data->interaction.configure(key, surface.serial))
            return false;
        const auto weak = std::weak_ptr<NativeData>(data);
        surface.destroy = resource->m_events.destroy.listen([weak] {
            if (const auto live = weak.lock())
                live->close();
        });
        surface.commit = resource->m_events.commit.listen([weak, key] {
            const auto live = weak.lock();
            if (!live || !live->refresh())
                return;
            auto &surface = live->surfaces.at(key);
            const auto resource = surface.resource.lock();
            const auto monitor = surface.monitor.lock();
            if (!resource || !monitor || !surface.acknowledged || !resource->m_current.buffer ||
                !resource->m_current.texture || resource->m_current.size != monitor->m_size ||
                !resource->m_subsurfaces.empty()) {
                live->interaction.cancel();
                return;
            }
            if (!resource->m_mapped)
                resource->map();
            live->damage();
        });
        surface.result = monitor->m_output->events.commitResult.listen(
            [weak, key](const Aquamarine::IOutput::SCommitResult &event) {
                const auto live = weak.lock();
                if (!live || live->closed)
                    return;
                auto &surface = live->surfaces.at(key);
                if (event.id == 0 || event.id != surface.commitId)
                    return;
                if (event.status != Aquamarine::IOutput::AQ_OUTPUT_COMMIT_SUBMITTED ||
                    event.error != 0) {
                    live->interaction.cancel();
                    live->damage();
                    return;
                }
                surface.submitted = true;
            });
        surface.present = monitor->m_output->events.present.listen(
            [weak, key](const Aquamarine::IOutput::SPresentEvent &event) {
                const auto live = weak.lock();
                if (!live || !live->refresh())
                    return;
                auto &surface = live->surfaces.at(key);
                if (event.commitID == 0 || event.commitID != surface.commitId)
                    return;
                live->interaction.presented(
                    key, event.commitID,
                    surface.submitted && event.presented &&
                        (event.flags & Aquamarine::IOutput::AQ_OUTPUT_PRESENT_HW_COMPLETION));
                const auto focus = live->focused();
                if (focus && g_pSeatManager)
                    g_pSeatManager->setKeyboardFocus(focus);
            });
        resource->enter(monitor->m_self.lock());
        surface.configure(surface.serial, static_cast<std::uint32_t>(monitor->m_size.x),
                          static_cast<std::uint32_t>(monitor->m_size.y));
        return true;
    }
    bool acknowledge(OutputKey key, std::uint32_t serial) override
    {
        if (!data->refresh())
            return false;
        const auto at = data->surfaces.find(key);
        if (at == data->surfaces.end() || serial != at->second.serial || at->second.acknowledged)
            return false;
        at->second.acknowledged = true;
        return true;
    }
    std::optional<ProtectedSceneStatus> status() override
    {
        if (!data->refresh())
            return std::nullopt;
        const auto facts = nativeBackend()->snapshot();
        return facts ? std::optional(ProtectedSceneStatus{compositorInstance(), facts->generation,
                                                          data->interaction.epoch(),
                                                          data->interaction.phase()})
                     : std::nullopt;
    }
    bool consume(const std::string &digest, std::uint64_t epoch) override
    {
        if (!data->inputReady())
            return false;
        const auto facts = nativeBackend()->snapshot();
        const auto clock = compositorClock();
        auto scope = data->interaction.scope();
        scope.digest = digest;
        return facts && clock && data->interaction.consume(scope, epoch, *facts, *clock);
    }
};
} // namespace
void initializeProtectedDisplay(wl_display &display)
{
    if (endpoint)
        return;
    drainTimer = wl_event_loop_add_timer(
        g_pCompositor->m_wlEventLoop,
        [](void *) {
            if (!g_pInputManager)
                return 0;
            std::erase_if(heldButtons, [](const auto &button) {
                const auto original = button.second.lock();
                return !original ||
                       !std::ranges::any_of(g_pInputManager->m_pointers, [&](const auto &pointer) {
                           return pointer == original;
                       });
            });
            inputRetirement.poll(heldInput());
            if (draining() && drainTimer)
                wl_event_source_timer_update(drainTimer, 100);
            else
                scheduleRefocus();
            return 0;
        },
        nullptr);
    if (!drainTimer)
        return;
    endpoint = std::make_unique<ProtectedWireEndpoint>(
        display, attestDisplayOwner,
        [](const ProtectedInteraction::Scope &scope) -> std::unique_ptr<ProtectedScene> {
            if (!supportedPresentation() || !active.expired() || draining() ||
                scopes.size() >= 256 || scopes.contains(scope.digest) || !nativeBackend() ||
                !g_pInputManager || !g_pSeatManager || !Pointer::mgr() || keysHeld() ||
                !g_pInputManager->getKeysFromAllKBs().empty() ||
                g_pInputManager->hasHeldButtons() || g_pInputManager->m_keyboards.empty() ||
                g_pInputManager->m_keyboards.size() > 16 ||
                g_pInputManager->m_pointers.size() > 16 ||
                !std::ranges::any_of(g_pInputManager->m_keyboards,
                                     [](const auto &keyboard) {
                                         return nativeKeyboardDevice(keyboard) &&
                                                keyboard->m_xkbKeymap && keyboard->m_enabled &&
                                                keyboard->m_allowed;
                                     }) ||
                nextEpoch >= std::numeric_limits<std::uint64_t>::max() - 1)
                return nullptr;
            const auto facts = nativeBackend()->snapshot();
            const auto clock = compositorClock();
            if (!facts || !clock)
                return nullptr;
            auto interaction = ProtectedInteraction::start(scope, *facts, *clock, nextEpoch++);
            if (!interaction)
                return nullptr;
            auto data = std::make_shared<NativeData>(std::move(*interaction));
            for (auto &keyboard : data->keyboards) {
                const auto device = keyboard.device.lock();
                if (!device)
                    return nullptr;
                keyboard.changed = device->m_keyboardEvents.keymap.listen(
                    [weak = std::weak_ptr<NativeData>(data)](const IKeyboard::SKeymapEvent &) {
                        if (const auto live = weak.lock())
                            live->interaction.inputReplaced();
                    });
            }
            auto scene = std::make_unique<PinnedScene>(data);
            if (!inputRetirement.begin(heldInput()))
                return nullptr;
            activeNative = data.get();
            active = data;
            Pointer::mgr()->refreshProtectedCursorFence();
            if (!Pointer::mgr()->protectedCursorFenceReady()) {
                data->close();
                return nullptr;
            }
            scopes.insert(scope.digest);
            data->timer = wl_event_loop_add_timer(
                g_pCompositor->m_wlEventLoop,
                [](void *context) {
                    auto &native = *static_cast<NativeData *>(context);
                    if (!native.refresh()) {
                        native.close();
                        return 0;
                    }
                    if (native.timer)
                        wl_event_source_timer_update(native.timer, 100);
                    return 0;
                },
                data.get());
            if (!data->timer || wl_event_source_timer_update(data->timer, 100) != 0) {
                data->close();
                return nullptr;
            }
            g_pSeatManager->setKeyboardFocus(nullptr);
            g_pSeatManager->setPointerFocus(nullptr, {});
            data->damage();
            return scene;
        });
}
void shutdownProtectedDisplay()
{
    endpoint.reset();
    if (const auto data = active.lock())
        data->close();
    active.reset();
    if (drainTimer) {
        wl_event_source_remove(drainTimer);
        drainTimer = nullptr;
    }
}
bool protectedDisplayActive()
{
    return !active.expired();
}
bool protectedInputExclusive()
{
    return !active.expired() || draining();
}
bool renderProtectedDisplay(Monitor::CMonitor *monitor, const Time::steady_tp &now)
{
    const auto data = active.lock();
    if (!data || !monitor || !g_pHyprRenderer)
        return false;
    CRectPassElement::SRectData black;
    black.box = {0, 0, monitor->m_transformedSize.x, monitor->m_transformedSize.y};
    black.color = CHyprColor(0, 0, 0, 1);
    g_pHyprRenderer->m_renderPass.add(makeUnique<CRectPassElement>(black));
    auto *surface = data->forMonitor(monitor);
    if (surface) {
        surface->selectedFrame = false;
        surface->pendingFrame = false;
        surface->renderedBuffer.reset();
    }
    if (!data->refresh() || !surface)
        return true;
    const auto resource = surface->resource.lock();
    if (!surface->acknowledged || !resource || !resource->m_mapped || !resource->m_current.texture)
        return true;
    CSurfacePassElement::SRenderData frame{monitor->m_self, now, monitor->m_position, {}};
    frame.surface = resource;
    frame.texture = resource->m_current.texture;
    frame.decorate = false;
    frame.w = monitor->m_size.x;
    frame.h = monitor->m_size.y;
    g_pHyprRenderer->m_renderPass.add(makeUnique<CSurfacePassElement>(frame));
    surface->selectedFrame = true;
    resource->frame(now);
    return true;
}
void protectedFrameRendered(Monitor::CMonitor *monitor, Aquamarine::IBuffer *buffer)
{
    const auto data = active.lock();
    if (!data || !monitor || !monitor->m_output || !buffer || !data->refresh())
        return;
    auto *surface = data->forMonitor(monitor);
    const auto current = monitor->m_output->state->state().buffer;
    if (!surface || !surface->selectedFrame || !current || current.get() != buffer)
        return;
    surface->selectedFrame = false;
    surface->renderedBuffer = current;
    surface->pendingFrame = true;
}
std::optional<bool> commitProtectedDisplay(Monitor::CMonitor *monitor)
{
    const auto data = active.lock();
    if (!data)
        return std::nullopt;
    auto *surface = data->forMonitor(monitor);
    // Never submit an unrendered swapchain placeholder or a client scanout
    // buffer in the protected scene. Black-only frames are allowed only after
    // the renderer has produced a trusted frame for this exact output.
    if (!data->refresh() || !surface || !surface->pendingFrame || !monitor || !monitor->m_output ||
        !surface->renderedBuffer ||
        surface->renderedBuffer != monitor->m_output->state->state().buffer)
        return false;
    surface->pendingFrame = false;
    surface->submitted = false;
    const auto submission = monitor->m_output->commitAsync({});
    surface->renderedBuffer.reset();
    if (submission.id == 0 || submission.error != 0 ||
        !data->interaction.commit(surface->output, surface->serial, submission.id)) {
        data->interaction.cancel();
        return false;
    }
    surface->commitId = submission.id;
    return true;
}
bool focusAllowed(const SP<CWLSurfaceResource> &resource, bool keyboard)
{
    const auto data = active.lock();
    if (!resource) {
        if (data && keyboard)
            data->interaction.focus(std::nullopt);
        return true;
    }
    if (!data)
        return !draining();
    for (const auto &[key, surface] : data->surfaces) {
        (void)key;
        if (surface.resource.lock() == resource) {
            if (keyboard)
                data->interaction.focus(key);
            return true;
        }
    }
    data->interaction.focus(std::nullopt);
    return false;
}
bool protectedKeyboardFocusAllowed(const SP<CWLSurfaceResource> &surface)
{
    return focusAllowed(surface, true);
}
bool protectedPointerFocusAllowed(const SP<CWLSurfaceResource> &surface)
{
    return focusAllowed(surface, false);
}
bool protectedKeyboardKey(const IKeyboard::SKeyEvent &event, const SP<IKeyboard> &keyboard)
{
    const auto data = active.lock();
    if (!data) {
        if (!inputRetirement.blocked())
            return false;
        const bool physical =
            nativeKeyboardDevice(keyboard) && keyboard->m_enabled && keyboard->m_allowed;
        if (!inputRetirement.key(physical, event.keycode == KEY_ESC,
                                 event.state == WL_KEYBOARD_KEY_STATE_PRESSED, heldInput()))
            return false;
        if (!draining())
            scheduleRefocus();
        return true;
    }
    if (!nativeKeyboardDevice(keyboard) || !keyboard->m_enabled || !keyboard->m_allowed) {
        data->interaction.cancel();
        return true;
    }
    const bool ready = data->inputReady();
    const auto held = heldInput();
    if (event.keycode == KEY_ESC) {
        if (event.state == WL_KEYBOARD_KEY_STATE_PRESSED) {
            const auto clock = compositorClock();
            if (!data->escapeDown && !held.other && clock) {
                data->exitBootMs = clock->bootMs;
                data->exitEpoch = data->interaction.epoch();
            }
            data->escapeDown = true;
        } else if (!held.escape)
            data->escapeDown = false;
    } else if (event.state == WL_KEYBOARD_KEY_STATE_PRESSED)
        data->exitBootMs = 0;
    if (ready) {
        g_pSeatManager->setKeyboard(keyboard);
        g_pSeatManager->sendKeyboardKey(event.timeMs, event.keycode, event.state);
    } else if (event.keycode == KEY_ESC && event.state == WL_KEYBOARD_KEY_STATE_PRESSED &&
               data->exitBootMs != 0) {
        data->close(); // Physical cancellation can abandon an unready prompt.
    }
    return true;
}
bool protectedKeyboardModifiers(const SP<IKeyboard> &keyboard)
{
    const auto data = active.lock();
    if (!data)
        return draining();
    if (!nativeKeyboardDevice(keyboard) || !keyboard->m_enabled || !keyboard->m_allowed) {
        data->interaction.cancel();
        return true;
    }
    if (data->inputReady()) {
        const auto &mods = keyboard->m_modifiersState;
        g_pSeatManager->setKeyboard(keyboard);
        g_pSeatManager->sendKeyboardMods(mods.depressed, mods.latched, mods.locked, mods.group);
    }
    return true;
}
bool protectedPointerRefocus(std::uint32_t time)
{
    const auto data = active.lock();
    if (!data)
        return draining();
    const auto focus = data->focused();
    if (!focus || !data->inputReady()) {
        g_pSeatManager->setPointerFocus(nullptr, {});
        return true;
    }
    const auto position = g_pInputManager->getMouseCoordsInternal();
    for (auto &[key, surface] : data->surfaces) {
        (void)key;
        const auto monitor = surface.monitor.lock();
        const auto resource = surface.resource.lock();
        if (monitor && resource &&
            CBox{monitor->m_position, monitor->m_size}.containsPoint(position)) {
            const auto local = position - monitor->m_position;
            g_pSeatManager->setPointerFocus(resource, local);
            g_pSeatManager->sendPointerMotion(time, local);
            g_pSeatManager->sendPointerFrame();
            return true;
        }
    }
    g_pSeatManager->setPointerFocus(nullptr, {});
    return true;
}
bool protectedPointerMove(const IPointer::SMotionEvent &event)
{
    const auto data = active.lock();
    if (!data)
        return draining();
    if (!nativePointerDevice(event.device) || !event.device->m_connected) {
        data->interaction.cancel();
        return true;
    }
    Pointer::mgr()->move(event.delta);
    (void)protectedPointerRefocus(event.timeMs);
    return true;
}
bool protectedPointerWarp(const IPointer::SMotionAbsoluteEvent &event)
{
    const auto data = active.lock();
    if (!data)
        return draining();
    // Absolute physical pointers/touch/tablets have distinct device semantics;
    // they cannot be relabelled as an authenticated physical relative pointer.
    (void)event;
    data->interaction.cancel();
    return true;
}
bool protectedPointerButton(const IPointer::SButtonEvent &event, const SP<IPointer> &pointer)
{
    const auto data = active.lock();
    if (!data && !draining())
        return false;
    if (event.button > KEY_MAX) {
        if (data)
            data->interaction.cancel();
        return true;
    }
    if (!nativePointerDevice(pointer)) {
        if (data)
            data->interaction.cancel();
        return true;
    }
    const auto key = std::pair{pointer.get(), event.button};
    if (event.state == WL_POINTER_BUTTON_STATE_PRESSED) {
        heldButtons.insert_or_assign(key, pointer);
        if (data)
            data->exitBootMs = 0;
    } else
        heldButtons.erase(key);
    inputRetirement.poll(heldInput());
    if (!data) {
        if (!draining())
            scheduleRefocus();
        return true;
    }
    if (!pointer->m_connected) {
        data->interaction.cancel();
        return true;
    }
    (void)protectedPointerRefocus(event.timeMs);
    if (data->inputReady()) {
        g_pSeatManager->sendPointerButton(event.timeMs, event.button, event.state);
        g_pSeatManager->sendPointerFrame();
    }
    return true;
}
} // namespace Linura::HyprlandDisplay
