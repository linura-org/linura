// Official client/server wire-component harness only. It does not attest a
// compositor, login session, PAM account, deployed owner or native qualification.
#include "native_wayland_lock.h"
#include "native_lock_protocol.h"
#include "secret_entry.h"
#include "native_presentation.h"
#include "ext-session-lock-v1-server-protocol.h"
#include "xdg-shell-server-protocol.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QQuickWindow>
#include <QTimer>
#include <xkbcommon/xkbcommon.h>
#include <wayland-client-core.h>
#include <wayland-server.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace Linura::SecurityOwner;
using namespace std::chrono_literals;

namespace {
enum class Case {
    Repaint,
    ResizePressure,
    Hotplug,
    ManagedFence,
    DirectRelease,
    NoGate,
    DeniedAcquire,
    DeniedRelease,
    PaintFailure,
    Finished,
    InvalidSize,
    ActiveDestruction,
    MissingManager,
    ProbeProgress,
    ProbeStarvation,
    ProtectedInput,
    InputLateCoverage,
    InputLateFocusLoss,
    InputFocusLoss,
    InputMapChange,
    InputCapabilityLoss,
    HeldSubmission,
    InvalidKeymap,
    InvalidKeycode,
    UnknownKeymapFormat,
    RenderedInput,
    UnlockRequest,
    UnlockHeldKey,
    UnlockModifiedKey,
    UnlockDenied,
    UnlockUnavailable,
    UnlockInFlight,
    PointerRequest,
    PointerSubmit,
    PointerCancel,
    PointerDragAway,
    PointerDuplicate,
    PointerFocusLoss,
    PointerCapabilityLoss,
    PointerPromptChange,
    PointerWrongButton,
    PointerReleaseOnly,
    PointerInvalidPosition,
    PointerResize,
    PointerExpired,
    PrelockConfirm,
    PrelockCancel,
    PrelockFocusLoss,
    PrelockMapChange,
    PrelockCapabilityLoss,
    PrelockHeldKey,
    PrelockModifiedKey,
    PrelockClose,
    PrelockNativeCancel,
    PrelockMissingDesktop,
    PrelockPointerConfirm,
    PrelockPointerCancel,
    PrelockPointerFocusLoss
};
bool inputCase(Case scenario)
{
    return scenario >= Case::ProtectedInput;
}
bool unlockRequestCase(Case scenario)
{
    return scenario >= Case::UnlockRequest && scenario <= Case::UnlockInFlight;
}
bool disabledPrimaryCase(Case scenario)
{
    return scenario >= Case::UnlockDenied && scenario <= Case::UnlockInFlight;
}
bool confirmationCase(Case scenario)
{
    return scenario >= Case::PrelockConfirm;
}
bool pointerCase(Case scenario)
{
    return (scenario >= Case::PointerRequest && scenario <= Case::PointerExpired) ||
           scenario >= Case::PrelockPointerConfirm;
}

struct WireServer final
{
    struct Role;
    struct Surface final
    {
        WireServer *owner;
        Role *role = nullptr;
        wl_resource *buffer = nullptr;
        wl_resource *native = nullptr;
    };
    struct Role final
    {
        WireServer *owner;
        Surface *surface;
        wl_resource *native;
        uint32_t serial = 1;
        uint32_t acknowledged = 0;
        int width = 32;
        int height = 24;
        wl_resource *window = nullptr;
        bool desktop = false;
    };
    Case scenario;
    wl_display *display = nullptr;
    wl_global *initialOutput = nullptr;
    std::map<wl_resource *, Role *> roles;
    std::vector<wl_resource *> retained;
    std::atomic<unsigned> locks{0}, unlocks{0}, commits{0}, acknowledgements{0}, errors{0};
    std::atomic<bool> stop{false};
    std::thread worker;
    int commands = -1;
    wl_resource *keyboard = nullptr;
    wl_resource *pointer = nullptr;
    wl_resource *seat = nullptr;
    wl_resource *deferredLock = nullptr;
    std::string mapText;
    bool focusSent = false;
    uint32_t altGrMask = 0;

    static WireServer &owner(wl_resource *resource)
    {
        return *static_cast<WireServer *>(wl_resource_get_user_data(resource));
    }
    static void destroy(wl_client *, wl_resource *resource)
    {
        wl_resource_destroy(resource);
    }
    static void invalid(wl_client *, wl_resource *resource, uint32_t)
    {
        owner(resource).errors++;
        wl_resource_post_error(resource, 0, "unsupported component request");
    }
    static void surfaceDestroyed(wl_resource *resource)
    {
        auto *surface = static_cast<Surface *>(wl_resource_get_user_data(resource));
        if (surface->role)
            surface->role->surface = nullptr;
        delete surface;
    }
    static void roleDestroyed(wl_resource *resource)
    {
        auto *role = static_cast<Role *>(wl_resource_get_user_data(resource));
        if (role->surface)
            role->surface->role = nullptr;
        role->owner->roles.erase(resource);
        delete role;
    }
    static void attach(wl_client *, wl_resource *resource, wl_resource *buffer, int32_t x,
                       int32_t y)
    {
        auto &surface = *static_cast<Surface *>(wl_resource_get_user_data(resource));
        if (!buffer || x || y) {
            surface.owner->errors++;
            return;
        }
        surface.buffer = buffer;
    }
    static void rectangle(wl_client *, wl_resource *, int32_t, int32_t, int32_t, int32_t) {}
    static void region(wl_client *, wl_resource *, wl_resource *) {}
    static void integer(wl_client *, wl_resource *, int32_t) {}
    static void offset(wl_client *, wl_resource *, int32_t, int32_t) {}
    static void unsupportedFrame(wl_client *, wl_resource *resource, uint32_t)
    {
        wl_resource_post_error(resource, 0, "unexpected component frame callback");
    }
    static void commit(wl_client *, wl_resource *resource)
    {
        auto &surface = *static_cast<Surface *>(wl_resource_get_user_data(resource));
        auto &self = *surface.owner;
        if (surface.role && surface.role->desktop && !surface.buffer) {
            auto &role = *surface.role;
            assert(role.window);
            wl_array states;
            wl_array_init(&states);
            xdg_toplevel_send_configure(role.window, role.width, role.height, &states);
            wl_array_release(&states);
            xdg_surface_send_configure(role.native, role.serial);
            return;
        }
        auto *buffer = surface.buffer ? wl_shm_buffer_get(surface.buffer) : nullptr;
        if (!surface.role || !buffer || surface.role->acknowledged != surface.role->serial ||
            wl_shm_buffer_get_width(buffer) != surface.role->width ||
            wl_shm_buffer_get_height(buffer) != surface.role->height ||
            wl_shm_buffer_get_format(buffer) != WL_SHM_FORMAT_XRGB8888) {
            self.errors++;
            wl_resource_post_error(resource, 0, "invalid component frame");
            return;
        }
        const unsigned count = ++self.commits;
        if ((self.scenario == Case::ProbeProgress || self.scenario == Case::ProbeStarvation) &&
            self.deferredLock) {
            ext_session_lock_v1_send_locked(self.deferredLock);
            self.deferredLock = nullptr;
        }
        if (inputCase(self.scenario) && !self.focusSent) {
            assert(self.keyboard);
            wl_array held;
            wl_array_init(&held);
            if (self.scenario == Case::HeldSubmission || self.scenario == Case::PrelockHeldKey ||
                self.scenario == Case::UnlockHeldKey) {
                auto *code = static_cast<uint32_t *>(wl_array_add(&held, sizeof(uint32_t)));
                assert(code);
                *code = 28; // Enter held before the secure prompt.
            }
            wl_keyboard_send_enter(self.keyboard, 10, resource, &held);
            wl_array_release(&held);
            if (pointerCase(self.scenario)) {
                assert(self.pointer);
                wl_pointer_send_enter(self.pointer, 11, resource, wl_fixed_from_int(5),
                                      wl_fixed_from_int(5));
            }
            self.focusSent = true;
            if (self.scenario == Case::InputLateCoverage ||
                self.scenario == Case::InputLateFocusLoss) {
                // The compositor may focus the configured surface before its
                // final global coverage acknowledgement. No second enter follows.
                assert(self.deferredLock);
                ext_session_lock_v1_send_locked(self.deferredLock);
                self.deferredLock = nullptr;
            }
        }
        if (self.scenario == Case::Hotplug) {
            if (count == 1)
                assert(wl_global_create(self.display, &wl_output_interface, 3, &self, bindOutput));
            if (count == 2) {
                wl_global_destroy(self.initialOutput);
                self.initialOutput = nullptr;
            }
        }
        if (self.scenario == Case::ResizePressure && count <= 4) {
            self.retained.push_back(surface.buffer);
            if (count == 4) {
                auto &role = *surface.role;
                role.serial++;
                role.width = 64;
                role.height = 48;
                ext_session_lock_surface_v1_send_configure(role.native, role.serial, 64, 48);
                // Four old-size slots are busy. Configure coalesces; releasing
                // old storage then repaints and retires its callback storage.
                for (auto *item : self.retained)
                    wl_buffer_send_release(item);
                self.retained.clear();
            }
        } else
            wl_buffer_send_release(surface.buffer);
    }
    static void createSurface(wl_client *client, wl_resource *resource, uint32_t id)
    {
        auto *native = wl_resource_create(client, &wl_surface_interface, 4, id);
        assert(native);
        static const struct wl_surface_interface implementation
        {
            destroy, attach, rectangle, unsupportedFrame, region, region, commit, integer, integer,
                rectangle, offset
        };
        wl_resource_set_implementation(native, &implementation,
                                       new Surface{&owner(resource), nullptr, nullptr, native},
                                       surfaceDestroyed);
    }
    static void bindCompositor(wl_client *client, void *data, uint32_t version, uint32_t id)
    {
        auto *resource =
            wl_resource_create(client, &wl_compositor_interface, static_cast<int>(version), id);
        assert(resource);
        static const struct wl_compositor_interface implementation
        {
            createSurface, invalid
        };
        wl_resource_set_implementation(resource, &implementation, data, nullptr);
    }
    static void bindOutput(wl_client *client, void *, uint32_t version, uint32_t id)
    {
        auto *resource =
            wl_resource_create(client, &wl_output_interface, static_cast<int>(version), id);
        assert(resource);
        static const struct wl_output_interface implementation
        {
            destroy
        };
        wl_resource_set_implementation(resource, &implementation, nullptr, nullptr);
        wl_output_send_scale(resource, 1);
        wl_output_send_done(resource);
    }
    void sendMap(uint32_t format = WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, bool malformed = false)
    {
        const int descriptor = memfd_create("s17-component-keymap", MFD_CLOEXEC);
        assert(descriptor >= 0);
        const std::string text = malformed ? "not a keymap" : mapText;
        const auto size = text.size() + 1;
        assert(write(descriptor, text.c_str(), size) == static_cast<ssize_t>(size));
        wl_keyboard_send_keymap(keyboard, format, descriptor, static_cast<uint32_t>(size));
        close(descriptor);
    }
    static void keyboardDestroyed(wl_resource *resource)
    {
        owner(resource).keyboard = nullptr;
    }
    static void getKeyboard(wl_client *client, wl_resource *resource, uint32_t id)
    {
        auto &self = owner(resource);
        assert(!self.keyboard);
        self.keyboard = wl_resource_create(client, &wl_keyboard_interface, 5, id);
        assert(self.keyboard);
        static const struct wl_keyboard_interface implementation
        {
            destroy
        };
        wl_resource_set_implementation(self.keyboard, &implementation, &self, keyboardDestroyed);
        self.sendMap();
        wl_keyboard_send_repeat_info(self.keyboard, 25, 600);
    }
    static void bindSeat(wl_client *client, void *data, uint32_t version, uint32_t id)
    {
        auto &self = *static_cast<WireServer *>(data);
        assert(!self.seat);
        self.seat = wl_resource_create(client, &wl_seat_interface, static_cast<int>(version), id);
        assert(self.seat);
        static const struct wl_seat_interface implementation
        {
            getPointer, getKeyboard, invalid, destroy
        };
        wl_resource_set_implementation(self.seat, &implementation, data, nullptr);
        wl_seat_send_capabilities(
            self.seat, WL_SEAT_CAPABILITY_KEYBOARD |
                           (pointerCase(self.scenario) ? WL_SEAT_CAPABILITY_POINTER : 0));
        wl_seat_send_name(self.seat, "component-seat");
    }
    static void pointerDestroyed(wl_resource *resource)
    {
        owner(resource).pointer = nullptr;
    }
    static void setCursor(wl_client *, wl_resource *, uint32_t, wl_resource *surface, int32_t x,
                          int32_t y)
    {
        assert(!surface && x == 0 && y == 0);
    }
    static void getPointer(wl_client *client, wl_resource *resource, uint32_t id)
    {
        auto &self = owner(resource);
        assert(pointerCase(self.scenario) && !self.pointer);
        self.pointer = wl_resource_create(client, &wl_pointer_interface, 5, id);
        assert(self.pointer);
        static const struct wl_pointer_interface implementation
        {
            setCursor, destroy
        };
        wl_resource_set_implementation(self.pointer, &implementation, &self, pointerDestroyed);
        if (self.focusSent && !self.roles.empty())
            wl_pointer_send_enter(self.pointer, 34, self.roles.begin()->second->surface->native,
                                  wl_fixed_from_int(5), wl_fixed_from_int(5));
    }
    void pointerCommand(unsigned char value)
    {
        constexpr uint32_t LeftButton = 0x110;
        const auto press = [&] {
            wl_pointer_send_button(pointer, 30, 0, LeftButton, WL_POINTER_BUTTON_STATE_PRESSED);
        };
        const auto release = [&] {
            wl_pointer_send_button(pointer, 31, 0, LeftButton, WL_POINTER_BUTTON_STATE_RELEASED);
        };
        const auto motion = [&](int x, int y) {
            wl_pointer_send_motion(pointer, 0, wl_fixed_from_int(x), wl_fixed_from_int(y));
        };
        if (value == 2) {
            if (scenario == Case::PointerPromptChange || scenario == Case::PointerExpired) {
                release();
                return;
            }
            auto *surface = roles.begin()->second->surface->native;
            if (!pointer) {
                wl_seat_send_capabilities(seat,
                                          WL_SEAT_CAPABILITY_KEYBOARD | WL_SEAT_CAPABILITY_POINTER);
                return;
            }
            wl_pointer_send_enter(pointer, 33, surface, wl_fixed_from_int(5), wl_fixed_from_int(5));
            press();
            release();
            return;
        }
        if (value == 3) {
            motion(5, 5);
            press();
            release();
            return;
        }
        assert(value == 1);
        if (scenario == Case::PointerReleaseOnly) {
            release();
            return;
        }
        if (scenario == Case::PointerWrongButton) {
            wl_pointer_send_button(pointer, 30, 0, LeftButton + 1, WL_POINTER_BUTTON_STATE_PRESSED);
            wl_pointer_send_button(pointer, 31, 0, LeftButton + 1,
                                   WL_POINTER_BUTTON_STATE_RELEASED);
            return;
        }
        if (scenario == Case::PointerCancel || scenario == Case::PrelockPointerCancel)
            motion(20, 5);
        if (scenario == Case::PointerInvalidPosition)
            motion(-1, -1);
        press();
        if (scenario == Case::PointerDuplicate)
            press();
        if (scenario == Case::PointerDragAway) {
            motion(15, 20);
            motion(5, 5);
        }
        if (scenario == Case::PointerResize) {
            auto &role = *roles.begin()->second;
            role.serial++;
            role.width = 64;
            role.height = 48;
            ext_session_lock_surface_v1_send_configure(role.native, role.serial, 64, 48);
        }
        if (scenario == Case::PointerPromptChange || scenario == Case::PointerExpired)
            return;
        if (scenario == Case::PointerFocusLoss || scenario == Case::PrelockPointerFocusLoss) {
            wl_pointer_send_leave(pointer, 32, roles.begin()->second->surface->native);
        }
        if (scenario == Case::PointerCapabilityLoss) {
            wl_seat_send_capabilities(seat, WL_SEAT_CAPABILITY_KEYBOARD);
            return;
        }
        release();
    }
    void sendKey(uint32_t code, uint32_t phase = WL_KEYBOARD_KEY_STATE_PRESSED)
    {
        assert(keyboard);
        wl_keyboard_send_key(keyboard, 12, 0, code, phase);
    }
    void stroke(uint32_t code)
    {
        sendKey(code);
        sendKey(code, WL_KEYBOARD_KEY_STATE_RELEASED);
    }
    void command(unsigned char value)
    {
        assert(inputCase(scenario) && keyboard && !roles.empty());
        if (scenario == Case::InputLateFocusLoss && value == 4) {
            wl_keyboard_send_leave(keyboard, 20, roles.begin()->second->surface->native);
            return;
        }
        if (scenario == Case::InputLateCoverage && value == 3) {
            stroke(30);
            stroke(48); // Unarmed text only synchronizes actual native focus.
            return;
        }
        if (pointerCase(scenario)) {
            pointerCommand(value);
            return;
        }
        if (unlockRequestCase(scenario)) {
            if (value == 1) {
                stroke(30); // Unarmed text cannot enter protected storage.
                if (scenario == Case::UnlockModifiedKey)
                    wl_keyboard_send_modifiers(keyboard, 21, 4, 0, 0, 0);
                sendKey(28);
                sendKey(28); // Held/repeat never synthesizes an edge.
            } else {
                assert(value == 2);
                wl_keyboard_send_modifiers(keyboard, 22, 0, 0, 0, 0);
                sendKey(28, WL_KEYBOARD_KEY_STATE_RELEASED);
                stroke(28);
            }
            return;
        }
        if (confirmationCase(scenario)) {
            auto &role = *roles.begin()->second;
            assert(role.desktop);
            if (value == 1) {
                switch (scenario) {
                case Case::PrelockCancel:
                    stroke(1);
                    break;
                case Case::PrelockFocusLoss:
                    wl_keyboard_send_leave(keyboard, 20, role.surface->native);
                    break;
                case Case::PrelockMapChange:
                    sendMap();
                    break;
                case Case::PrelockCapabilityLoss:
                    wl_seat_send_capabilities(seat, 0);
                    break;
                case Case::PrelockHeldKey:
                    sendKey(28);
                    break;
                case Case::PrelockModifiedKey:
                    wl_keyboard_send_modifiers(keyboard, 21, 4, 0, 0, 0);
                    stroke(28);
                    break;
                case Case::PrelockClose:
                    xdg_toplevel_send_close(role.window);
                    break;
                default:
                    stroke(30);
                    stroke(28);
                    break; // Text is ignored; Enter is interaction only.
                }
            } else {
                assert(value == 2);
                wl_keyboard_send_modifiers(keyboard, 22, 0, 0, 0, 0);
                sendKey(28, WL_KEYBOARD_KEY_STATE_RELEASED);
                stroke(28);
            }
            return;
        }
        if (value == 1) {
            if (scenario == Case::InvalidKeymap) {
                sendMap(WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, true);
                return;
            }
            if (scenario == Case::UnknownKeymapFormat) {
                sendMap(17);
                return;
            }
            if (scenario == Case::InvalidKeycode) {
                sendKey(768);
                return;
            }
            if (scenario == Case::HeldSubmission) {
                sendKey(28);
                return;
            }
            stroke(30); // One public-layout key, never a credential fixture.
            // A duplicate press is ignored; Ctrl+V cannot paste or type text.
            sendKey(48);
            sendKey(48);
            sendKey(48, WL_KEYBOARD_KEY_STATE_RELEASED);
            stroke(14); // Backspace the second scalar.
            wl_keyboard_send_modifiers(keyboard, 13, 4, 0, 0, 0);
            stroke(47);
            wl_keyboard_send_modifiers(keyboard, 14, 0, 0, 0, 0);
            wl_keyboard_send_modifiers(keyboard, 15, altGrMask, 0, 0, 0);
            stroke(18);
            stroke(14); // AltGr Unicode must work without enabling paste.
            wl_keyboard_send_modifiers(keyboard, 16, 0, 0, 0, 0);
            stroke(40);
            stroke(18); // US-intl dead acute + e -> one Unicode scalar.
        } else if (value == 2) {
            if (scenario == Case::InputFocusLoss)
                wl_keyboard_send_leave(keyboard, 15, roles.begin()->second->surface->native);
            else if (scenario == Case::InputMapChange)
                sendMap();
            else if (scenario == Case::InputCapabilityLoss)
                wl_seat_send_capabilities(seat, 0);
            else {
                if (scenario == Case::HeldSubmission)
                    sendKey(28, WL_KEYBOARD_KEY_STATE_RELEASED);
                stroke(28);
            }
        } else
            assert(false);
    }
    static void ack(wl_client *, wl_resource *resource, uint32_t serial)
    {
        auto &role = *static_cast<Role *>(wl_resource_get_user_data(resource));
        if (serial != role.serial || serial == role.acknowledged) {
            role.owner->errors++;
            wl_resource_post_error(resource, 0,
                                   "duplicate or stale component configure acknowledgement");
            return;
        }
        role.acknowledged = serial;
        role.owner->acknowledgements++;
    }
    static void getSurface(wl_client *client, wl_resource *resource, uint32_t id,
                           wl_resource *surfaceResource, wl_resource *)
    {
        auto &self = owner(resource);
        auto *surface = static_cast<Surface *>(wl_resource_get_user_data(surfaceResource));
        assert(surface && !surface->role);
        auto *native = wl_resource_create(client, &ext_session_lock_surface_v1_interface, 1, id);
        assert(native);
        auto *role = new Role{&self, surface, native};
        if (self.scenario == Case::RenderedInput || disabledPrimaryCase(self.scenario)) {
            role->width = 640;
            role->height = 480;
        }
        surface->role = role;
        self.roles.emplace(native, role);
        static const struct ext_session_lock_surface_v1_interface implementation
        {
            destroy, ack
        };
        wl_resource_set_implementation(native, &implementation, role, roleDestroyed);
        const uint32_t width =
            self.scenario == Case::InvalidSize ? 0 : static_cast<uint32_t>(role->width);
        ext_session_lock_surface_v1_send_configure(native, role->serial, width,
                                                   static_cast<uint32_t>(role->height));
    }
    static void unlock(wl_client *, wl_resource *resource)
    {
        owner(resource).unlocks++;
        wl_resource_destroy(resource);
    }
    static void unexpectedLockDestroy(wl_client *, wl_resource *resource)
    {
        owner(resource).errors++;
        wl_resource_post_error(resource, 0, "active component lock destruction");
    }
    static void acquire(wl_client *client, wl_resource *resource, uint32_t id)
    {
        auto &self = owner(resource);
        self.locks++;
        auto *native = wl_resource_create(client, &ext_session_lock_v1_interface, 1, id);
        assert(native);
        static const struct ext_session_lock_v1_interface implementation
        {
            unexpectedLockDestroy, getSurface, unlock
        };
        wl_resource_set_implementation(native, &implementation, &self, nullptr);
        if (self.scenario == Case::InputLateCoverage || self.scenario == Case::InputLateFocusLoss ||
            self.scenario == Case::ProbeProgress || self.scenario == Case::ProbeStarvation)
            self.deferredLock = native;
        else
            ext_session_lock_v1_send_locked(native);
        if (self.scenario == Case::Finished)
            ext_session_lock_v1_send_finished(native);
    }
    static void bindManager(wl_client *client, void *data, uint32_t, uint32_t id)
    {
        auto *resource = wl_resource_create(client, &ext_session_lock_manager_v1_interface, 1, id);
        assert(resource);
        static const struct ext_session_lock_manager_v1_interface implementation
        {
            destroy, acquire
        };
        wl_resource_set_implementation(resource, &implementation, data, nullptr);
    }
    static void unusedPopup(wl_client *, wl_resource *resource, uint32_t, wl_resource *,
                            wl_resource *)
    {
        wl_resource_post_error(resource, 0, "unexpected component popup");
    }
    static void windowText(wl_client *, wl_resource *, const char *) {}
    static void windowSize(wl_client *, wl_resource *, int32_t, int32_t) {}
    static void getWindow(wl_client *client, wl_resource *resource, uint32_t id)
    {
        auto &role = *static_cast<Role *>(wl_resource_get_user_data(resource));
        assert(!role.window && role.desktop);
        role.window = wl_resource_create(client, &xdg_toplevel_interface, 1, id);
        assert(role.window);
        // Only the fixed dialog requests are legal in this harness.
        static const struct xdg_toplevel_interface implementation
        {
            destroy, nullptr, windowText, windowText, nullptr, nullptr, nullptr, windowSize,
                windowSize, nullptr, nullptr, nullptr, nullptr, nullptr
        };
        wl_resource_set_implementation(role.window, &implementation, nullptr, nullptr);
    }
    static void getDesktopSurface(wl_client *client, wl_resource *resource, uint32_t id,
                                  wl_resource *surfaceResource)
    {
        auto &self = owner(resource);
        auto *surface = static_cast<Surface *>(wl_resource_get_user_data(surfaceResource));
        assert(surface && !surface->role);
        auto *native = wl_resource_create(client, &xdg_surface_interface, 1, id);
        assert(native);
        auto *role = new Role{&self, surface, native};
        role->desktop = true;
        role->width = 640;
        role->height = 360;
        surface->role = role;
        self.roles.emplace(native, role);
        static const struct xdg_surface_interface implementation
        {
            destroy, getWindow, unusedPopup, rectangle, ack
        };
        wl_resource_set_implementation(native, &implementation, role, roleDestroyed);
    }
    static void pong(wl_client *, wl_resource *, uint32_t serial)
    {
        assert(serial == 87);
    }
    static void bindDesktop(wl_client *client, void *data, uint32_t, uint32_t id)
    {
        auto *resource = wl_resource_create(client, &xdg_wm_base_interface, 1, id);
        assert(resource);
        static const struct xdg_wm_base_interface implementation
        {
            destroy, invalid, getDesktopSurface, pong
        };
        wl_resource_set_implementation(resource, &implementation, data, nullptr);
        xdg_wm_base_send_ping(resource, 87);
    }
    WireServer(Case selected, int descriptor, int commandDescriptor)
        : scenario(selected), commands(commandDescriptor)
    {
        display = wl_display_create();
        assert(display && wl_display_init_shm(display) == 0);
        assert(wl_global_create(display, &wl_compositor_interface, 4, this, bindCompositor));
        initialOutput = wl_global_create(display, &wl_output_interface, 3, this, bindOutput);
        assert(initialOutput);
        if (selected != Case::MissingManager)
            assert(wl_global_create(display, &ext_session_lock_manager_v1_interface, 1, this,
                                    bindManager));
        if (confirmationCase(selected) && selected != Case::PrelockMissingDesktop)
            assert(wl_global_create(display, &xdg_wm_base_interface, 1, this, bindDesktop));
        if (inputCase(selected)) {
            auto *context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
            assert(context);
            const xkb_rule_names names{nullptr, nullptr, "us", "intl", nullptr};
            auto *keymap = xkb_keymap_new_from_names(context, &names, XKB_KEYMAP_COMPILE_NO_FLAGS);
            assert(keymap);
            const auto altGr = xkb_keymap_mod_get_index(keymap, "Mod5");
            assert(altGr < 32);
            altGrMask = 1U << altGr;
            char *text = xkb_keymap_get_as_string(keymap, XKB_KEYMAP_FORMAT_TEXT_V1);
            assert(text);
            mapText = text;
            free(text);
            xkb_keymap_unref(keymap);
            xkb_context_unref(context);
            assert(wl_global_create(display, &wl_seat_interface, 5, this, bindSeat));
        }
        assert(wl_client_create(display, descriptor));
        worker = std::thread([this] {
            while (!stop.load()) {
                assert(wl_event_loop_dispatch(wl_display_get_event_loop(display), 10) >= 0);
                unsigned char value = 0;
                if (recv(commands, &value, 1, MSG_DONTWAIT) == 1)
                    command(value);
                wl_display_flush_clients(display);
            }
        });
    }
    ~WireServer()
    {
        stop = true;
        worker.join();
        wl_display_destroy_clients(display);
        wl_display_destroy(display);
        close(commands);
        assert(roles.empty());
    }
};

void waitUntil(const std::function<bool()> &predicate)
{
    const auto end = std::chrono::steady_clock::now() + 1500ms;
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= end)
            _exit(80);
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        std::this_thread::sleep_for(1ms);
    }
}

class KeyFilter final : public QObject
{
  public:
    unsigned keys = 0;
    bool eventFilter(QObject *, QEvent *event) override
    {
        if (event->type() == QEvent::KeyPress || event->type() == QEvent::KeyRelease)
            keys++;
        return false;
    }
};

void client(Case scenario, int descriptor, int commands)
{
    int argc = 1;
    char name[] = "s17-wire-component";
    char *argv[] = {name, nullptr};
    if (scenario == Case::RenderedInput || confirmationCase(scenario) ||
        disabledPrimaryCase(scenario))
        QQuickWindow::setSceneGraphBackend(QStringLiteral("software"));
    std::unique_ptr<QCoreApplication> application;
    if (inputCase(scenario))
        application = std::make_unique<QGuiApplication>(argc, argv);
    else
        application = std::make_unique<QCoreApplication>(argc, argv);
    auto *display = wl_display_connect_to_fd(descriptor);
    assert(display);
    unsigned paints = 0, gates = 0, unlockRequests = 0;
    bool queuedCallback = false;
    quint64 pointerRevision = 1;
    std::unique_ptr<SecretEntry> ownedEntry;
    std::unique_ptr<NativePresentation> presentation;
    SecretEntry *entry = nullptr;
    if (scenario == Case::RenderedInput || confirmationCase(scenario) ||
        disabledPrimaryCase(scenario)) {
        presentation = std::make_unique<NativePresentation>();
        assert(presentation->initialize());
        auto state = NativePresentation::State::Authenticating;
        if (confirmationCase(scenario))
            state = NativePresentation::State::ConfirmingLock;
        else if (scenario == Case::UnlockDenied)
            state = NativePresentation::State::Denied;
        else if (scenario == Case::UnlockUnavailable)
            state = NativePresentation::State::Unavailable;
        presentation->present(state);
        entry = &presentation->protectedEntry();
    } else if (inputCase(scenario)) {
        ownedEntry = std::make_unique<SecretEntry>();
        entry = ownedEntry.get();
    }
    {
        NativeWaylandLock *ownedBackend = nullptr;
        NativeWaylandLock backend(display, [&](quint32, QImage &frame) {
            paints++;
            if (scenario == Case::ProbeProgress) {
                assert(ownedBackend);
                ownedBackend->progressNativeState(); // No recursive pump while painting.
            }
            return scenario != Case::PaintFailure && (!presentation || presentation->paint(frame));
        });
        ownedBackend = &backend;
        if (presentation)
            QObject::connect(presentation.get(), &NativePresentation::repaintRequested, &backend,
                             &NativeWaylandLock::repaint, Qt::QueuedConnection);
        assert(backend.actualDisplayFd() == descriptor);
        assert(!backend.protectedInputAvailable() && !backend.protectedInputFocused());
        if (entry) {
            // A missing primary-action observer must fail closed before native binding.
            assert(!backend.bindProtectedInput(*entry, [&] { unlockRequests++; }, {}));
            assert(backend.bindProtectedInput(
                *entry, [&] { unlockRequests++; },
                [&] { return presentation ? presentation->primaryRequestAvailable() : true; },
                pointerCase(scenario)
                    ? NativeWaylandLock::PointerHitTest([&](QSize, const QPointF &position) {
                          if (position.y() < 0 || position.y() > 10)
                              return NativePointerTarget{};
                          if (position.x() >= 0 && position.x() <= 10)
                              return NativePointerTarget{NativePointerTarget::Action::Primary,
                                                         pointerRevision};
                          if (position.x() >= 16 && position.x() <= 25)
                              return NativePointerTarget{NativePointerTarget::Action::Cancel,
                                                         pointerRevision};
                          return NativePointerTarget{};
                      })
                    : NativeWaylandLock::PointerHitTest{}));
            assert(!backend.bindProtectedInput(*entry, {}, {}));
        }
        const bool initialized = backend.initialize();
        assert(!backend.initialize()); // One startup attempt, no second reader.
        if (scenario == Case::MissingManager) {
            assert(!initialized);
            return;
        }
        assert(initialized && backend.available());
        if (entry)
            assert(backend.protectedInputAvailable() &&
                   !backend.bindProtectedInput(*entry, {}, {}));
        if (confirmationCase(scenario)) {
            assert(entry && presentation);
            unsigned completions = 0;
            bool confirmed = false;
            const bool shown = backend.showLockConfirmation([&](bool accepted) {
                completions++;
                confirmed = accepted;
                assert(!backend.lockConfirmationVisible() && !backend.secureCoverage() &&
                       !backend.requestedSecure());
            });
            if (scenario == Case::PrelockMissingDesktop) {
                assert(!shown && completions == 0);
                return;
            }
            assert(shown && !backend.showLockConfirmation([](bool) {}));
            waitUntil([&] { return backend.lockConfirmationVisible() && paints > 0; });
            assert(!backend.protectedInputFocused() && !entry->acceptsInput() &&
                   entry->maskedLength() == 0);
            assert(backend.installManagedEffectGate([&](bool) {
                gates++;
                return true;
            }));
            assert(!backend.dispatchNative(true) &&
                   gates == 0); // Confirmation cannot dispatch an effect.
            QKeyEvent synthetic(QEvent::KeyPress, Qt::Key_Return, Qt::NoModifier);
            QCoreApplication::sendEvent(entry, &synthetic);
            assert(completions == 0);
            if (scenario == Case::PrelockNativeCancel)
                backend.cancelLockConfirmation();
            else {
                unsigned char value = 1;
                assert(write(commands, &value, 1) == 1);
                if (scenario == Case::PrelockHeldKey || scenario == Case::PrelockModifiedKey) {
                    const auto until = std::chrono::steady_clock::now() + 100ms;
                    while (std::chrono::steady_clock::now() < until)
                        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
                    assert(completions == 0 && backend.lockConfirmationVisible());
                    value = 2;
                    assert(write(commands, &value, 1) == 1);
                }
                waitUntil([&] { return completions == 1; });
            }
            const bool expected =
                scenario == Case::PrelockConfirm || scenario == Case::PrelockHeldKey ||
                scenario == Case::PrelockModifiedKey || scenario == Case::PrelockPointerConfirm;
            assert(completions == 1 && confirmed == expected && gates == 0);
            backend.cancelLockConfirmation(); // Cannot replay the completed callback.
            assert(completions == 1 && !backend.lockConfirmationVisible() &&
                   entry->maskedLength() == 0);
            return;
        }
        if (scenario == Case::NoGate) {
            assert(!backend.dispatchNative(true));
            return;
        }
        if (scenario == Case::ManagedFence || scenario == Case::DirectRelease ||
            scenario == Case::ProbeProgress || scenario == Case::ProbeStarvation) {
            auto identity = NativeLockIdentity::parse(
                QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:"
                               "98765432-1234-4567-89ab-0123456789ab:1"));
            assert(identity);
            NativeLockProtocol binding(backend, *identity);
            assert(binding.bound());
            assert(binding.dispatch(*identity, true));
            if (scenario == Case::ProbeStarvation) {
                // Replies are queued on the wire, but a blocked Qt thread does
                // not read them. The ORIGINAL five-second watchdog must exit.
                std::this_thread::sleep_for(6s);
                _exit(81);
            }
            // A synchronous observer may run before Qt dispatches its socket
            // notifier. Drain actual available Wayland replies without a nested
            // Qt event loop; cached acquiring state must not hide the reply.
            const auto nativeDeadline = std::chrono::steady_clock::now() + 2s;
            while (!backend.secureCoverage() || paints == 0) {
                assert(std::chrono::steady_clock::now() < nativeDeadline);
                backend.refreshNativeState();
                std::this_thread::sleep_for(1ms);
            }
            if (scenario == Case::DirectRelease) {
                (void)backend.dispatchNative(
                    false); // No managed dispatch frame: zero release opcodes.
                _exit(81);
            }
            for (unsigned generation = 1; generation <= 2; ++generation) {
                auto stale = *identity;
                stale.generation++;
                assert(binding.inspect() == LockMechanism::State::Secure);
                assert(!binding.dispatch(stale, false));
                assert(binding.dispatch(*identity, false));
                waitUntil([&] { return !backend.requestedSecure(); });
                assert(binding.inspect() == LockMechanism::State::Releasing);
                assert(!binding.commitVerifiedRelease(*identity));
                assert(!binding.independentlyVerifiedReleased(stale));
                // These are component-only verifier/commit inputs, not a claim
                // that the fake server independently proved global release.
                assert(binding.independentlyVerifiedReleased(*identity));
                assert(binding.inspect() == LockMechanism::State::Released);
                assert(binding.identity() == *identity);
                assert(!binding.dispatch(*identity, true));
                assert(!binding.commitVerifiedRelease(stale));
                assert(binding.commitVerifiedRelease(*identity));
                const auto next = binding.identity();
                assert(next.generation == generation + 1);
                assert(!binding.dispatch(*identity, true));
                if (generation == 1) {
                    identity = next;
                    assert(binding.dispatch(*identity, true));
                    if (scenario == Case::ProbeProgress) {
                        QTimer::singleShot(0, &backend, [&] { queuedCallback = true; });
                        const auto auditsEnd = std::chrono::steady_clock::now() + 6s;
                        // Emulate successive bounded metadata reads without a
                        // Qt event loop. The server acknowledges only a valid
                        // committed frame, never the lock request itself.
                        while (std::chrono::steady_clock::now() < auditsEnd) {
                            backend.progressNativeState();
                            std::this_thread::sleep_for(20ms);
                        }
                        assert(!queuedCallback && backend.secureCoverage() && paints == 2);
                        assert(binding.inspect() == LockMechanism::State::Secure);
                    }
                    waitUntil([&] { return backend.secureCoverage() && paints >= 2; });
                }
            }
            return;
        }
        assert(backend.installManagedEffectGate([&](bool secure) {
            gates++;
            return scenario != Case::DeniedAcquire && (secure || scenario != Case::DeniedRelease);
        }));
        assert(!backend.installManagedEffectGate([](bool) { return true; }));
        unsigned beforeFocusCancellations = 0;
        if (scenario == Case::InputLateFocusLoss) {
            assert(entry && !entry->nativeAccessibilityFocused());
            QObject::connect(entry, &SecretEntry::cancellationRequested, entry,
                             [&] { ++beforeFocusCancellations; });
            assert(entry->beginNativePrompt());
        }
        assert(backend.dispatchNative(true));
        waitUntil([&] { return backend.secureCoverage() && paints > 0; });
        assert(backend.requestedSecure() && gates == 1);
        if (pointerCase(scenario)) {
            waitUntil([&] { return backend.protectedInputFocused(); });
            unsigned submissions = 0, cancellations = 0;
            const bool request = scenario != Case::PointerSubmit &&
                                 scenario != Case::PointerCancel &&
                                 scenario != Case::PointerPromptChange;
            QObject::connect(entry, &SecretEntry::submissionRequested, entry, [&] {
                submissions++;
                assert(entry->respondToNativePrompt(
                    [](const char *response) { assert(std::strlen(response) == 0); }));
            });
            QObject::connect(entry, &SecretEntry::cancellationRequested, entry,
                             [&] { cancellations++; });
            if (!request)
                assert(entry->beginNativePrompt());
            unsigned char value = 1;
            assert(write(commands, &value, 1) == 1);
            if (scenario != Case::PointerRequest && scenario != Case::PointerSubmit &&
                scenario != Case::PointerCancel) {
                const auto until = std::chrono::steady_clock::now() +
                                   (scenario == Case::PointerExpired ? 1100ms : 100ms);
                while (std::chrono::steady_clock::now() < until)
                    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
                assert(unlockRequests == 0 && submissions == 0 && cancellations == 0);
                if (scenario == Case::PointerPromptChange) {
                    entry->cancelNativePrompt();
                    assert(entry->beginNativePrompt());
                    pointerRevision++;
                }
                value = 2;
                assert(write(commands, &value, 1) == 1);
                if (scenario == Case::PointerPromptChange || scenario == Case::PointerExpired ||
                    scenario == Case::PointerCapabilityLoss) {
                    const auto settled = std::chrono::steady_clock::now() + 100ms;
                    while (std::chrono::steady_clock::now() < settled)
                        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
                    assert(unlockRequests == 0 && submissions == 0);
                    value = 3;
                    assert(write(commands, &value, 1) == 1);
                }
            }
            waitUntil([&] {
                return request                           ? unlockRequests == 1
                       : scenario == Case::PointerCancel ? cancellations == 1
                                                         : submissions == 1;
            });
            assert(gates == 1 && backend.secureCoverage() && entry->maskedLength() == 0);
            assert(backend.dispatchNative(false));
            waitUntil([&] { return !backend.requestedSecure(); });
            return;
        }
        if (unlockRequestCase(scenario)) {
            waitUntil([&] { return backend.protectedInputFocused(); });
            assert(entry && !entry->acceptsInput());
            QKeyEvent injected(QEvent::KeyPress, Qt::Key_Return, Qt::NoModifier);
            QCoreApplication::sendEvent(entry, &injected);
            assert(unlockRequests == 0);
            unsigned char value = 1;
            assert(write(commands, &value, 1) == 1);
            if (disabledPrimaryCase(scenario)) {
                const auto until = std::chrono::steady_clock::now() + 100ms;
                while (std::chrono::steady_clock::now() < until)
                    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
                assert(unlockRequests == 0 && entry->maskedLength() == 0);
                value = 2;
                assert(write(commands, &value, 1) == 1);
                const auto settled = std::chrono::steady_clock::now() + 100ms;
                while (std::chrono::steady_clock::now() < settled)
                    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
                assert(unlockRequests == 0 && !entry->acceptsInput());
                assert(backend.dispatchNative(false));
                waitUntil([&] { return !backend.requestedSecure(); });
                return;
            }
            if (scenario != Case::UnlockRequest) {
                const auto until = std::chrono::steady_clock::now() + 100ms;
                while (std::chrono::steady_clock::now() < until)
                    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
                assert(unlockRequests == 0);
                value = 2;
                assert(write(commands, &value, 1) == 1);
            }
            waitUntil([&] { return unlockRequests == 1; });
            assert(entry->maskedLength() == 0 && !entry->acceptsInput() && gates == 1 &&
                   backend.secureCoverage());
            // This request callback itself sent ZERO release opcodes. Only the
            // fixture's explicit managed effect below can release the lock.
            assert(backend.dispatchNative(false));
            waitUntil([&] { return !backend.requestedSecure(); });
            return;
        }
        if (entry) {
            waitUntil([&] { return backend.protectedInputFocused(); });
            if (scenario == Case::InputLateFocusLoss) {
                // Pre-coverage state/enter cancelled the prompt while cached
                // focus was false. Coverage then established focus, no key.
                assert(beforeFocusCancellations == 1 && !entry->acceptsInput());
                unsigned cancellations = 0;
                QObject::connect(entry, &SecretEntry::cancellationRequested, entry,
                                 [&] { ++cancellations; });
                assert(entry->nativeAccessibilityFocused());
                assert(entry->beginNativePrompt());
                unsigned char leave = 4;
                assert(write(commands, &leave, 1) == 1);
                waitUntil([&] { return cancellations != 0; });
                assert(cancellations == 1 && !entry->acceptsInput() && entry->maskedLength() == 0 &&
                       !backend.protectedInputFocused());
                assert(backend.dispatchNative(false));
                waitUntil([&] { return !backend.requestedSecure(); });
                return;
            }
            if (scenario == Case::InputLateCoverage) {
                assert(entry->nativeAccessibilityFocused());
                unsigned notices = 0;
                const auto connection =
                    QObject::connect(entry, &SecretEntry::inputChanged, entry, [&] { ++notices; });
                unsigned char synchronize = 3;
                assert(write(commands, &synchronize, 1) == 1);
                const auto settled = std::chrono::steady_clock::now() + 100ms;
                while (std::chrono::steady_clock::now() < settled)
                    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
                assert(notices == 0 && !entry->acceptsInput() && entry->maskedLength() == 0);
                QObject::disconnect(connection); // No repeated focus event per key.
            }
            KeyFilter filter;
            unsigned submissions = 0;
            bool cancelled = false;
            QObject::connect(entry, &SecretEntry::cancellationRequested, entry,
                             [&] { cancelled = true; });
            QObject::connect(entry, &SecretEntry::submissionRequested, entry, [&] {
                submissions++;
                assert(entry->respondToNativePrompt([&](const char *response) {
                    // Verify encoding/shape only; no credential is embedded or logged.
                    if (scenario == Case::HeldSubmission)
                        assert(std::strlen(response) == 0);
                    else
                        assert(std::strlen(response) == 3 && entry->maskedLength() == 2);
                }));
            });
            assert(entry->beginNativePrompt());
            // Once exclusively bound, generic Qt events cannot edit, submit or
            // cancel a protected native prompt. These synthetic events carry no
            // real response and are injected before installing the key spies.
            QKeyEvent injectedText(QEvent::KeyPress, Qt::Key_unknown, Qt::NoModifier,
                                   QString(QChar(char16_t(0x20 + 17))));
            QKeyEvent injectedSubmit(QEvent::KeyPress, Qt::Key_Return, Qt::NoModifier);
            QKeyEvent injectedCancel(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
            QCoreApplication::sendEvent(entry, &injectedText);
            QCoreApplication::sendEvent(entry, &injectedSubmit);
            QCoreApplication::sendEvent(entry, &injectedCancel);
            assert(entry->acceptsInput() && entry->maskedLength() == 0 && submissions == 0 &&
                   !cancelled);
            application->installEventFilter(&filter);
            entry->installEventFilter(&filter);
            unsigned char value = 1;
            assert(write(commands, &value, 1) == 1);
            if (scenario == Case::InvalidKeymap || scenario == Case::InvalidKeycode ||
                scenario == Case::UnknownKeymapFormat) {
                waitUntil([] { return false; }); // Must terminate closed, never release.
            }
            if (scenario == Case::HeldSubmission) {
                const auto until = std::chrono::steady_clock::now() + 100ms;
                while (std::chrono::steady_clock::now() < until)
                    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
                assert(submissions == 0 && entry->acceptsInput() && entry->maskedLength() == 0);
            } else
                waitUntil([&] { return entry->maskedLength() == 2; });
            value = 2;
            assert(write(commands, &value, 1) == 1);
            const bool cancellation = scenario == Case::InputFocusLoss ||
                                      scenario == Case::InputMapChange ||
                                      scenario == Case::InputCapabilityLoss;
            waitUntil([&] { return cancellation ? cancelled : submissions == 1; });
            assert(!entry->acceptsInput() && entry->maskedLength() == 0 && filter.keys == 0);
            if (cancellation)
                assert(submissions == 0 && !backend.protectedInputFocused());
            application->removeEventFilter(&filter);
            entry->removeEventFilter(&filter);
        }
        if (scenario == Case::ActiveDestruction)
            return;
        if (scenario == Case::Hotplug)
            waitUntil([&] { return paints >= 2; });
        if (scenario == Case::ResizePressure) {
            // Fill bounded slots without dispatching releases. Further repaints
            // coalesce; a resize then retires released old-size callback storage.
            for (unsigned i = 0; i < 20; ++i)
                backend.repaint();
            waitUntil([&] { return paints >= 5; });
        } else if (scenario == Case::Repaint) {
            for (unsigned i = 0; i < 8; ++i) {
                backend.repaint();
                QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
            }
        }
        assert(backend.dispatchNative(false));
        waitUntil([&] { return !backend.requestedSecure(); });
        assert(!backend.secureCoverage() && gates == 2);
    }
}

void run(Case scenario, int expectedExit, unsigned expectedLocks, unsigned expectedUnlocks)
{
    int sockets[2];
    int commands[2];
    int diagnostics[2] = {-1, -1};
    const bool captureProgress =
        scenario == Case::ProbeProgress || scenario == Case::ProbeStarvation;
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, commands) == 0);
    if (captureProgress)
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, diagnostics) == 0);
    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        if (captureProgress) {
            close(diagnostics[0]);
            assert(dup2(diagnostics[1], STDERR_FILENO) == STDERR_FILENO);
            close(diagnostics[1]);
        }
        close(sockets[0]);
        close(commands[0]);
        client(scenario, sockets[1], commands[1]);
        _exit(0);
    }
    close(sockets[1]);
    close(commands[1]);
    if (captureProgress)
        close(diagnostics[1]);
    WireServer server(scenario, sockets[0], commands[0]); // No server thread exists across fork.
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expectedExit)
        std::fprintf(stderr, "native wire case=%u wait-status=%d expected-exit=%d\n",
                     static_cast<unsigned>(scenario), status, expectedExit);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == expectedExit);
    if (captureProgress) {
        std::string trace;
        char bytes[512];
        ssize_t count;
        while ((count = read(diagnostics[0], bytes, sizeof(bytes))) > 0) {
            trace.append(bytes, static_cast<std::size_t>(count));
            assert(trace.size() <= 4096);
        }
        assert(count == 0);
        close(diagnostics[0]);
        if (scenario == Case::ProbeProgress) {
            const std::string cycle = "native-owner-lock-progress stage=requested\n"
                                      "native-owner-lock-progress stage=surface-configured\n"
                                      "native-owner-lock-progress stage=frame-flushed\n"
                                      "native-owner-lock-progress stage=all-surfaces-flushed\n"
                                      "native-owner-lock-progress stage=acknowledged\n"
                                      "native-owner-lock-progress stage=released\n";
            assert(trace == cycle + cycle);
        } else
            assert(trace == "native-owner-lock-progress stage=requested\n"
                            "native-owner-timeout stage=lock-acquisition\n");
    }
    assert(server.locks == expectedLocks && server.unlocks == expectedUnlocks &&
           server.errors == 0);
    if (scenario == Case::Repaint)
        assert(server.acknowledgements == 1 && server.commits > 1);
    if (scenario == Case::RenderedInput)
        assert(server.acknowledgements == 1 && server.commits > 1);
    if (scenario == Case::ResizePressure)
        assert(server.acknowledgements == 2 && server.commits >= 5);
    if (scenario == Case::Hotplug || scenario == Case::ManagedFence ||
        scenario == Case::ProbeProgress)
        assert(server.acknowledgements == 2 && server.commits >= 2);
}
} // namespace

int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--native-probe-progress") {
        run(Case::ProbeProgress, 0, 2, 2);
        run(Case::ProbeStarvation, NativeDeadline::NativeBoundaryTimeoutExit, 1, 0);
        return 0;
    }
    assert(argc == 1);
    assert(!NativeWaylandLock::boundedFrame(0, 1));
    assert(!NativeWaylandLock::boundedFrame(1, 0));
    assert(!NativeWaylandLock::boundedFrame(8193, 1));
    assert(!NativeWaylandLock::boundedFrame(UINT32_MAX, UINT32_MAX));
    assert(!NativeWaylandLock::boundedFrame(8192, 8192));
    assert(NativeWaylandLock::boundedFrame(3840, 2160));
    assert(NativeWaylandLock::boundedFrame(4096, 2048));
    assert(!NativeWaylandLock::boundedFrame(4096, 2049));
    run(Case::Repaint, 0, 1, 1);
    run(Case::ResizePressure, 0, 1, 1);
    run(Case::Hotplug, 0, 1, 1);
    run(Case::ManagedFence, 0, 2, 2);
    run(Case::DirectRelease, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::NoGate, 0, 0, 0);
    run(Case::DeniedAcquire, NativeLockProtocol::NativeLockFaultExit, 0, 0);
    run(Case::DeniedRelease, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::PaintFailure, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::Finished, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::InvalidSize, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::ActiveDestruction, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::MissingManager, 0, 0, 0);
    run(Case::ProtectedInput, 0, 1, 1);
    run(Case::InputLateCoverage, 0, 1, 1);
    run(Case::InputLateFocusLoss, 0, 1, 1);
    run(Case::InputFocusLoss, 0, 1, 1);
    run(Case::InputMapChange, 0, 1, 1);
    run(Case::InputCapabilityLoss, 0, 1, 1);
    run(Case::HeldSubmission, 0, 1, 1);
    run(Case::InvalidKeymap, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::InvalidKeycode, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::UnknownKeymapFormat, NativeLockProtocol::NativeLockFaultExit, 1, 0);
    run(Case::RenderedInput, 0, 1, 1);
    for (auto scenario : {Case::UnlockRequest, Case::UnlockHeldKey, Case::UnlockModifiedKey,
                          Case::UnlockDenied, Case::UnlockUnavailable, Case::UnlockInFlight})
        run(scenario, 0, 1, 1);
    for (auto scenario :
         {Case::PointerRequest, Case::PointerSubmit, Case::PointerCancel, Case::PointerDragAway,
          Case::PointerDuplicate, Case::PointerFocusLoss, Case::PointerCapabilityLoss,
          Case::PointerPromptChange, Case::PointerWrongButton, Case::PointerReleaseOnly,
          Case::PointerInvalidPosition, Case::PointerResize, Case::PointerExpired})
        run(scenario, 0, 1, 1);
    for (auto scenario :
         {Case::PrelockConfirm, Case::PrelockCancel, Case::PrelockFocusLoss, Case::PrelockMapChange,
          Case::PrelockCapabilityLoss, Case::PrelockHeldKey, Case::PrelockModifiedKey,
          Case::PrelockClose, Case::PrelockNativeCancel, Case::PrelockMissingDesktop,
          Case::PrelockPointerConfirm, Case::PrelockPointerCancel, Case::PrelockPointerFocusLoss})
        run(scenario, 0, 0, 0);
}
