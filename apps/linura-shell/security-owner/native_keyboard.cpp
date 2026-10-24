#include "native_keyboard.h"
#include "native_compose.h"
#include "native_lock_protocol.h"
#include "secret_entry.h"

#include <QPointer>
#include <QThread>
#include <QPainter>
#include <QPolygonF>
#include <cmath>
#include <optional>
#include <time.h>
#include <wayland-client.h>
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-compose.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <string_view>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace Linura::SecurityOwner {
namespace {
constexpr std::size_t MaximumMapBytes = 1024U * 1024U;
constexpr std::size_t MaximumKeys = 768;
[[noreturn]] void failClosed()
{
    _exit(NativeLockProtocol::NativeLockFaultExit);
}
template <class F> void callback(F &&function) noexcept
{
    try {
        function();
    } catch (...) {
        failClosed();
    }
}
void suppressDiagnostic(xkb_context *, xkb_log_level, const char *, va_list) {}

// Copy a bounded regular descriptor; never mmap compositor-controlled storage
// (truncation/SIGBUS) or block reading a pipe/device. Always close the received fd.
std::vector<char> readMap(int descriptor, std::size_t bytes, bool immutableRoot)
{
    struct stat metadata
    {};
    std::vector<char> result;
    if (descriptor >= 0 && bytes > 0 && bytes <= MaximumMapBytes &&
        fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 && fstat(descriptor, &metadata) == 0 &&
        S_ISREG(metadata.st_mode) && metadata.st_size >= 0 &&
        static_cast<unsigned long long>(metadata.st_size) == bytes &&
        (!immutableRoot ||
         (metadata.st_uid == 0 && (metadata.st_mode & 022) == 0 && metadata.st_nlink == 1))) {
        result.resize(bytes);
        std::size_t offset = 0;
        while (offset < bytes) {
            const auto count = pread(descriptor, result.data() + offset, bytes - offset,
                                     static_cast<off_t>(offset));
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0) {
                result.clear();
                break;
            }
            offset += static_cast<std::size_t>(count);
        }
    }
    if (descriptor >= 0)
        close(descriptor);
    return result;
}

} // namespace

class NativeKeyboard::Impl final
{
  public:
    QPointer<SecretEntry> entry;
    SurfaceGuard guard;
    CoverageGuard coverage;
    UnlockRequest unlockRequest;
    PrimaryRequestAvailable primaryAvailable;
    PointerHitTest hitTest;
    Repaint repaint;
    wl_pointer *pointer = nullptr;
    wl_surface *pointerFocus = nullptr;
    QPointF pointerPosition;
    std::optional<NativePointerTarget> pointerPress;
    quint64 pointerPressedAt = 0;
    bool leftHeld = false;
    wl_seat *seat = nullptr;
    wl_keyboard *keyboard = nullptr;
    wl_surface *focus = nullptr;
    wl_surface *confirmationSurface = nullptr;
    Confirmation confirmation;
    xkb_context *context = nullptr;
    xkb_keymap *map = nullptr;
    xkb_state *state = nullptr;
    xkb_compose_table *table = nullptr;
    xkb_compose_state *compose = nullptr;
    std::array<bool, MaximumKeys> pressed{};
    bool bound = false;

    Impl(SecretEntry &input, SurfaceGuard surfaceGuard, CoverageGuard coverageGuard,
         UnlockRequest request, PrimaryRequestAvailable primaryRequest, PointerHitTest target,
         Repaint paint)
        : entry(&input), guard(std::move(surfaceGuard)), coverage(std::move(coverageGuard)),
          unlockRequest(std::move(request)), primaryAvailable(std::move(primaryRequest)),
          hitTest(std::move(target)), repaint(std::move(paint))
    {
        const auto flags = static_cast<xkb_context_flags>(XKB_CONTEXT_NO_DEFAULT_INCLUDES |
                                                          XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
        context = xkb_context_new(flags);
        if (!context)
            return;
        xkb_context_set_log_fn(context, suppressDiagnostic);
        table = trustedComposeTable(context);
        if (table)
            compose = xkb_compose_state_new(table, XKB_COMPOSE_STATE_NO_FLAGS);
    }
    ~Impl()
    {
        loseFocus();
        if (pointer)
            wl_pointer_release(pointer);
        if (keyboard)
            wl_keyboard_release(keyboard);
        if (seat)
            wl_seat_release(seat);
        clearMap();
        if (compose)
            xkb_compose_state_unref(compose);
        if (table)
            xkb_compose_table_unref(table);
        if (context)
            xkb_context_unref(context);
    }
    void clearMap()
    {
        if (state)
            xkb_state_unref(state);
        if (map)
            xkb_keymap_unref(map);
        state = nullptr;
        map = nullptr;
    }
    void checkThread() const
    {
        if (!entry || entry->thread() != QThread::currentThread())
            failClosed();
    }
    void loseFocus()
    {
        pointerPress.reset();
        focus = nullptr;
        pressed.fill(false);
        if (compose)
            xkb_compose_state_reset(compose);
        if (entry) {
            checkThread();
            entry->setNativeKeyboardFocus(false);
        }
    }
    bool eligible() const
    {
        return focus && state && compose && guard && guard(focus) &&
               ((confirmationSurface == focus && confirmation) || (coverage && coverage()));
    }
    bool protectedFocus() const
    {
        return eligible() && focus != confirmationSurface && coverage && coverage();
    }
    void cancelConfirmation()
    {
        auto completion = std::move(confirmation);
        confirmationSurface = nullptr;
        loseFocus();
        if (completion)
            completion(false);
    }

    static quint64 now()
    {
        timespec time{};
        if (clock_gettime(CLOCK_BOOTTIME, &time) != 0 || time.tv_sec < 0)
            failClosed();
        return static_cast<quint64>(time.tv_sec) * 1000U +
               static_cast<quint64>(time.tv_nsec / 1'000'000);
    }
    void clearPointer()
    {
        pointerFocus = nullptr;
        pointerPress.reset();
        leftHeld = false;
        if (repaint)
            repaint();
    }
    NativePointerTarget currentPointerTarget() const
    {
        if (!pointerFocus || !guard || !guard(pointerFocus) || !hitTest ||
            !std::isfinite(pointerPosition.x()) || !std::isfinite(pointerPosition.y()) ||
            pointerPosition.x() < 0 || pointerPosition.y() < 0 || pointerPosition.x() > 8192 ||
            pointerPosition.y() > 8192 ||
            !((pointerFocus == confirmationSurface && confirmation) || (coverage && coverage())))
            return {};
        const auto target = hitTest(pointerFocus, pointerPosition);
        if (target.revision == 0 || (target.action != NativePointerTarget::Action::Primary &&
                                     target.action != NativePointerTarget::Action::Cancel))
            return {};
        return target;
    }
    static void pointerEnter(void *data, wl_pointer *native, uint32_t serial, wl_surface *surface,
                             wl_fixed_t x, wl_fixed_t y)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            if (native != self.pointer || !surface || !self.guard || !self.guard(surface))
                failClosed();
            self.clearPointer();
            self.pointerFocus = surface;
            self.pointerPosition = QPointF(wl_fixed_to_double(x), wl_fixed_to_double(y));
            // Draw the fixed cursor in our opaque frame; no theme/plugin/user
            // file selection, cursor surface or Qt input-event delivery.
            wl_pointer_set_cursor(native, serial, nullptr, 0, 0);
            if (self.repaint)
                self.repaint();
        });
    }
    static void pointerLeave(void *data, wl_pointer *native, uint32_t, wl_surface *surface)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            if (native != self.pointer || (self.pointerFocus && surface != self.pointerFocus))
                failClosed();
            const bool confirmationLost =
                self.confirmationSurface && surface == self.confirmationSurface;
            self.clearPointer();
            if (confirmationLost)
                self.cancelConfirmation();
        });
    }
    static void pointerMotion(void *data, wl_pointer *native, uint32_t, wl_fixed_t x, wl_fixed_t y)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            if (native != self.pointer)
                failClosed();
            self.pointerPosition = QPointF(wl_fixed_to_double(x), wl_fixed_to_double(y));
            if (self.pointerPress && self.currentPointerTarget() != *self.pointerPress)
                self.pointerPress.reset();
            if (self.repaint)
                self.repaint();
        });
    }
    static void pointerButton(void *data, wl_pointer *native, uint32_t, uint32_t, uint32_t button,
                              uint32_t phase)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            if (native != self.pointer || phase > WL_POINTER_BUTTON_STATE_PRESSED)
                failClosed();
            constexpr uint32_t LeftButton = 0x110;
            if (button != LeftButton) {
                self.pointerPress.reset();
                return;
            }
            if (phase == WL_POINTER_BUTTON_STATE_PRESSED) {
                if (self.leftHeld) {
                    self.pointerPress.reset();
                    return;
                }
                self.leftHeld = true;
                const auto target = self.currentPointerTarget();
                if (target.action != NativePointerTarget::Action::None)
                    self.pointerPress = target;
                self.pointerPressedAt = now();
                return;
            }
            const bool held = std::exchange(self.leftHeld, false);
            const auto pressed = std::exchange(self.pointerPress, std::nullopt);
            const auto time = now();
            if (!held || !pressed || time < self.pointerPressedAt ||
                time - self.pointerPressedAt > 1000 || *pressed != self.currentPointerTarget())
                return;
            const bool primary = pressed->action == NativePointerTarget::Action::Primary;
            if (self.pointerFocus == self.confirmationSurface && self.confirmation) {
                auto completion = std::move(self.confirmation);
                self.confirmationSurface = nullptr;
                self.loseFocus();
                completion(primary);
            } else if (self.entry->acceptsInput() && self.protectedFocus()) {
                self.entry->nativeKey(primary ? Qt::Key_Return : Qt::Key_Escape, Qt::NoModifier,
                                      {});
            } else if (primary && !self.entry->acceptsInput() && self.coverage && self.coverage() &&
                       self.unlockRequest && self.primaryAvailable && self.primaryAvailable())
                self.unlockRequest();
        });
    }
    static void pointerAxis(void *, wl_pointer *, uint32_t, uint32_t, wl_fixed_t) {}
    static void pointerFrame(void *, wl_pointer *) {}
    static void pointerAxisSource(void *, wl_pointer *, uint32_t) {}
    static void pointerAxisStop(void *, wl_pointer *, uint32_t, uint32_t) {}
    static void pointerAxisDiscrete(void *, wl_pointer *, uint32_t, int32_t) {}

    static void capabilities(void *data, wl_seat *native, uint32_t flags)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            if (native != self.seat || (flags & ~uint32_t(7)) != 0)
                failClosed();
            if ((flags & WL_SEAT_CAPABILITY_POINTER) && !self.pointer && self.hitTest) {
                self.pointer = wl_seat_get_pointer(native);
                // The seat is bound to v5. Later distribution-header listener
                // members stay null because that object cannot emit them.
                static const wl_pointer_listener listener = [] {
                    wl_pointer_listener value{};
                    value.enter = pointerEnter;
                    value.leave = pointerLeave;
                    value.motion = pointerMotion;
                    value.button = pointerButton;
                    value.axis = pointerAxis;
                    value.frame = pointerFrame;
                    value.axis_source = pointerAxisSource;
                    value.axis_stop = pointerAxisStop;
                    value.axis_discrete = pointerAxisDiscrete;
                    return value;
                }();
                if (!self.pointer || wl_pointer_add_listener(self.pointer, &listener, &self) != 0)
                    failClosed();
            } else if (!(flags & WL_SEAT_CAPABILITY_POINTER) && self.pointer) {
                self.clearPointer();
                wl_pointer_release(self.pointer);
                self.pointer = nullptr;
            }
            if ((flags & WL_SEAT_CAPABILITY_KEYBOARD) != 0 && !self.keyboard) {
                self.keyboard = wl_seat_get_keyboard(native);
                static const wl_keyboard_listener listener{keymap, enter,     leave,
                                                           key,    modifiers, repeat};
                if (!self.keyboard ||
                    wl_keyboard_add_listener(self.keyboard, &listener, &self) != 0)
                    failClosed();
            } else if ((flags & WL_SEAT_CAPABILITY_KEYBOARD) == 0 && self.keyboard) {
                self.cancelConfirmation();
                wl_keyboard_release(self.keyboard);
                self.keyboard = nullptr;
                self.clearMap();
            }
        });
    }
    static void name(void *, wl_seat *, const char *) {} // No device/account text retained.
    static void keymap(void *data, wl_keyboard *native, uint32_t format, int32_t descriptor,
                       uint32_t size)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            auto source = readMap(descriptor, size, false);
            self.checkThread();
            if (native != self.keyboard || format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 ||
                source.size() < 2 || source.back() != '\0' ||
                std::find(source.begin(), source.end() - 1, '\0') != source.end() - 1)
                failClosed();
            // Layout replacement cannot migrate a live secret conversation.
            self.cancelConfirmation();
            self.clearMap();
            self.map =
                xkb_keymap_new_from_buffer(self.context, source.data(), source.size() - 1,
                                           XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
            if (!self.map)
                failClosed();
            self.state = xkb_state_new(self.map);
            if (!self.state)
                failClosed();
        });
    }
    static void enter(void *data, wl_keyboard *native, uint32_t, wl_surface *surface,
                      wl_array *keys)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            self.loseFocus();
            if (native != self.keyboard || !surface || !self.state || !keys ||
                keys->size % sizeof(uint32_t) != 0 || keys->size > MaximumKeys * sizeof(uint32_t) ||
                (keys->size != 0 && !keys->data) || !self.guard || !self.guard(surface))
                failClosed();
            self.focus = surface;
            // Keys held before focus never synthesize text/confirmation. A new
            // press edge is required; compositor repeat and duplicate presses
            // cannot submit twice or accumulate unbounded protected text.
            const auto *held = static_cast<const uint32_t *>(keys->data);
            for (std::size_t i = 0; i < keys->size / sizeof(uint32_t); ++i) {
                if (held[i] >= MaximumKeys || self.pressed[held[i]])
                    failClosed();
                self.pressed[held[i]] = true;
            }
            self.entry->setNativeKeyboardFocus(self.protectedFocus());
        });
    }
    static void leave(void *data, wl_keyboard *native, uint32_t, wl_surface *surface)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            if (native != self.keyboard || (self.focus && surface != self.focus))
                failClosed();
            self.cancelConfirmation();
        });
    }
    static void modifiers(void *data, wl_keyboard *native, uint32_t, uint32_t depressed,
                          uint32_t latched, uint32_t locked, uint32_t group)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            if (native != self.keyboard || !self.state || group >= xkb_keymap_num_layouts(self.map))
                failClosed();
            (void)xkb_state_update_mask(self.state, depressed, latched, locked, 0, 0, group);
        });
    }
    static void repeat(void *data, wl_keyboard *native, int32_t rate, int32_t delay)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            if (native != self.keyboard || rate < 0 || rate > 1000 || delay < 0 || delay > 60'000)
                failClosed();
            // No authentication-key autorepeat. Physical press/release only.
        });
    }
    static void key(void *data, wl_keyboard *native, uint32_t, uint32_t, uint32_t code,
                    uint32_t phase)
    {
        callback([&] {
            auto &self = *static_cast<Impl *>(data);
            self.checkThread();
            if (native != self.keyboard || code >= MaximumKeys ||
                (phase != WL_KEYBOARD_KEY_STATE_PRESSED && phase != WL_KEYBOARD_KEY_STATE_RELEASED))
                failClosed();
            if (phase == WL_KEYBOARD_KEY_STATE_RELEASED) {
                self.pressed[code] = false;
                return;
            }
            if (self.pressed[code])
                return;
            self.pressed[code] = true;
            if (!self.eligible()) {
                self.cancelConfirmation();
                return;
            }
            const auto nativeCode = code + 8;
            const auto symbol = xkb_state_key_get_one_sym(self.state, nativeCode);
            if (self.focus == self.confirmationSurface && self.confirmation) {
                // Confirmation input never calls the protected text path, even
                // if a stale native prompt is accidentally still open.
                for (const char *modifier :
                     {XKB_MOD_NAME_SHIFT, XKB_MOD_NAME_CTRL, XKB_MOD_NAME_ALT, XKB_MOD_NAME_LOGO,
                      "Mod5", "LevelThree"}) {
                    if (xkb_state_mod_name_is_active(self.state, modifier,
                                                     XKB_STATE_MODS_EFFECTIVE) > 0)
                        return;
                }
                if (symbol == XKB_KEY_Return || symbol == XKB_KEY_KP_Enter ||
                    symbol == XKB_KEY_Escape) {
                    auto completion = std::move(self.confirmation);
                    self.confirmationSurface = nullptr;
                    self.loseFocus();
                    completion(symbol != XKB_KEY_Escape);
                }
                return;
            }
            // A compositor enter may precede the final lock-coverage event.
            // Derive focus again from this live guarded surface and coverage
            // before delivering a fresh press, never from the old enter flag.
            self.entry->setNativeKeyboardFocus(self.protectedFocus());
            if (!self.entry->acceptsInput()) {
                // A native press requests typed intent through Control. It is
                // not PAM success, approval, prepared dispatch or an unlock.
                if ((symbol == XKB_KEY_Return || symbol == XKB_KEY_KP_Enter) &&
                    self.protectedFocus() && self.unlockRequest && self.primaryAvailable &&
                    self.primaryAvailable()) {
                    for (const char *modifier :
                         {XKB_MOD_NAME_SHIFT, XKB_MOD_NAME_CTRL, XKB_MOD_NAME_ALT,
                          XKB_MOD_NAME_LOGO, "Mod5", "LevelThree"}) {
                        if (xkb_state_mod_name_is_active(self.state, modifier,
                                                         XKB_STATE_MODS_EFFECTIVE) > 0)
                            return;
                    }
                    self.unlockRequest();
                }
                return;
            }
            int qtKey = Qt::Key_unknown;
            switch (symbol) {
            case XKB_KEY_Return:
            case XKB_KEY_KP_Enter:
                qtKey = Qt::Key_Return;
                break;
            case XKB_KEY_Escape:
                qtKey = Qt::Key_Escape;
                break;
            case XKB_KEY_BackSpace:
                qtKey = Qt::Key_Backspace;
                break;
            case XKB_KEY_Delete:
            case XKB_KEY_KP_Delete:
                qtKey = Qt::Key_Delete;
                break;
            case XKB_KEY_Tab:
                qtKey = Qt::Key_Tab;
                break;
            case XKB_KEY_Up:
                qtKey = Qt::Key_Up;
                break;
            case XKB_KEY_Down:
                qtKey = Qt::Key_Down;
                break;
            case XKB_KEY_ISO_Left_Tab:
                qtKey = Qt::Key_Backtab;
                break;
            default:
                break;
            }
            Qt::KeyboardModifiers qtModifiers = Qt::NoModifier;
            if (xkb_state_mod_name_is_active(self.state, XKB_MOD_NAME_CTRL,
                                             XKB_STATE_MODS_EFFECTIVE) > 0)
                qtModifiers |= Qt::ControlModifier;
            if (xkb_state_mod_name_is_active(self.state, XKB_MOD_NAME_LOGO,
                                             XKB_STATE_MODS_EFFECTIVE) > 0)
                qtModifiers |= Qt::MetaModifier;
            if (xkb_state_mod_name_is_active(self.state, "Mod5", XKB_STATE_MODS_EFFECTIVE) > 0 ||
                xkb_state_mod_name_is_active(self.state, "LevelThree", XKB_STATE_MODS_EFFECTIVE) >
                    0)
                qtModifiers |= Qt::GroupSwitchModifier;
            std::array<char, 128> text{};
            struct WipeText final
            {
                std::array<char, 128> &bytes;
                ~WipeText()
                {
                    explicit_bzero(bytes.data(), bytes.size());
                }
            } wipe{text};
            int length = 0;
            const bool shortcut = (qtModifiers & (Qt::ControlModifier | Qt::MetaModifier)) &&
                                  !(qtModifiers & Qt::GroupSwitchModifier);
            if (qtKey == Qt::Key_unknown && !shortcut) {
                (void)xkb_compose_state_feed(self.compose, symbol);
                switch (xkb_compose_state_get_status(self.compose)) {
                case XKB_COMPOSE_COMPOSING:
                    return;
                case XKB_COMPOSE_CANCELLED:
                    xkb_compose_state_reset(self.compose);
                    return;
                case XKB_COMPOSE_COMPOSED:
                    length = xkb_compose_state_get_utf8(self.compose, text.data(), text.size());
                    xkb_compose_state_reset(self.compose);
                    break;
                case XKB_COMPOSE_NOTHING:
                    length =
                        xkb_state_key_get_utf8(self.state, nativeCode, text.data(), text.size());
                    break;
                }
            } else
                xkb_compose_state_reset(self.compose);
            if (length < 0 || static_cast<std::size_t>(length) >= text.size()) {
                explicit_bzero(text.data(), text.size());
                self.loseFocus();
                return;
            }
            // No owning QString/QKeyEvent copy: validated native UTF-8 goes
            // directly into protected storage. It never enters Qt input queues,
            // QML/window/application filters or shortcut handlers.
            self.entry->nativeKey(qtKey, qtModifiers,
                                  std::string_view(text.data(), static_cast<std::size_t>(length)));
            explicit_bzero(text.data(), text.size());
        });
    }
};

NativeKeyboard::NativeKeyboard(SecretEntry &entry, SurfaceGuard guard, CoverageGuard coverage,
                               UnlockRequest request, PrimaryRequestAvailable primaryAvailable,
                               PointerHitTest hitTest, Repaint repaint)
    : impl_(std::make_unique<Impl>(entry, std::move(guard), std::move(coverage), std::move(request),
                                   std::move(primaryAvailable), std::move(hitTest),
                                   std::move(repaint)))
{}
NativeKeyboard::~NativeKeyboard() = default;
bool NativeKeyboard::bind(wl_seat *ownedSeat)
{
    impl_->checkThread();
    if (impl_->bound || !ownedSeat || !impl_->context || !impl_->compose || !impl_->guard ||
        !impl_->coverage || !impl_->primaryAvailable || wl_seat_get_version(ownedSeat) < 5 ||
        !impl_->entry->bindNativeInput()) {
        if (ownedSeat)
            wl_seat_release(ownedSeat);
        return false;
    }
    impl_->bound = true;
    impl_->seat = ownedSeat;
    static const wl_seat_listener listener{Impl::capabilities, Impl::name};
    return wl_seat_add_listener(ownedSeat, &listener, impl_.get()) == 0;
}
bool NativeKeyboard::available() const noexcept
{
    return impl_->entry && impl_->keyboard && impl_->state && impl_->compose;
}
bool NativeKeyboard::focused() const
{
    impl_->checkThread();
    return impl_->protectedFocus();
}
void NativeKeyboard::refreshProtectedFocus()
{
    impl_->checkThread();
    impl_->entry->setNativeKeyboardFocus(impl_->protectedFocus());
}
void NativeKeyboard::forgetSurface(wl_surface *surface)
{
    if (surface && impl_->pointerFocus == surface)
        impl_->clearPointer();
    if (surface && impl_->focus == surface)
        resetFocus();
}
void NativeKeyboard::paintPointer(wl_surface *surface, QImage &frame) const
{
    impl_->checkThread();
    if (!surface || impl_->pointerFocus != surface || frame.isNull() ||
        !std::isfinite(impl_->pointerPosition.x()) || !std::isfinite(impl_->pointerPosition.y()) ||
        !QRectF(QPointF(0, 0), frame.size()).contains(impl_->pointerPosition))
        return;
    QPainter painter(&frame);
    painter.translate(impl_->pointerPosition);
    painter.setPen(QPen(Qt::black, 2));
    painter.setBrush(Qt::white);
    painter.drawPolygon(QPolygonF{QPointF(0, 0), QPointF(0, 22), QPointF(6, 16), QPointF(11, 26),
                                  QPointF(15, 24), QPointF(10, 14), QPointF(19, 14)});
}
void NativeKeyboard::resetFocus()
{
    impl_->checkThread();
    impl_->loseFocus();
}
bool NativeKeyboard::setConfirmationTarget(wl_surface *surface, Confirmation completion)
{
    impl_->checkThread();
    if (!available() || !surface || !completion || impl_->confirmationSurface ||
        impl_->confirmation)
        return false;
    impl_->loseFocus();
    impl_->confirmationSurface = surface;
    impl_->confirmation = std::move(completion);
    return true;
}
void NativeKeyboard::clearConfirmationTarget()
{
    impl_->checkThread();
    impl_->confirmationSurface = nullptr;
    impl_->confirmation = {};
    impl_->loseFocus();
}

} // namespace Linura::SecurityOwner
