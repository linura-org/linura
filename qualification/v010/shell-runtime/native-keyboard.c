// SPDX-License-Identifier: Apache-2.0
// Qualification-only Wayland input. No provider, executor or elevated access.
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include "virtual-keyboard-unstable-v1-client-protocol.h"

struct input {
    struct wl_display *display;
    struct wl_seat *seat;
    struct zwp_virtual_keyboard_manager_v1 *manager;
    uint32_t seat_name;
    uint32_t manager_name;
};

static void fail(const char *message)
{
    fprintf(stderr, "native-keyboard: %s\n", message);
    exit(1);
}

static uint32_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        fail("monotonic clock unavailable");
    return (uint32_t)((uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
}

static void global(void *data, struct wl_registry *registry, uint32_t name,
                   const char *interface, uint32_t version)
{
    struct input *input = data;
    if (version < 1)
        return;
    if (strcmp(interface, "wl_seat") == 0) {
        if (input->seat)
            fail("qualification requires exactly one seat");
        input->seat_name = name;
        input->seat = wl_registry_bind(registry, name, &wl_seat_interface, 1);
    } else if (strcmp(interface, "zwp_virtual_keyboard_manager_v1") == 0) {
        if (input->manager)
            fail("duplicate virtual keyboard manager");
        input->manager_name = name;
        input->manager = wl_registry_bind(
            registry, name, &zwp_virtual_keyboard_manager_v1_interface, 1);
    }
}

static void global_remove(void *data, struct wl_registry *registry, uint32_t name)
{
    (void)registry;
    struct input *input = data;
    if (name == input->seat_name || name == input->manager_name)
        fail("qualification input global disappeared");
}

static const struct wl_registry_listener listener = {global, global_remove};

static void sync_display(struct wl_display *display)
{
    if (wl_display_roundtrip(display) < 0)
        fail("compositor synchronization failed");
}

static void install_keymap(struct zwp_virtual_keyboard_v1 *keyboard)
{
    // Fixed mapping; the compositor receives evdev key codes (XKB minus eight).
    static const char keymap[] =
        "xkb_keymap {\n"
        "xkb_keycodes { minimum=8; maximum=10; <K1>=9; <K2>=10; };\n"
        "xkb_types { include \"complete\" };\n"
        "xkb_compatibility { include \"complete\" };\n"
        "xkb_symbols { key <K1> { [space] }; key <K2> { [Escape] }; };\n"
        "};\n";
    char path[] = "/tmp/linura-native-keymap-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        fail("private keymap creation failed");
    if (unlink(path) != 0)
        fail("private keymap unlink failed");
    FILE *file = fdopen(fd, "wb");
    if (!file || fwrite(keymap, 1, sizeof(keymap), file) != sizeof(keymap)
            || fflush(file) != 0)
        fail("private keymap write failed");
    zwp_virtual_keyboard_v1_keymap(keyboard, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1,
                                   fd, sizeof(keymap));
    // Marshaling duplicates the fd; no pathname remains accessible.
    if (fclose(file) != 0)
        fail("private keymap close failed");
}

static void send_key(struct input *input, struct zwp_virtual_keyboard_v1 *keyboard,
                     uint32_t key)
{
    uint32_t press = monotonic_ms();
    zwp_virtual_keyboard_v1_key(keyboard, press, key, WL_KEYBOARD_KEY_STATE_PRESSED);
    uint32_t release = monotonic_ms();
    // For a tap, both events are queued before any flush, sleep or round trip.
    zwp_virtual_keyboard_v1_key(keyboard, release, key, WL_KEYBOARD_KEY_STATE_RELEASED);
    sync_display(input->display);
    printf("%s press_ms=%u release_ms=%u\n",
           key == 2 ? "escape" : "tap", press, release);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1)
        fail("no command-line arguments accepted");
    // Bound handshake, each command and idle time, including compositor stalls.
    alarm(60);
    struct input input = {0};
    input.display = wl_display_connect(NULL);
    if (!input.display)
        fail("Wayland connection unavailable");
    struct wl_registry *registry = wl_display_get_registry(input.display);
    if (!registry || wl_registry_add_listener(registry, &listener, &input) != 0)
        fail("registry subscription failed");
    sync_display(input.display);
    if (!input.seat || !input.manager)
        fail("seat or virtual keyboard protocol unavailable");
    struct zwp_virtual_keyboard_v1 *keyboard =
        zwp_virtual_keyboard_manager_v1_create_virtual_keyboard(input.manager, input.seat);
    if (!keyboard)
        fail("virtual keyboard creation failed");
    install_keymap(keyboard);
    sync_display(input.display);
    puts("ready");
    fflush(stdout);

    char command[16];
    unsigned count = 0;
    int held = 0;
    uint32_t held_press = 0;
    for (;;) {
        alarm(60);
        if (!fgets(command, sizeof(command), stdin))
            fail("input ended without explicit quit");
        if (strcmp(command, "quit\n") == 0 && !held)
            break;
        if (++count > 16)
            fail("input command budget exceeded");
        if (strcmp(command, "tap\n") == 0 && !held)
            send_key(&input, keyboard, 1);
        else if (strcmp(command, "hold\n") == 0 && !held) {
            held_press = monotonic_ms();
            zwp_virtual_keyboard_v1_key(keyboard, held_press, 1, WL_KEYBOARD_KEY_STATE_PRESSED);
            sync_display(input.display);
            held = 1;
            printf("held press_ms=%u\n", held_press);
            fflush(stdout);
        } else if (strcmp(command, "release\n") == 0 && held) {
            uint32_t release = monotonic_ms();
            zwp_virtual_keyboard_v1_key(keyboard, release, 1, WL_KEYBOARD_KEY_STATE_RELEASED);
            sync_display(input.display);
            held = 0;
            printf("hold press_ms=%u release_ms=%u\n", held_press, release);
            fflush(stdout);
        } else if (strcmp(command, "escape\n") == 0 && !held)
            send_key(&input, keyboard, 2);
        else
            fail("unsupported input command");
    }
    zwp_virtual_keyboard_v1_destroy(keyboard);
    sync_display(input.display);
    wl_seat_destroy(input.seat);
    zwp_virtual_keyboard_manager_v1_destroy(input.manager);
    wl_registry_destroy(registry);
    wl_display_disconnect(input.display);
    puts("quit");
    return 0;
}
