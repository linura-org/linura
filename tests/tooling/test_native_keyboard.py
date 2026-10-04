from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import re

from tools.verify_tray_keyboard import decode_snapshot, verify, verify_records, verify_retained, holding_ready

ROOT = Path(__file__).resolve().parents[2]


class NativeFocusReadinessTests(unittest.TestCase):
    def test_async_opener_readiness_never_retries_key_activation(self):
        text = (ROOT / "qualification/v010/shell-runtime/run-shell-runtime.sh").read_text()
        def function(name):
            match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', text, re.M | re.S)
            self.assertIsNotNone(match)
            return match.group()
        with tempfile.TemporaryDirectory() as directory:
            script = '''set -euo pipefail
checked_panel_call() {
    case "$2" in
        trayKeyboardSnapshot) echo '{}' ;;
        trayOverflowOpenCount) echo 0 ;;
        focusTrayOverflowButtonControl)
            local count=0
            if [[ -f "$TASK_DIR/focus" ]]; then read -r count < "$TASK_DIR/focus"; fi
            count=$((count + 1))
            echo "$count" > "$TASK_DIR/focus"
            if (( count >= 3 )); then echo true; else echo false; fi ;;
        trayOverflowButtonFocused) echo true ;;
        *) exit 2 ;;
    esac
}
fail() { echo "$*" >&2; exit 1; }
native_input_send() {
    local count
    read -r count < "$TASK_DIR/focus"
    (( count >= 3 )) || fail 'input sent before native focus'
    echo "$1" >> "$TASK_DIR/events"
}
'''
            script += '\n'.join(function(name) for name in (
                'wait_until', 'panel_tray_opener_focus_ready', 'panel_tray_open_by_keyboard'))
            script += '\npanel_tray_open_by_keyboard\n'
            result = subprocess.run(['bash', '-c', script], text=True, capture_output=True,
                                    env={**os.environ, 'TASK_DIR': directory}, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(directory) / 'focus').read_text().strip(), '3')
            self.assertEqual((Path(directory) / 'events').read_text(), 'tap\n')
SOURCE = ROOT / 'qualification/v010/shell-runtime/native-keyboard.c'
# A recording Wayland adapter executes the real C producer without installing
# desktop dependencies. Native Qt repeat/focus behavior is tested in the guest.
MOCK = r'''
#ifndef LINURA_MOCK_WAYLAND
#define LINURA_MOCK_WAYLAND
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
struct wl_display { int unused; };
struct wl_registry { int unused; };
struct wl_seat { int unused; };
struct zwp_virtual_keyboard_manager_v1 { int unused; };
struct zwp_virtual_keyboard_v1 { int unused; };
struct wl_interface { int unused; };
static struct wl_interface wl_seat_interface;
static struct wl_interface zwp_virtual_keyboard_manager_v1_interface;
struct wl_registry_listener {
 void (*global)(void *, struct wl_registry *, uint32_t, const char *, uint32_t);
 void (*global_remove)(void *, struct wl_registry *, uint32_t);
};
static const struct wl_registry_listener *saved_listener;
static void *saved_data;
static int discovered;
#define WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 1
#define WL_KEYBOARD_KEY_STATE_PRESSED 1
#define WL_KEYBOARD_KEY_STATE_RELEASED 0
static struct wl_display *wl_display_connect(const char *name) {
 (void)name; return getenv("MOCK_NO_DISPLAY") ? NULL : (void *)1;
}
static struct wl_registry *wl_display_get_registry(struct wl_display *d) {
 (void)d; return (void *)2;
}
static int wl_registry_add_listener(struct wl_registry *r, const struct wl_registry_listener *l, void *data) {
 (void)r; saved_listener=l; saved_data=data; return 0;
}
static void *wl_registry_bind(struct wl_registry *r, uint32_t n, const struct wl_interface *i, uint32_t v) {
 (void)r; (void)n; (void)i; (void)v; return (void *)3;
}
static int wl_display_roundtrip(struct wl_display *d) {
 (void)d; fputs("sync\n",stderr);
 if (!discovered++) {
  saved_listener->global(saved_data,(void *)2,1,"wl_seat",1);
  if (!getenv("MOCK_NO_PROTOCOL"))
   saved_listener->global(saved_data,(void *)2,2,"zwp_virtual_keyboard_manager_v1",1);
  if (getenv("MOCK_TWO_SEATS"))
   saved_listener->global(saved_data,(void *)2,3,"wl_seat",1);
 }
 return getenv("MOCK_SYNC_FAIL") ? -1 : 0;
}
static struct zwp_virtual_keyboard_v1 *zwp_virtual_keyboard_manager_v1_create_virtual_keyboard(
 struct zwp_virtual_keyboard_manager_v1 *m, struct wl_seat *s) {
 (void)m; (void)s; fputs("create\n",stderr); return (void *)4;
}
static void zwp_virtual_keyboard_v1_keymap(struct zwp_virtual_keyboard_v1 *k,uint32_t f,int fd,uint32_t size) {
 (void)k; (void)f; (void)fd; (void)size; fputs("keymap\n",stderr);
}
static void zwp_virtual_keyboard_v1_key(struct zwp_virtual_keyboard_v1 *k,uint32_t t,uint32_t key,uint32_t state) {
 (void)k; fprintf(stderr,"key %u %u %u\n",key,state,t);
}
static void zwp_virtual_keyboard_v1_destroy(struct zwp_virtual_keyboard_v1 *k) {
 (void)k; fputs("destroy\n",stderr);
}
static void wl_seat_destroy(struct wl_seat *s) { (void)s; }
static void zwp_virtual_keyboard_manager_v1_destroy(struct zwp_virtual_keyboard_manager_v1 *m) { (void)m; }
static void wl_registry_destroy(struct wl_registry *r) { (void)r; }
static void wl_display_disconnect(struct wl_display *d) { (void)d; }
#endif
'''


class NativeKeyboardProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which('cc') is None:
            raise RuntimeError('native input behavioral tests require the declared C compiler')
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        (cls.root / 'wayland-client.h').write_text(MOCK)
        (cls.root / 'virtual-keyboard-unstable-v1-client-protocol.h').write_text('#include "wayland-client.h"\n')
        cls.binary = cls.root / 'native-keyboard'
        cls.compile(SOURCE, cls.binary)

    @classmethod
    def compile(cls, source, binary):
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(cls.root),
                        str(source), '-o', str(binary)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_input(self, commands, *, flags=(), binary=None, arguments=()):
        environment = os.environ.copy()
        for flag in flags:
            environment[flag] = '1'
        return subprocess.run([str(binary or self.binary), *arguments], input=commands,
                              text=True, capture_output=True, timeout=10, env=environment)

    def assert_batched_tap(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stderr.splitlines()
        for index, line in enumerate(lines):
            if line.startswith('key ') and line.split()[2] == '1':
                self.assertTrue(lines[index + 1].startswith('key '), result.stderr)
                self.assertEqual(lines[index + 1].split()[1:3], [line.split()[1], '0'])

    def test_taps_and_escape_are_batched_on_one_persistent_device(self):
        result = self.run_input('tap\ntap\nescape\nquit\n')
        self.assert_batched_tap(result)
        self.assertEqual(result.stderr.splitlines().count('create'), 1)
        self.assertEqual(result.stderr.splitlines().count('keymap'), 1)
        self.assertEqual(result.stderr.splitlines().count('destroy'), 1)
        self.assertEqual([line.split()[0] for line in result.stdout.splitlines()],
                         ['ready', 'tap', 'tap', 'escape', 'quit'])

    def test_roundtrip_between_tap_events_is_detected_behaviorally(self):
        mutant = self.root / 'mutant.c'
        text = SOURCE.read_text()
        needle = 'uint32_t release = monotonic_ms();\n    // For a tap'
        self.assertEqual(text.count(needle), 1)
        mutant.write_text(text.replace(needle, 'sync_display(input->display);\n    ' + needle))
        binary = self.root / 'mutant'
        self.compile(mutant, binary)
        with self.assertRaises(AssertionError):
            self.assert_batched_tap(self.run_input('tap\nquit\n', binary=binary))

    def test_adversarial_hold_waits_for_an_explicit_receiver_driven_release(self):
        process = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(process.stdout.readline().strip(), 'ready')
        process.stdin.write('hold\n')
        process.stdin.flush()
        self.assertRegex(process.stdout.readline().strip(), r'held press_ms=\d+')
        self.assertIsNone(process.poll())
        output, errors = process.communicate('release\nquit\n', timeout=10)
        self.assertEqual(process.returncode, 0, errors)
        self.assertRegex(output, r'hold press_ms=\d+ release_ms=\d+\nquit\n')
        self.assertRegex(errors, r'key 1 1 \d+\nsync\nkey 1 0')
        for commands in ('release\nquit\n', 'hold\ntap\n', 'hold\nquit\n'):
            with self.subTest(commands=commands):
                self.assertNotEqual(self.run_input(commands).returncode, 0)

    def test_unknown_overlong_eof_and_unbounded_input_fail_closed(self):
        for commands in ('arbitrary\nquit\n', 'x' * 30 + '\nquit\n', 'tap\n',
                         'tap\n' * 17 + 'quit\n'):
            with self.subTest(commands=commands):
                self.assertNotEqual(self.run_input(commands).returncode, 0)
        self.assertNotEqual(self.run_input('quit\n', arguments=('tap',)).returncode, 0)

    def test_unavailable_or_ambiguous_native_input_fails_closed(self):
        for flag in ('MOCK_NO_DISPLAY', 'MOCK_NO_PROTOCOL', 'MOCK_TWO_SEATS', 'MOCK_SYNC_FAIL'):
            with self.subTest(flag=flag):
                self.assertNotEqual(self.run_input('quit\n', flags=(flag,)).returncode, 0)


class TrayReceiverEvidenceTests(unittest.TestCase):
    def snapshots(self):
        before = dict(activations=0, opens=0, presses=0, releases=0, repeats=0,
                      pressMs=0, releaseMs=0, visible=False)
        after = dict(activations=1, opens=1, presses=1, releases=1, repeats=0,
                     pressMs=1000, releaseMs=1001, visible=True)
        return before, after

    def test_exactly_once_native_tap_and_held_repeat_filtering(self):
        before, after = self.snapshots()
        verify('tap', before, after, 'tap press_ms=100 release_ms=101')
        after['repeats'] = 20
        verify('hold', before, after, 'hold press_ms=100 release_ms=1600',
               dict(before, presses=1, repeats=20))

    def test_duplicate_activation_missed_delivery_and_hidden_popup_are_rejected(self):
        for field, value in [('activations', 18), ('opens', 18), ('presses', 0),
                             ('releases', 0), ('visible', False), ('releaseMs', 999)]:
            before, after = self.snapshots()
            after[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify('tap', before, after, 'tap press_ms=100 release_ms=101')

    def test_unexercised_hold_and_wrong_producer_receipts_are_rejected(self):
        before, after = self.snapshots()
        for receipt in ('hold press_ms=100 release_ms=1600',
                        'hold press_ms=100 release_ms=101', 'tap press_ms=100 release_ms=1600'):
            with self.subTest(receipt=receipt), self.assertRaises(ValueError):
                verify('hold', before, after, receipt)

    def test_hold_release_requires_observed_repeats_without_early_activation(self):
        before, _ = self.snapshots()
        held = dict(before, presses=1, repeats=0)
        self.assertFalse(holding_ready(before, held))
        held['repeats'] = 2
        self.assertTrue(holding_ready(before, held))
        held['activations'] = 1
        with self.assertRaises(ValueError):
            holding_ready(before, held)

    def test_snapshot_parser_rejects_duplicate_boolean_and_missing_fields(self):
        before, _ = self.snapshots()
        for invalid in [json.dumps(before).replace('"opens": 0', '"opens": true'),
                        '{"opens":0,"opens":1}', '{}', '[]', ' ' * 4097]:
            with self.assertRaises(ValueError):
                decode_snapshot(invalid)

    def test_retained_matrix_requires_all_cases_and_unbroken_counter_lineage(self):
        before, _ = self.snapshots()
        rows = []
        for index in range(6):
            after = dict(before)
            for field in ('activations', 'opens', 'presses', 'releases'):
                after[field] += 1
            after.update(pressMs=1000 + index * 100, releaseMs=1001 + index * 100, visible=True)
            mode = 'hold' if index == 5 else 'tap'
            if mode == 'hold':
                after['repeats'] = 20
            receipt = f'{mode} press_ms=100 release_ms={1600 if mode == "hold" else 101}'
            held = dict(before, presses=before['presses'] + 1, repeats=20) if mode == 'hold' else None
            rows.append(dict(mode=mode, before=dict(before), held=held, after=after, producer=receipt))
            before = dict(after, visible=False)
        report = '\n'.join(json.dumps(row) for row in rows)
        verify_records(report)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            behavior, events, digest = (root / name for name in ('behavior', 'events', 'digest'))
            behavior.write_text(report)
            receipts = [row['producer'] for row in rows]
            events.write_text('\n'.join(receipts[:5] + ['held press_ms=100', receipts[5], 'escape press_ms=1800 release_ms=1801', 'quit']))
            digest.write_text('a' * 64 + '  /usr/local/lib/linura-qualification/native-keyboard\n')
            verify_retained(behavior, events, digest)
            events.write_text('\n'.join(receipts + ['quit']))
            with self.assertRaises(ValueError):
                verify_retained(behavior, events, digest)
            behavior.write_text(' ' * 65537)
            with self.assertRaises(ValueError):
                verify_retained(behavior, events, digest)
        with self.assertRaises(ValueError):
            verify_records('\n'.join(report.splitlines()[:-1]))
        rows[3]['before']['activations'] += 1
        with self.assertRaises(ValueError):
            verify_records('\n'.join(json.dumps(row) for row in rows))
