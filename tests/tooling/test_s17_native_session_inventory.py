"""Session inventory/class/recovery regressions, never native VM evidence."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "qualification/v010/session-security"


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), FIXTURE / (name + ".py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load("native-suspend-fixture")
runner = load("qualify-native-suspend")
codec = runner.codec
LOCK = "session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:2"
TARGET = {
    "Id": "c1",
    "User": "1000",
    "Class": "user",
    "Type": "wayland",
    "Active": "yes",
    "Remote": "no",
    "State": "active",
    "TimestampMonotonic": "9",
}


def fields(values):
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode()


def rows(*identities):
    # The unused display fields may include Unicode. They carry no authority.
    return json.dumps(
        [
            {
                "session": session,
                "uid": uid,
                "user": "bounded-display-ä",
                "seat": None,
                "tty": None,
                "idle": False,
                "since": None,
            }
            for session, uid in identities
        ],
        ensure_ascii=False,
    ).encode()


class NativeSessionInventoryTests(unittest.TestCase):
    def test_departing_login_discards_partial_snapshot_before_fresh_admission(self):
        other = {**TARGET, "Id": "c2", "Class": "manager-early"}
        wire = [
            rows(("c1", 1000), ("c2", 1000)),
            fields(TARGET),
            fixture.CommandRefused(1, "private-wire-marker"),
            rows(("c1", 1000), ("c2", 1000)),
            fields(TARGET),
            fields({**other, "Class": "user", "Remote": "yes"}),
            rows(("c1", 1000)),
            fields(TARGET),
        ]
        with (
            patch.object(fixture, "command", side_effect=wire) as command,
            patch.object(fixture.time, "sleep") as sleep,
        ):
            fixture.wait_for_only_target_session(
                LOCK, codec, fixture.time.monotonic() + 20
            )
        self.assertEqual(command.call_count, len(wire))
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(
            [call.args[0][1] for call in command.call_args_list].count("list-sessions"),
            3,
        )

    def test_persistent_inventory_refusal_keeps_original_deadline_and_closed_reason(
        self,
    ):
        for listing in (False, True):
            clock = [0.0]

            def advance(seconds):
                clock[0] += seconds

            failure = fixture.CommandRefused(1, "private-wire-marker")

            def refused_query(arguments, **_):
                if not listing and arguments[1] == "list-sessions":
                    return rows(("c1", 1000))
                raise failure

            with (
                self.subTest(listing=listing),
                patch.object(fixture.time, "monotonic", side_effect=lambda: clock[0]),
                patch.object(fixture.time, "sleep", side_effect=advance),
                patch.object(
                    fixture,
                    "command",
                    side_effect=refused_query,
                ) as command,
                self.assertRaises(fixture.CommandRefused) as caught,
            ):
                fixture.wait_for_only_target_session(LOCK, codec, 0.25)
            self.assertEqual(clock[0], 0.25)
            self.assertEqual(caught.exception.returncode, 1)
            self.assertEqual(
                caught.exception.categories,
                "session-list-refused" if listing else "session-properties-refused",
            )
            self.assertNotIn("private-wire-marker", str(caught.exception))
            self.assertTrue(
                all(
                    0 < call.kwargs["budget"] <= 0.25 for call in command.call_args_list
                )
            )

    def test_inventory_retry_never_accepts_unknown_state_or_expired_complete_snapshot(
        self,
    ):
        with (
            patch.object(
                fixture,
                "command",
                side_effect=[rows(("c1", 1000)), fields({**TARGET, "User": "1001"})],
            ) as command,
            patch.object(fixture.time, "sleep") as sleep,
            self.assertRaisesRegex(codec.InventoryFailure, "session-inventory-drift"),
        ):
            fixture.wait_for_only_target_session(
                LOCK, codec, fixture.time.monotonic() + 20
            )
        self.assertEqual(command.call_count, 2)
        sleep.assert_not_called()
        with (
            patch.object(fixture.time, "monotonic", side_effect=[0, 20]),
            patch.object(fixture, "only_target_session", return_value=True),
            self.assertRaisesRegex(codec.InventoryFailure, "session-inventory-timeout"),
        ):
            fixture.wait_for_only_target_session(LOCK, codec, 20)

    def test_logout_presence_retry_requires_fresh_absence_and_never_assumes_read_failure(
        self,
    ):
        with (
            patch.object(
                fixture,
                "command",
                side_effect=[
                    rows(("c1", 1000)),
                    fixture.CommandRefused(1),
                    rows(("c2", 1000)),
                ],
            ) as command,
            patch.object(fixture.time, "sleep"),
        ):
            self.assertFalse(
                fixture.original_session_present(
                    LOCK, codec, fixture.time.monotonic() + 15
                )
            )
        self.assertEqual(command.call_count, 3)
        clock = [0.0]

        def advance(seconds):
            clock[0] += seconds

        with (
            patch.object(fixture.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(fixture.time, "sleep", side_effect=advance),
            patch.object(fixture, "command", side_effect=fixture.CommandRefused(1)),
            self.assertRaises(fixture.CommandRefused),
        ):
            fixture.original_session_present(LOCK, codec, 0.25)
        self.assertEqual(clock[0], 0.25)

    def test_login_client_requires_one_property_per_selector(self):
        # loginctl appends each -p argument as ONE literal property name; it
        # does not split comma lists like systemctl. Real-client/private-bus
        # controls independently reproduced exit0/empty for the old selector.
        def native_query(arguments, **_):
            selectors = [
                argument.removeprefix("--property=")
                for argument in arguments
                if argument.startswith("--property=")
            ]
            return fields(
                {key: value for key, value in TARGET.items() if key in selectors}
            )

        with patch.object(fixture, "command", side_effect=native_query) as command:
            self.assertEqual(
                fixture.session_facts("c1", 1000, codec, fixture.time.monotonic() + 20),
                TARGET,
            )
        selectors = [
            arg for arg in command.call_args.args[0] if arg.startswith("--property=")
        ]
        self.assertEqual(len(selectors), 8)
        self.assertTrue(all("," not in argument for argument in selectors))
        self.assertEqual(
            {arg.removeprefix("--property=") for arg in selectors}, set(TARGET)
        )

    def inspect(self, other):
        wire = [
            rows(("c1", 1000), ("c2", int(other["User"]))),
            fields(TARGET),
            fields(other),
        ]
        with patch.object(fixture, "command", side_effect=wire):
            return fixture.only_target_session(
                LOCK, codec, fixture.time.monotonic() + 20
            )

    def test_same_owner_service_classes_follow_production_without_ignoring_foreign_users(
        self,
    ):
        for session_class in (
            "manager",
            "manager-early",
            "background",
            "background-light",
        ):
            for uid in (0, 1000, 1001):
                for state in ("opening", "online", "active", "closing"):
                    with self.subTest(
                        session_class=session_class, uid=uid, state=state
                    ):
                        other = {
                            **TARGET,
                            "Id": "c2",
                            "User": str(uid),
                            "Class": session_class,
                            "Type": "unspecified",
                            "State": state,
                            "Active": "no",
                        }
                        self.assertEqual(self.inspect(other), uid == 1000)

    def test_every_other_login_class_blocks_even_same_uid_remote_inactive_or_closing(
        self,
    ):
        for session_class in (
            "user",
            "user-early",
            "user-incomplete",
            "user-light",
            "user-early-light",
            "greeter",
            "lock-screen",
        ):
            for uid in (0, 1000, 1001):
                for state in ("online", "active", "closing"):
                    with self.subTest(
                        session_class=session_class, uid=uid, state=state
                    ):
                        self.assertFalse(
                            self.inspect(
                                {
                                    **TARGET,
                                    "Id": "c2",
                                    "User": str(uid),
                                    "Class": session_class,
                                    "Remote": "yes",
                                    "Active": "no",
                                    "State": state,
                                }
                            )
                        )
        for session_class in ("unknown", "Manager", "future-class"):
            with (
                self.subTest(session_class=session_class),
                self.assertRaisesRegex(
                    codec.InventoryFailure, "session-class-unsupported"
                ),
            ):
                self.inspect({**TARGET, "Id": "c2", "Class": session_class})

    def test_machine_rows_are_typed_bounded_unique_and_never_fall_back_to_a_table(self):
        with patch.object(
            fixture, "command", return_value=rows(("c1", 1000))
        ) as command:
            self.assertEqual(
                fixture.session_rows(codec, fixture.time.monotonic() + 20),
                [("c1", 1000)],
            )
        self.assertEqual(
            command.call_args.args[0],
            ["/usr/bin/loginctl", "list-sessions", "--json=short", "--no-pager"],
        )
        bad = [
            b"c1 1000 linura seat0 42 user tty1 no -\n",
            b"c1 1000 private-wire-marker\xe2\x80\xa6\n",
            b'{"session":"c1","uid":1000}',
            b'[{"session":"c1","uid":1000,"uid":1001}]',
            rows(*[(f"c{i}", 1000) for i in range(17)]),
            b"x" * 16385,
            b"\xff",
            b"[[[[",
        ]
        for value in (
            None,
            [],
            {"session": "c1"},
            {"session": "c1", "uid": True},
            {"session": "c1", "uid": -1},
            {"session": "c1", "uid": 2**32 - 1},
            {"session": "private-wire-marker\n", "uid": 1000},
            {"session": "../other", "uid": 1000},
        ):
            bad.append(json.dumps([value]).encode())
        bad.append(rows(("c1", 1000), ("c1", 1001)))
        for wire in bad:
            with (
                self.subTest(size=len(wire)),
                patch.object(fixture, "command", return_value=wire),
                self.assertRaises(codec.InventoryFailure) as caught,
            ):
                fixture.session_rows(codec, fixture.time.monotonic() + 20)
            self.assertNotIn("private-wire-marker", str(caught.exception))

    def test_fresh_properties_bind_enumerated_identity_and_generation(self):
        for key, value in (
            ("Id", "c2"),
            ("User", "1001"),
            ("User", "01000"),
            ("TimestampMonotonic", "0"),
            ("TimestampMonotonic", "09"),
            ("TimestampMonotonic", str(2**64)),
            ("Active", "1"),
            ("Remote", "maybe"),
            ("State", "unknown"),
            ("Class", "private-wire-marker\n"),
        ):
            with (
                self.subTest(key=key, value=value),
                patch.object(
                    fixture,
                    "command",
                    side_effect=[rows(("c1", 1000)), fields({**TARGET, key: value})],
                ),
                self.assertRaises(codec.InventoryFailure),
            ):
                fixture.only_target_session(LOCK, codec, fixture.time.monotonic() + 20)
        with (
            patch.object(fixture, "command", return_value=b"[]"),
            self.assertRaisesRegex(codec.InventoryFailure, "session-target-absent"),
        ):
            fixture.only_target_session(LOCK, codec, fixture.time.monotonic() + 20)
        for key in TARGET:
            incomplete = {k: v for k, v in TARGET.items() if k != key}
            with (
                self.subTest(missing=key),
                patch.object(fixture, "command", return_value=fields(incomplete)),
                self.assertRaises(codec.InventoryFailure),
            ):
                fixture.session_facts("c1", 1000, codec, fixture.time.monotonic() + 20)

    def test_inventory_deadline_includes_command_and_does_not_start_a_new_budget(self):
        with (
            patch.object(fixture.time, "monotonic", side_effect=[0, 21]),
            patch.object(
                fixture, "command", return_value=rows(("c1", 1000))
            ) as command,
            self.assertRaisesRegex(codec.InventoryFailure, "session-inventory-timeout"),
        ):
            fixture.session_rows(codec, 20)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.kwargs["budget"], 15)
        with (
            patch.object(fixture.time, "monotonic", return_value=21),
            patch.object(fixture, "command") as command,
            self.assertRaisesRegex(codec.InventoryFailure, "session-inventory-timeout"),
        ):
            fixture.only_target_session(LOCK, codec, 20)
        command.assert_not_called()

    def test_original_session_presence_uses_same_machine_inventory_and_exact_epoch(
        self,
    ):
        for value, present in (
            (TARGET, True),
            ({**TARGET, "User": "1001"}, False),
            ({**TARGET, "TimestampMonotonic": "10"}, False),
        ):
            with (
                self.subTest(value=value),
                patch.object(
                    fixture,
                    "command",
                    side_effect=[rows(("c1", int(value["User"]))), fields(value)],
                ),
            ):
                self.assertIs(
                    fixture.original_session_present(
                        LOCK, codec, fixture.time.monotonic() + 15
                    ),
                    present,
                )
        with patch.object(fixture, "command", return_value=rows(("c2", 1000))):
            self.assertFalse(
                fixture.original_session_present(
                    LOCK, codec, fixture.time.monotonic() + 15
                )
            )
        with patch.object(fixture, "command", return_value=b"[]"):
            self.assertFalse(
                fixture.original_session_present(
                    LOCK, codec, fixture.time.monotonic() + 15
                )
            )

    def test_inventory_failure_diagnostics_are_closed_and_never_authority(self):
        for category in codec.POWER_INVENTORY_FAILURES:
            with (
                self.subTest(category=category),
                patch.object(fixture, "write_record") as write,
            ):
                fixture.retain_failure(
                    "worker-failure.json",
                    "session-inventory",
                    codec.InventoryFailure(category),
                    codec,
                )
                record = write.call_args.args[1]
                self.assertEqual(
                    record,
                    {
                        "stage": "session-inventory",
                        "exit": None,
                        "categories": category,
                    },
                )
                guest = Mock()
                guest.run.return_value = json.dumps(
                    {
                        "claim": "failure-diagnostics-only",
                        "records": {
                            "worker-failure.json": record,
                            "prompt-failure.json": None,
                        },
                    }
                ).encode()
                with patch.object(
                    runner.sys, "stderr", new_callable=io.StringIO
                ) as output:
                    runner.failure_diagnostics(guest, "fixed diagnostics")
                    self.assertIn(category, output.getvalue())
        with self.assertRaises(RuntimeError) as caught:
            codec.InventoryFailure("private-wire-marker")
        self.assertNotIn("private-wire-marker", str(caught.exception))
