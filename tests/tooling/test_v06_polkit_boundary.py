from __future__ import annotations

import fnmatch
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
ACTION_ID = "org.linura.authority.manage-systemd-active-state"
ACTION_OWNER = "unix-user:linura-authority"
EXECUTOR_DESTINATION = "org.linura.Executor.Systemd1"
EXECUTOR_INTERFACE = "org.linura.Executor.Systemd1"
READ_ONLY_INTERFACES = {
    "org.freedesktop.DBus.Introspectable",
    "org.freedesktop.DBus.Peer",
    "org.freedesktop.DBus.Properties",
}


class V06PolkitBoundaryTests(unittest.TestCase):
    def test_expanded_guest_matrix_preserves_all_cases_and_legacy_projection(
        self,
    ) -> None:
        source = (ROOT / "tests/acceptance/v06/qualify-guest.sh").read_text(
            encoding="utf-8"
        )
        script = source.split(
            "stage deterministic-fault-matrix-inside-disposable-guest\n", 1
        )[1].split('\necho "real-authority1-success=qualified"', 1)[0]
        self.assertIn(
            "--test-threads=1 --nocapture 2>&1 | tee /tmp/v06-matrix.log",
            script,
        )
        self.assertIn(
            "--test-threads=1 --nocapture --skip s17_managed_ --skip s21_managed_ 2>&1 "
            "| tee /tmp/v06-legacy-matrix.log",
            script,
        )
        self.assertIn("59 passed; 0 failed; 0 ignored;", script)
        self.assertIn("11 passed; 0 failed; 0 ignored;", script)

        mock = """set -euo pipefail
matrix() {
    if [[ " $* " == *" --skip s17_managed_ "* ]]; then
        [[ " $* " == *" --skip s21_managed_ "* ]] || return 99
        printf 'test result: ok. %s passed; 0 failed; %s ignored;\\n' "$LINURA_TEST_BASELINE" "$LINURA_BASELINE_IGNORED"
        return "$LINURA_BASELINE_EXIT"
    fi
    printf 'test result: ok. %s passed; 0 failed; %s ignored;\\n' "$LINURA_TEST_FULL" "$LINURA_TEST_IGNORED"
    return "$LINURA_TEST_EXIT"
}
"""
        for full, baseline, ignored, baseline_ignored, code, baseline_code, valid in (
            (59, 11, 0, 0, 0, 0, True),
            (49, 11, 0, 0, 0, 0, False),
            (55, 11, 0, 0, 0, 0, False),
            (56, 11, 0, 0, 0, 0, False),
            (57, 11, 0, 0, 0, 0, False),
            (58, 11, 0, 0, 0, 0, False),
            (60, 11, 0, 0, 0, 0, False),
            (59, 10, 0, 0, 0, 0, False),
            (59, 12, 0, 0, 0, 0, False),
            (59, 11, 1, 0, 0, 0, False),
            (59, 11, 0, 1, 0, 0, False),
            (59, 11, 0, 0, 1, 0, False),
            (59, 11, 0, 0, 0, 1, False),
        ):
            with (
                self.subTest(
                    full=full,
                    baseline=baseline,
                    ignored=ignored,
                    baseline_ignored=baseline_ignored,
                    code=code,
                    baseline_code=baseline_code,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                scoped = script.replace(
                    "/usr/libexec/linura/v06-qualification-matrix", "matrix"
                ).replace("/tmp/v06-", directory + "/v06-")
                result = subprocess.run(
                    ["bash", "-c", mock + scoped],
                    env={
                        **os.environ,
                        "LINURA_TEST_FULL": str(full),
                        "LINURA_TEST_BASELINE": str(baseline),
                        "LINURA_TEST_IGNORED": str(ignored),
                        "LINURA_BASELINE_IGNORED": str(baseline_ignored),
                        "LINURA_TEST_EXIT": str(code),
                        "LINURA_BASELINE_EXIT": str(baseline_code),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                self.assertEqual(result.returncode == 0, valid, result.stderr)

        host = (ROOT / "tests/acceptance/v06/qualify-host.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"$ARTIFACT_DIR/$matrix_log"', host)
        self.assertIn("v06-matrix.log v06-legacy-matrix.log", host)
        self.assertIn(
            'if [[ "$guest_rc" -ne 0 || "$matrix_evidence_rc" -ne 0 ]]; then',
            host,
        )
        self.assertIn('exit "$matrix_evidence_rc"', host)

    def test_v06_guest_qualifies_live_native_session_packaging(self) -> None:
        host = (ROOT / "tests/acceptance/v06/qualify-host.sh").read_text(
            encoding="utf-8"
        )
        guest = (ROOT / "tests/acceptance/v06/qualify-native-session.sh").read_text(
            encoding="utf-8"
        )
        workflow = (ROOT / ".github/workflows/v06-managed-lifecycle-vm.yml").read_text(
            encoding="utf-8"
        )
        for required in (
            "linura-executor-session",
            "org.linura.Executor.Session1.conf",
            "org.linura.executor.session.policy",
            "50-linura-executor-session.rules",
            "50-linura-qualified-sleep.conf",
            "50-linura-protective-lock.conf",
            "linura-executor-session.service",
            "qualify-native-session.sh",
        ):
            self.assertIn(required, host)
        self.assertIn("v06-native-session.log", host)
        self.assertIn("-p linura-executor-session", workflow)
        self.assertIn('"session_executor": "v06-executor-session.bin"', workflow)
        for expected in (
            "stage active-native-session-executor",
            "systemctl is-active --quiet",
            "busctl --system introspect",
            "SetSecure sbsttssss",
            "native-session-root-denied",
            "native-session-polkit-ordinary-denied",
            'LAST_FAILURE_OUTPUT="$output"',
            '--process "$$"',
            "pkaction --action-id org.linura.executor.session",
            "access.*denied|permission.*denied",
            "native-session-ordinary-denied",
            "native-session-display-ordinary-denied",
            "native-session-display-root-denied",
            "native-session-display-polkit-ordinary-denied",
            "ApplyDisplayLayout ststtsssss",
            "systemd-suspend.service --value -p ExecStartPre",
            "non-supervised-sleep-helper",
            "native-session-live-boundary=qualified",
        ):
            self.assertIn(expected, guest)
        self.assertNotIn("systemctl suspend", guest)
        self.assertNotIn("systemctl reboot", guest)
        self.assertNotIn("systemctl poweroff", guest)

    def test_display_executor_keeps_default_deny_and_exact_service_only_rule(
        self,
    ) -> None:
        actions = ET.parse(
            ROOT / "packaging/polkit-1/actions/org.linura.executor.session.policy"
        ).getroot()
        action_id = "org.linura.executor.session.apply-display-layout"
        action = actions.find(f"action[@id='{action_id}']")
        self.assertIsNotNone(action)
        assert action is not None
        for name in ("allow_any", "allow_inactive", "allow_active"):
            self.assertEqual(action.findtext(f"defaults/{name}"), "no")
        rule = (
            ROOT / "packaging/polkit-1/rules.d/50-linura-executor-session.rules"
        ).read_text()
        self.assertIn(f'action.id === "{action_id}"', rule)
        self.assertIn('subject.user === "linura-authority"', rule)
        self.assertNotIn('subject.user === "root"', rule)
        policy = ET.parse(
            ROOT / "packaging/dbus-1/system.d/org.linura.Executor.Session1.conf"
        ).getroot()
        for scope in ("policy[@context='default']", "policy[@user='root']"):
            self.assertIsNotNone(
                policy.find(
                    f"{scope}/deny[@send_destination='org.linura.Executor.Session1'][@send_interface='org.linura.Executor.Session1']"
                )
            )

    def test_native_denial_capture_rejects_unrelated_failures(self) -> None:
        guest = (ROOT / "tests/acceptance/v06/qualify-native-session.sh").read_text(
            encoding="utf-8"
        )
        prelude = guest.split('\nservice="', 1)[0]
        probe = (
            "\nfail() { printf '%s\\n' \"$TEST_DIAGNOSTIC\" >&2; return 1; }\n"
            "expect_failure test-denial fail\n"
            "grep -Eiq 'access.*denied|permission.*denied' "
            '<<<"$LAST_FAILURE_OUTPUT"\n'
        )
        for diagnostic, accepted in (
            ("Call failed: Access denied", True),
            ("Call failed: Invalid arguments", False),
            ("Call failed: Service not found", False),
        ):
            with self.subTest(diagnostic=diagnostic):
                result = subprocess.run(
                    ["bash", "-c", prelude + probe],
                    env={**os.environ, "TEST_DIAGNOSTIC": diagnostic},
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_session_security_assets_route_to_v06_qualification(self) -> None:
        workflow = (ROOT / ".github/workflows/v06-managed-lifecycle-vm.yml").read_text(
            encoding="utf-8"
        )
        routes = workflow.split("  pull_request:\n    paths:\n", 1)[1].split(
            "\npermissions:", 1
        )[0]
        workflow_paths = re.findall(r'(?m)^      - "([^"]+)"$', routes)
        contract = tomllib.loads(
            (ROOT / "contracts/qualification-gate-matrix.toml").read_text(
                encoding="utf-8"
            )
        )
        gate = next(
            gate for gate in contract["gate"] if gate["id"] == "v06-managed-lifecycle"
        )
        assets = (
            "interfaces/dbus/org.linura.Executor.Session1.xml",
            "packaging/dbus-1/system.d/org.linura.Executor.Session1.conf",
            "packaging/polkit-1/actions/org.linura.executor.session.policy",
            "packaging/polkit-1/rules.d/50-linura-executor-session.rules",
            "packaging/systemd/system/linura-executor-session.service",
            "packaging/systemd/sleep.conf.d/50-linura-qualified-sleep.conf",
            "packaging/systemd/system/systemd-suspend.service.d/50-linura-protective-lock.conf",
            "packaging/systemd/sleep.conf.d/future-sleep-policy.conf",
            "packaging/systemd/system/systemd-suspend.service.d/future-protective-gate.conf",
        )
        session_contract = next(
            item
            for item in contract["contract"]
            if item["path"] == "interfaces/dbus/org.linura.Executor.Session1.xml"
        )
        self.assertIn("v06-managed-lifecycle", session_contract["gates"])
        for asset in assets:
            with self.subTest(asset=asset):
                self.assertTrue(
                    any(fnmatch.fnmatchcase(asset, path) for path in workflow_paths),
                    f"GitHub workflow does not route {asset}",
                )
                self.assertTrue(
                    any(fnmatch.fnmatchcase(asset, path) for path in gate["paths"]),
                    f"qualification matrix does not route {asset}",
                )

    def test_session_power_requires_separate_nonretained_admin_authentication(
        self,
    ) -> None:
        root = ET.fromstring(
            (ROOT / "packaging/polkit-1/actions/org.linura.authority.policy").read_text(
                encoding="utf-8"
            )
        )
        for operation in ("suspend", "logout", "reboot", "power-off"):
            action_id = f"org.linura.authority.{operation}-session"
            actions = [
                action
                for action in root.findall("action")
                if action.get("id") == action_id
            ]
            self.assertEqual(len(actions), 1)
            action = actions[0]
            self.assertEqual(
                action.findtext("annotate[@key='org.freedesktop.policykit.owner']"),
                ACTION_OWNER,
            )
            self.assertEqual(action.findtext("defaults/allow_any"), "no")
            self.assertEqual(action.findtext("defaults/allow_inactive"), "no")
            self.assertEqual(action.findtext("defaults/allow_active"), "auth_admin")
            self.assertNotIn("_keep", ET.tostring(action, encoding="unicode"))

    def test_session_owner_unlock_is_native_self_authentication_without_reusable_grants(
        self,
    ) -> None:
        root = ET.fromstring(
            (ROOT / "packaging/polkit-1/actions/org.linura.authority.policy").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(
            any(
                action.get("id") == "org.linura.authority.lock-session"
                for action in root.findall("action")
            )
        )
        for action_id, active in [("org.linura.authority.unlock-session", "auth_self")]:
            actions = [
                action
                for action in root.findall("action")
                if action.get("id") == action_id
            ]
            self.assertEqual(len(actions), 1)
            action = actions[0]
            self.assertEqual(
                action.findtext("annotate[@key='org.freedesktop.policykit.owner']"),
                ACTION_OWNER,
            )
            self.assertEqual(action.findtext("defaults/allow_any"), "no")
            self.assertEqual(action.findtext("defaults/allow_inactive"), "no")
            self.assertEqual(action.findtext("defaults/allow_active"), active)
            self.assertNotIn("_keep", ET.tostring(action, encoding="unicode"))

    def test_authority_action_owner_matches_unprivileged_service_identity(self) -> None:
        policy_path = ROOT / "packaging/polkit-1/actions/org.linura.authority.policy"
        root = ET.fromstring(policy_path.read_text(encoding="utf-8"))
        actions = [
            action for action in root.findall("action") if action.get("id") == ACTION_ID
        ]
        self.assertEqual(
            len(actions), 1, "Authority1 must own exactly one canonical Polkit action"
        )

        action = actions[0]
        owners = [
            annotation.text
            for annotation in action.findall("annotate")
            if annotation.get("key") == "org.freedesktop.policykit.owner"
        ]
        self.assertEqual(owners, [ACTION_OWNER])

        defaults = action.find("defaults")
        self.assertIsNotNone(defaults)
        assert defaults is not None
        self.assertEqual(defaults.findtext("allow_any"), "no")
        self.assertEqual(defaults.findtext("allow_inactive"), "auth_admin")
        self.assertEqual(defaults.findtext("allow_active"), "auth_admin")
        self.assertNotIn("auth_admin_keep", policy_path.read_text(encoding="utf-8"))

        service = (
            ROOT / "packaging/systemd/system/linura-authorityd.service"
        ).read_text(encoding="utf-8")
        self.assertIn("User=linura-authority\n", service)
        self.assertIn("Group=linura-authority\n", service)
        self.assertIn("NoNewPrivileges=yes\n", service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertIn("AmbientCapabilities=\n", service)

    def test_executor_dbus_transport_is_authority_only_for_mutation(self) -> None:
        config = ET.fromstring(
            (
                ROOT / "packaging/dbus-1/system.d/org.linura.Executor.Systemd1.conf"
            ).read_text(encoding="utf-8")
        )
        policies = config.findall("policy")

        default_policy = next(
            policy for policy in policies if policy.get("context") == "default"
        )
        mutation_deny = default_policy.find(
            f"deny[@send_destination='{EXECUTOR_DESTINATION}'][@send_interface='{EXECUTOR_INTERFACE}']"
        )
        self.assertIsNotNone(mutation_deny)

        metadata_allows = {
            element.get("send_interface")
            for element in default_policy.findall("allow")
            if element.get("send_destination") == EXECUTOR_DESTINATION
        }
        self.assertEqual(metadata_allows, READ_ONLY_INTERFACES)
        self.assertNotIn(EXECUTOR_INTERFACE, metadata_allows)

        authority_policy = next(
            policy for policy in policies if policy.get("user") == "linura-authority"
        )
        authority_allow = authority_policy.find(
            f"allow[@send_destination='{EXECUTOR_DESTINATION}']"
        )
        self.assertIsNotNone(authority_allow)
        assert authority_allow is not None
        self.assertIsNone(authority_allow.get("send_interface"))

        root_policy = next(
            policy for policy in policies if policy.get("user") == "root"
        )
        self.assertIsNotNone(root_policy.find(f"allow[@own='{EXECUTOR_DESTINATION}']"))
        self.assertIsNotNone(
            root_policy.find(
                f"deny[@send_destination='{EXECUTOR_DESTINATION}'][@send_interface='{EXECUTOR_INTERFACE}']"
            )
        )
        self.assertIsNone(
            root_policy.find(f"allow[@send_destination='{EXECUTOR_DESTINATION}']")
        )

        product_text = ET.tostring(config, encoding="unicode")
        self.assertNotIn("linura-v05-qualifier", product_text)
        self.assertNotIn("linura-v06-qualifier", product_text)

        qualification = ET.fromstring(
            (
                ROOT / "tests/acceptance/v05/49-linura-v05-qualification-dbus.conf"
            ).read_text(encoding="utf-8")
        )
        qualification_policy = next(
            policy
            for policy in qualification.findall("policy")
            if policy.get("user") == "linura-v05-qualifier"
        )
        self.assertIsNotNone(
            qualification_policy.find(
                f"allow[@send_destination='{EXECUTOR_DESTINATION}']"
            )
        )

    def test_qualification_approval_remains_test_only(self) -> None:
        qualification_rule = (
            ROOT / "tests/acceptance/v06/49-linura-v06-qualification.rules"
        ).read_text(encoding="utf-8")
        product_policy = (
            ROOT / "packaging/polkit-1/actions/org.linura.authority.policy"
        ).read_text(encoding="utf-8")

        self.assertIn('subject.user === "linura-v06-qualifier"', qualification_rule)
        self.assertIn("polkit.Result.YES", qualification_rule)
        self.assertNotIn("linura-v06-qualifier", product_policy)
        self.assertNotIn("polkit.Result.YES", product_policy)

    def test_expected_denials_do_not_disable_errexit_or_trip_err_trap(self) -> None:
        guest = (ROOT / "tests/acceptance/v06/qualify-guest.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("trap on_error ERR", guest)
        self.assertIn('if output="$("$@" 2>&1)"; then', guest)
        self.assertNotIn("set +e", guest)
        self.assertIn(
            "expect_failure unapproved-human call_authority_unapproved", guest
        )
        self.assertIn(
            "expect_failure direct-executor-ordinary call_executor_direct", guest
        )
        self.assertIn(
            "expect_failure direct-executor-root call_executor_direct_root", guest
        )


if __name__ == "__main__":
    unittest.main()
