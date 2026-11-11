"""S21-5 power/idle must not introduce an unattended S17 authority bypass."""

from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contracts/v010-s21-power-idle.toml"


class S21PowerIdleBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.policy = tomllib.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_is_inert_and_default_off(self):
        self.assertEqual(self.policy["schema_version"], 1)
        self.assertEqual(self.policy["slice"], "S21-5")
        self.assertEqual(self.policy["status"], "proposed")
        self.assertEqual(self.policy["activation"], "none")
        self.assertEqual(self.policy["power_authority"], "s17-managed-control")
        self.assertEqual(self.policy["unsupported_behavior"], "fail-closed")
        for field in (
            "register_runtime_operations",
            "implements_idle_effects",
            "new_power_executor",
            "unattended_power_dispatch",
            "unattended_security_consent",
            "override_inhibitors",
            "root_permission_substitution",
            "skip_secure_lock_coverage",
            "indeterminate_replay",
        ):
            self.assertIs(self.policy[field], False, field)
        idle = self.policy["idle"]
        self.assertEqual(idle["defaults"], "disabled")
        self.assertEqual(
            idle["persistent_policy"], "control-owned-versioned-sqlite-cas"
        )
        self.assertEqual(idle["preference_default_seconds"], 300)
        self.assertIs(idle["preference_never_authorizes_effects"], True)
        self.assertIs(idle["preference_revision_cas"], True)
        self.assertIs(idle["observation_is_authorization"], False)
        for field in (
            "automatic_lock",
            "automatic_suspend",
            "automatic_logout",
            "automatic_reboot",
            "automatic_power_off",
            "automatic_display_off",
            "automatic_brightness",
        ):
            self.assertIs(idle[field], False, field)
        self.assertEqual(
            set(idle["source_change_invalidates"]),
            {"boot", "session", "seat", "owner", "generation"},
        )

    def test_compositor_idle_advisory_is_observe_only_and_inhibitor_sensitive(self):
        idle = self.policy["idle"]
        self.assertEqual(
            idle["observation"], "compositor-ext-idle-notify-presentation-advisory"
        )
        self.assertEqual(idle["threshold_seconds"], 300)
        self.assertIs(idle["respect_inhibitors"], True)
        self.assertIs(idle["presentation_only"], True)
        self.assertIs(idle["native_authoritative_observation"], False)
        shell = (ROOT / "apps/linura-shell/shell.qml").read_text(encoding="utf-8")
        for marker in (
            "import Quickshell.Wayland",
            "IdleMonitor {",
            "id: inputIdleMonitor",
            "enabled: shell.quickSettingsOpen && managedSessionController.idlePreferenceReady",
            "timeout: managedSessionController.idleAdvisorySeconds",
            "respectInhibitors: true",
            "idleAdvisory: !managedSessionController.idlePreferenceReady",
            "inputIdleMonitor.isIdle",
        ):
            self.assertIn(marker, shell)
        self.assertNotIn("onIsIdleChanged:", shell)
        self.assertNotIn("onActiveChanged:", shell)
        self.assertIn("No inactivity threshold is currently reported.", shell)
        self.assertIn("not verified by this indicator.", shell)
        quick = (
            ROOT / "apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml"
        ).read_text(encoding="utf-8")
        session = (
            ROOT / "apps/linura-shell/plugins/session/SessionControls.qml"
        ).read_text(encoding="utf-8")
        power = (ROOT / "apps/linura-shell/plugins/power/PowerControls.qml").read_text(
            encoding="utf-8"
        )
        self.assertIn("idleAdvisory: root.idleAdvisory", quick)
        self.assertIn("Compositor idle advisory unavailable", shell)
        self.assertIn("Refresh idle preference", power)
        self.assertIn("root.controller.refreshIdleAdvisoryPreference()", power)
        self.assertIn("!root.controller.hasPending", power)
        self.assertIn("idleAdvisory: root.idleAdvisory", session)
        self.assertIn('objectName: "idleInputAdvisory"', power)
        self.assertIn("text: root.idleAdvisory", power)
        self.assertIn("Accessible.role: Accessible.StaticText", power)
        self.assertNotIn("onIsIdleChanged:", power)

    def test_authenticated_native_logind_idle_is_advisory_only(self):
        native = (ROOT / "crates/linura-linux-observation/src/logind.rs").read_text(
            encoding="utf-8"
        )
        authority = (ROOT / "crates/linura-dbus/src/authority.rs").read_text(
            encoding="utf-8"
        )
        runtime = (ROOT / "apps/linura-authorityd/src/runtime.rs").read_text(
            encoding="utf-8"
        )
        qml = (
            ROOT / "apps/linura-shell/plugins/session/SessionControls.qml"
        ).read_text(encoding="utf-8")
        wire = (ROOT / "interfaces/dbus/org.linura.Authority1.xml").read_text(
            encoding="utf-8"
        )
        self.assertIn("LOGIND_IDLE_CAPABILITY", native)
        self.assertIn('snapshot_property(properties, "IdleHint")', native)
        self.assertIn('snapshot_property(properties, "IdleSinceHintMonotonic")', native)
        self.assertIn("if idle_before != idle_after", native)
        self.assertIn('method name="GetOwnNativeIdleStatus"', wire)
        self.assertIn('type="(ssbt)"', wire)
        self.assertIn("session_context(connection, &header)", authority)
        self.assertIn("own_native_idle_status(context)", authority)
        self.assertIn("SessionSafetyReview::review(", runtime)
        self.assertIn(".require_current(now)", runtime)
        self.assertIn("nativeIdleStatusText", qml)
        self.assertIn("GetOwnIdleAdvisoryPreference", wire)
        self.assertIn("SetOwnIdleAdvisoryPreference", wire)
        self.assertIn("compare_and_set(uid, seconds, expected_revision)", runtime)
        self.assertIn(
            "idle_preferences: Option<SqliteIdleAdvisoryPreferenceStore>", runtime
        )
        self.assertIn('.ok_or("idle advisory preferences unavailable")?', runtime)
        self.assertNotIn("onIsIdleChanged:", qml)

    def test_native_diagnostics_serialize_without_queueing_managed_actions(self):
        client = (ROOT / "apps/linura-shell/bridge/session_controller.cpp").read_text(
            encoding="utf-8"
        )
        header = (ROOT / "apps/linura-shell/bridge/session_controller.h").read_text(
            encoding="utf-8"
        )
        self.assertIn("idlePreferenceRefreshRequested_ = true;", header)
        self.assertEqual(
            client.count(
                "connect(timer, &QTimer::timeout, this, "
                "&SessionController::refreshNativeSleepStatus);"
            ),
            1,
        )
        self.assertNotIn(
            "connect(timer, &QTimer::timeout, this, "
            "&SessionController::refreshNativeIdleStatus);",
            client,
        )
        self.assertNotIn(
            "QTimer::singleShot(0, this, &SessionController::refreshNativeIdleStatus);",
            client,
        )
        self.assertNotIn(
            "QTimer::singleShot(0, this, "
            "&SessionController::refreshIdleAdvisoryPreference);",
            client,
        )
        self.assertIn("idlePreferenceRefreshRequested_ = false;", client)
        sleep = client.split("void SessionController::refreshNativeSleepStatus()", 1)[1]
        sleep = sleep.split(
            "void SessionController::refreshIdleAdvisoryPreference()", 1
        )[0]
        self.assertIn("refreshNativeIdleStatus();", sleep)
        self.assertIn(
            "nativeSleepQueryPending_ || nativeIdleQueryPending_ || "
            "idlePreferenceQueryPending_",
            sleep,
        )
        idle = client.split("void SessionController::refreshNativeIdleStatus()", 1)[1]
        idle = idle.split("QString SessionController::requestId()", 1)[0]
        self.assertIn("idlePreferenceQueryPending_", idle)
        self.assertIn("idlePreferenceBusy_", idle)
        self.assertIn("if (idlePreferenceRefreshRequested_)", idle)
        self.assertIn("refreshIdleAdvisoryPreference();", idle)
        self.assertNotIn("ConvergeSession", sleep + idle)

    def test_only_existing_s17_operations_are_reused(self):
        s21 = tomllib.loads(
            (ROOT / "contracts/v010-s21-design.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            s21["power_idle_design"], CONTRACT.relative_to(ROOT).as_posix()
        )
        self.assertEqual(s21["power_idle_qualification"], self.policy["qualification"])
        registered = tomllib.loads(
            (ROOT / "contracts/operation-semantics.toml").read_text(encoding="utf-8")
        )["registered_operations"]
        expected = set(s21["existing_authority"]["reuse"])
        self.assertEqual(set(self.policy["existing_power"]["registered"]), expected)
        self.assertTrue(
            expected <= {item["operation_id"] for item in registered.values()}
        )
        self.assertIs(s21["existing_authority"]["no_new_power_executor"], True)
        self.assertIs(s21["existing_authority"]["no_skip_inhibitors"], True)
        self.assertIs(s21["register_runtime_operations"], False)

    def test_shipped_client_is_non_authorizing_and_does_not_auto_dispatch(self):
        manifest = json.loads(
            (ROOT / "apps/linura-shell/plugins/power/manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["authority"], "none")
        self.assertEqual(
            set(manifest["registered_operations"]),
            set(self.policy["existing_power"]["registered"])
            - {"operation:session.lock.set-secure"},
        )
        qml = (ROOT / "apps/linura-shell/plugins/power/PowerControls.qml").read_text(
            encoding="utf-8"
        )
        self.assertIn("!root.controller.busy && !root.controller.hasPending", qml)
        self.assertIn("root.controller.request(modelData.action)", qml)
        self.assertIn("Automatic idle", qml)
        for forbidden in (
            "Process {",
            "Timer {",
            "Hyprland.dispatch(",
            "systemctl",
            "pkexec",
            "QDBusConnection",
            "ConvergeSessionTransition(",
        ):
            self.assertNotIn(forbidden, qml, forbidden)

    def test_durable_s17_client_and_observe_only_recovery_are_preserved(self):
        source = (ROOT / "apps/linura-shell/bridge/session_controller.cpp").read_text(
            encoding="utf-8"
        )
        for required in (
            'QStringLiteral("ConvergeSessionLock")',
            'QStringLiteral("GetOwnSessionTransition")',
            'QStringLiteral("ConvergeSessionTransition")',
            'QStringLiteral("RecoverSessionTransition")',
            "if (busy_ || hasPending()",
            "if (!retain(operation, TransitionRequest))",
            "if (busy_ || operation_.isEmpty() || invalidRecord_)",
        ):
            self.assertIn(required, source, required)

    def test_qualification_gates_cover_new_scope(self):
        paths = (
            self.policy["architecture"],
            self.policy["qualification"],
            "contracts/v010-s21-design.toml",
            "contracts/v010-s21-power-idle.toml",
            "tests/tooling/test_v010_s21_power_idle.py",
        )
        for item in paths:
            self.assertTrue((ROOT / item).is_file(), item)
        matrix = tomllib.loads(
            (ROOT / "contracts/qualification-gate-matrix.toml").read_text(
                encoding="utf-8"
            )
        )
        gate = next(
            entry for entry in matrix["gate"] if entry["id"] == "v010-workstation"
        )
        self.assertTrue(set(paths) <= set(gate["paths"]))
        text = (ROOT / self.policy["qualification"]).read_text(encoding="utf-8")
        self.assertIn("S17 remains the sole power authority", text)
        self.assertIn("not implemented or qualified", text)


if __name__ == "__main__":
    unittest.main()
