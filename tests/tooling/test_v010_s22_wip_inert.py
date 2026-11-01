"""Development-only regression guards for S22 security non-activation.

These checks inspect source and contracts. They are never native evidence.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "contracts/v010-s22-design.toml"
CAPTURE = ROOT / "crates/linura-linux-observation/src/desktop_capture"
PLATFORM = ROOT / "crates/linura-linux-observation/src/platform_discovery.rs"


class S22WipInertTests(unittest.TestCase):
    def test_operation_registration_and_sensitive_features_remain_off(self) -> None:
        contract = tomllib.loads(DESIGN.read_text(encoding="utf-8"))
        for key in (
            "register_runtime_operations",
            "implements_effects",
            "runtime_support_promotion",
            "clipboard_history_enabled_by_default",
            "capture_without_compositor_protection",
            "recording_without_native_stop",
            "allow_sensitive_bytes_in_plan_audit_model",
            "allow_auto_upload_or_share",
        ):
            with self.subTest(key=key):
                self.assertFalse(contract[key])
        self.assertTrue(all(not operation["enabled"] for operation in contract["candidate_operation"]))

    def test_capture_and_clipboard_require_real_native_exclusion(self) -> None:
        capture = (CAPTURE / "mod.rs").read_text(encoding="utf-8")
        clip = (CAPTURE / "clipboard.rs").read_text(encoding="utf-8")
        self.assertIn("CompositorExclusionNotProved", capture)
        self.assertIn("CapturePreflight::Unavailable", capture)
        self.assertIn("ClipboardReadPreflight::Unavailable", clip)
        self.assertIn("UnknownOrProtectedSource", clip)

    def test_no_public_fake_recording_supervision_grant(self) -> None:
        recorder = (CAPTURE / "recording.rs").read_text(encoding="utf-8")
        self.assertIn("pub struct NativeStopSupervisorWitness", recorder)
        self.assertIn("_private: ()", recorder)
        self.assertIn("Option<&NativeStopSupervisorWitness>", recorder)
        self.assertIn("NoIndependentNativeStopProof", recorder)

    def test_portal_probe_is_read_only_and_authenticates_native_peers(self) -> None:
        source = PLATFORM.read_text(encoding="utf-8")
        start = source.index("fn connect_capture_system_bus()")
        end = source.index("pub fn observe_network_provider()", start)
        native = source[start:end]
        self.assertIn('Path::new("/run/dbus/system_bus_socket")', native)
        self.assertIn("socket_peercred(&stream)", native)
        self.assertIn("credentials.uid.as_raw() != 0", native)
        self.assertIn('call("GetNameOwner"', native)
        self.assertIn('call("GetConnectionUnixUser"', native)
        self.assertIn('ObservedValue::Bool(false)', native)
        for forbidden in ('call("Screenshot"', 'call("Start"', 'Command::new('):
            self.assertNotIn(forbidden, native)


if __name__ == "__main__":
    unittest.main()
