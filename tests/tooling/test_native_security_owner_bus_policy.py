from __future__ import annotations

from pathlib import Path
import tomllib
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
POLICY = "packaging/dbus-1/system.d/org.linura.SecurityOwner1.conf"
OBJECT_PATH = "/org/linura/SecurityOwner1"
INTERFACE = "org.linura.SecurityOwner1"
DISCOVERY = "org.freedesktop.DBus.Introspectable"
DROPIN = "packaging/systemd/system/user@.service.d/50-linura-security-owner.conf"


class NativeSecurityOwnerBusPolicyTests(unittest.TestCase):
    def test_unique_name_endpoint_has_exact_sender_scoped_bus_admission(self) -> None:
        policy = ET.parse(ROOT / POLICY).getroot()
        self.assertEqual(policy.tag, "busconfig")
        self.assertEqual(len(policy), 3)
        self.assertFalse(
            any(
                "own" in rule.attrib or "own_prefix" in rule.attrib
                for rule in policy.iter()
            )
        )
        self.assertFalse(
            any("send_destination" in rule.attrib for rule in policy.iter())
        )
        entries = {}
        for scope in policy:
            self.assertEqual(scope.tag, "policy")
            key = tuple(sorted(scope.attrib.items()))
            self.assertNotIn(key, entries)
            entries[key] = [(rule.tag, rule.attrib) for rule in scope]
        self.assertEqual(
            entries,
            {
                (("context", "default"),): [
                    ("deny", {"send_type": "method_call", "send_path": OBJECT_PATH}),
                ],
                (("user", "linura-authority"),): [
                    (
                        "allow",
                        {
                            "send_type": "method_call",
                            "send_path": OBJECT_PATH,
                            "send_interface": INTERFACE,
                        },
                    ),
                    (
                        "allow",
                        {
                            "send_type": "method_call",
                            "send_path": OBJECT_PATH,
                            "send_interface": DISCOVERY,
                            "send_member": "Introspect",
                        },
                    ),
                ],
                (("user", "root"),): [
                    (
                        "allow",
                        {
                            "send_type": "method_call",
                            "send_path": OBJECT_PATH,
                            "send_interface": INTERFACE,
                        },
                    ),
                    (
                        "allow",
                        {
                            "send_type": "method_call",
                            "send_path": OBJECT_PATH,
                            "send_interface": DISCOVERY,
                            "send_member": "Introspect",
                        },
                    ),
                ],
            },
        )
        interface = ET.parse(ROOT / "interfaces/dbus/org.linura.SecurityOwner1.xml")
        self.assertIsNotNone(interface.find(f".//interface[@name='{INTERFACE}']"))
        native = (ROOT / "crates/linura-linux-session/src/owner.rs").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            native,
            r'ENDPOINT,\s*"org\.freedesktop\.DBus\.Introspectable",\s*"Introspect"',
        )

    def test_policy_is_packaged_classified_and_covered_by_required_gates(self) -> None:
        cmake = (ROOT / "apps/linura-shell/security-owner/CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '"${LINURA_SECURITY_OWNER_PACKAGING_DIR}/dbus-1/system.d/'
            'org.linura.SecurityOwner1.conf"',
            cmake,
        )
        self.assertIn("DESTINATION share/dbus-1/system.d", cmake)
        self.assertIn("user@.service.d/50-linura-security-owner.conf", cmake)

        formats = (ROOT / "tools/check_tracked_formats.py").read_text(encoding="utf-8")
        self.assertIn(f'"{POLICY}": "xml"', formats)

        matrix = tomllib.loads(
            (ROOT / "contracts/qualification-gate-matrix.toml").read_text(
                encoding="utf-8"
            )
        )
        # D-Bus policy is a deployment asset, not a versioned interface in the
        # exhaustive stability/contract registry. Its exact qualified routing
        # is required in the executable gate inventory below.
        self.assertFalse(any(entry["path"] == POLICY for entry in matrix["contract"]))

        for gate_id in ("v06-managed-lifecycle", "v010-workstation"):
            matched_gates = [gate for gate in matrix["gate"] if gate["id"] == gate_id]
            self.assertEqual(len(matched_gates), 1)
            self.assertIn(POLICY, matched_gates[0]["paths"])
            self.assertIn(DROPIN, matched_gates[0]["paths"])

        for workflow in (
            ".github/workflows/v06-managed-lifecycle-vm.yml",
            ".github/workflows/v010-qualification.yml",
        ):
            text = (ROOT / workflow).read_text(encoding="utf-8")
            self.assertIn(f'"{POLICY}"', text)
            self.assertIn(f'"{DROPIN}"', text)

        canonical = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "python3 -m unittest discover -s tests/tooling "
            "-p 'test_native_security_owner_bus_policy.py'",
            canonical,
        )


if __name__ == "__main__":
    unittest.main()
