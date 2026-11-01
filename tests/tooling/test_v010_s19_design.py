"""Proposed v0.10 S19 BlueZ design is non-authorizing and exact-gate routed."""

from __future__ import annotations

import copy
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "contracts/v010-s19-design.toml"
EXPECTED = {
    "operation:bluetooth.discovery.start",
    "operation:bluetooth.discovery.stop",
    "operation:bluetooth.adapter.set-powered",
    "operation:bluetooth.adapter.set-pairable",
    "operation:bluetooth.adapter.set-discoverable",
    "operation:bluetooth.device.pair",
    "operation:bluetooth.device.cancel-pairing",
    "operation:bluetooth.device.connect",
    "operation:bluetooth.device.disconnect",
    "operation:bluetooth.device.set-trusted",
    "operation:bluetooth.device.set-blocked",
    "operation:bluetooth.device.remove",
}
SECURITY_SENSITIVE = EXPECTED - {
    "operation:bluetooth.discovery.start",
    "operation:bluetooth.discovery.stop",
    "operation:bluetooth.device.cancel-pairing",
}


def read(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def verify_design(doc: dict) -> None:
    if doc["status"] != "proposed" or doc["activation"] != "none":
        raise ValueError("S19 design activated")
    for key in (
        "register_runtime_operations", "implements_effects", "runtime_support_promotion",
        "interactive_evidence_ready", "indeterminate_replay",
        "secrets_in_plan_audit_or_model", "address_or_alias_grants_authority",
        "unmatched_incoming_agent_requests_allowed", "replay_indeterminate_pairing_or_removal",
    ):
        if doc[key] is not False:
            raise ValueError("S19 design cannot grant authority: " + key)
    for key in (
        "no_generic_dbus_forwarding", "no_shell_or_bluetoothctl_executor",
        "no_ambient_default_agent_takeover", "protected_pairing_input_required",
    ):
        if doc[key] is not True:
            raise ValueError("S19 boundary weakened: " + key)
    if doc["existing_platform_discovery"]["grants_mutation_authority"] is not False:
        raise ValueError("platform BlueZ presence grants no mutations")
    if doc["existing_platform_discovery"]["reuse_required"] is not True:
        raise ValueError("platform provider probe must be reused")
    required_observation = (
        "require_unique_bluez_owner", "require_bounded_object_manager",
        "require_parent_adapter_relationship", "require_device_address_type",
        "distinguish_paired_trusted_blocked_connected",
        "distinguish_connected_from_services_resolved", "reject_duplicate_native_identity",
        "reject_mixed_owner_epochs", "reject_stale_adapter_or_device_generation",
        "control_owns_aggregation",
    )
    if any(doc["proposed_observation"][k] is not True for k in required_observation):
        raise ValueError("native observation weakens identity/freshness")
    agent = doc["pairing_agent"]
    if agent["interface"] != "org.bluez.Agent1":
        raise ValueError("invalid pairing agent interface")
    if agent["manager_interface"] != "org.bluez.AgentManager1":
        raise ValueError("invalid pairing manager interface")
    if any(v is not True for key, v in agent.items() if key not in {
        "interface", "manager_interface",
    }):
        raise ValueError("unprotected Agent1 callback/agent registration")
    if any(v is not True for v in doc["discovery"].values()):
        raise ValueError("discovery ownership or scan boundary weakened")
    if any(doc["unsupported_extensions"].values()):
        raise ValueError("unsupported Bluetooth extension activated")
    candidates = doc["candidate_operation"]
    ids = [x["id"] for x in candidates]
    if len(ids) != len(set(ids)) or set(ids) != EXPECTED:
        raise ValueError("unknown, duplicate or missing candidate operation")
    for operation in candidates:
        if operation["enabled"] is not False or operation["class"] != "managed-external-effect":
            raise ValueError("candidate effect enabled or downgraded")
        if operation["provider"] != "bluez" or not operation["observation"].startswith("bluez."):
            raise ValueError("candidate source not bound to BlueZ")
        if not operation["resource"].startswith("exact-provider-"):
            raise ValueError("candidate target is an untrusted alias")
        if not operation["requested_keys"] or "independent-reobserve" not in operation["requires"]:
            raise ValueError("candidate lacks exact bounded keys/verifier")
        if operation["id"] in SECURITY_SENSITIVE and operation["risk_floor"] not in {
            "security-sensitive", "destructive",
        }:
            raise ValueError("security-sensitive candidate risk downgraded")
    removal = next(x for x in candidates if x["id"].endswith(".device.remove"))
    if removal["risk_floor"] != "destructive" or "bond-key-loss-review" not in removal["requires"]:
        raise ValueError("bond removal is destructive")
    pairing = next(x for x in candidates if x["id"].endswith(".device.pair"))
    if not {
        "purpose-bound-agent", "protected-confirmation", "no-replay",
    } <= set(pairing["requires"]):
        raise ValueError("pairing-agent protection incomplete")
    stop = next(x for x in candidates if x["id"].endswith(".discovery.stop"))
    if "no-other-client-stop" not in stop["requires"]:
        raise ValueError("discovery stop impacts another client")
    if doc["qualification"]["virtual_hci_is_physical"] is not False:
        raise ValueError("VM radio is not physical")
    if doc["qualification"]["video_is_correctness_oracle"] is not False:
        raise ValueError("video is not Bluetooth verification")


class S19ArchitectureDesignTests(unittest.TestCase):
    def test_inert_bluez_contract_and_correct_dependency(self):
        doc = read(DESIGN)
        self.assertEqual(
            (doc["schema_version"], doc["slice"], doc["milestone"]),
            (1, "S19", "v0.10.0"),
        )
        self.assertEqual((doc["profile"], doc["dependency"]), ("arch-hyprland-v1", "S16"))
        self.assertEqual(doc["provider_well_known_name"], "org.bluez")
        self.assertEqual(doc["provider_bus"], "system")
        self.assertEqual(doc["provider_object_manager"], "org.freedesktop.DBus.ObjectManager")
        self.assertEqual(doc["unsupported_behavior"], "fail-closed")
        verify_design(doc)

    def test_blueZ_platform_discovery_is_not_a_mutating_adapter(self):
        present = read(DESIGN)["existing_platform_discovery"]
        self.assertEqual(present["capability"], "platform.provider.bluetooth.observe")
        self.assertEqual(present["resource"], "platform:provider:bluetooth")
        self.assertEqual(present["interface"], "org.freedesktop.DBus.Peer")
        self.assertEqual(present["path"], "/")
        self.assertFalse(present["grants_mutation_authority"])

    def test_registry_remains_owned_by_trusted_control(self):
        runtime = read(ROOT / "contracts/operation-semantics.toml")
        self.assertEqual(
            runtime["classification_owner"],
            "trusted-operation-registry-and-linura-control",
        )
        self.assertFalse(runtime["client_classification_authority"])
        self.assertFalse(runtime["provider_classification_authority"])
        self.assertEqual(runtime["unknown_effect_behavior"], "fail-closed")
        registered = {x["operation_id"] for x in runtime["registered_operations"].values()}
        self.assertFalse(
            EXPECTED & registered,
            "S19 candidates cannot be registered by this design",
        )

    def test_adversarial_design_mutation_probes_fail_closed(self):
        valid = read(DESIGN)
        for key, value in (
            ("activation", "active"),
            ("register_runtime_operations", True),
            ("interactive_evidence_ready", True),
            ("protected_pairing_input_required", False),
            ("no_ambient_default_agent_takeover", False),
            ("address_or_alias_grants_authority", True),
            ("unmatched_incoming_agent_requests_allowed", True),
        ):
            with self.subTest(flag=key):
                bad = copy.deepcopy(valid)
                bad[key] = value
                with self.assertRaises(ValueError):
                    verify_design(bad)
        for operation_id, field, value in (
            ("operation:bluetooth.device.pair", "class", "transient-external-effect"),
            ("operation:bluetooth.device.remove", "risk_floor", "user-state"),
            ("operation:bluetooth.device.set-trusted", "risk_floor", "user-state"),
            ("operation:bluetooth.device.connect", "resource", "alias"),
            ("operation:bluetooth.discovery.stop", "enabled", True),
        ):
            with self.subTest(operation=operation_id, field=field):
                bad = copy.deepcopy(valid)
                candidate = next(x for x in bad["candidate_operation"] if x["id"] == operation_id)
                candidate[field] = value
                with self.assertRaises(ValueError):
                    verify_design(bad)

    def test_documents_and_qualification_paths_are_routed(self):
        doc = read(DESIGN)
        for key in (
            "architecture", "qualification_document", "security_qualification", "source_audit",
        ):
            self.assertTrue((ROOT / doc[key]).is_file(), key)
        self.assertIn(
            "0049-s19-bluez-bluetooth-authority.md",
            (ROOT / "docs/adr/README.md").read_text(),
        )
        self.assertIn("v0.10.0-s19.md", (ROOT / "docs/milestones/v0.10.0.md").read_text())
        self.assertIn(
            "v0.10.0-s19-security.md",
            (ROOT / "docs/qualification/v0.10.0.md").read_text(),
        )
        self.assertIn("ADR 0049", (ROOT / "docs/threat-model.md").read_text())
        matrix = read(ROOT / "contracts/qualification-gate-matrix.toml")
        gate = next(x for x in matrix["gate"] if x["id"] == "v010-workstation")
        expected = {
            "contracts/v010-s19-design.toml", doc["architecture"], doc["qualification_document"],
            doc["security_qualification"], "tests/tooling/test_v010_s19_design.py",
        }
        self.assertTrue(expected <= set(gate["paths"]))
        routes = {item["path"]: item["gates"] for item in matrix["contract"]}
        self.assertIn("v010-workstation", routes["contracts/v010-s19-design.toml"])
        workflow = (ROOT / ".github/workflows/v010-qualification.yml").read_text()
        for path in expected:
            self.assertIn(f'"{path}"', workflow)

    def test_ledger_cannot_be_prematurely_promoted(self):
        doc = read(DESIGN)
        ledger = {
            item["id"]: item
            for item in read(ROOT / "contracts/v010-workstation-slices.toml")["slice"]
        }
        self.assertEqual(ledger["S19"]["depends_on"], ["S16"])
        self.assertEqual(ledger["S19"]["status"], "planned")
        self.assertEqual(ledger["S19"]["evidence_prs"], [])
        self.assertEqual(ledger["S16"]["status"], "complete")
        self.assertFalse(doc["qualification"]["virtual_hci_is_physical"])
        self.assertFalse(doc["qualification"]["video_is_correctness_oracle"])
        self.assertTrue(doc["qualification"]["require_indeterminate_no_replay"])
        self.assertTrue(doc["qualification"]["require_physical_radio_for_hardware_claim"])


if __name__ == "__main__":
    unittest.main()
