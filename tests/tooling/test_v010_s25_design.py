"""Inert S25 personalization architecture: no runtime privileges or visual proof."""

from __future__ import annotations

import copy
import json
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "contracts/v010-s25-design.toml"
REGISTRY = ROOT / "contracts/operation-semantics.toml"
LOCAL = {
    "operation:personalization.appearance.configure",
    "operation:personalization.typography.configure",
    "operation:personalization.density.configure",
    "operation:personalization.motion.configure",
    "operation:personalization.icons.configure",
    "operation:personalization.wallpaper.configure",
    "operation:personalization.profile.reset",
}
EXTERNAL = {
    "operation:personalization.wallpaper.apply",
    "operation:personalization.wallpaper.clear",
    "operation:personalization.desktop.color-scheme.set",
}
EXPECTED = LOCAL | EXTERNAL


def read(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def validate_inert(doc: dict) -> None:
    if doc["status"] != "proposed" or doc["activation"] != "none":
        raise ValueError("proposed S25 design activated")
    for key in (
        "register_runtime_operations", "implements_effects", "runtime_support_promotion",
        "interactive_evidence_ready", "new_persistent_preferences_enabled",
        "imported_theme_is_executable", "qml_writes_provider_directly",
        "wallpaper_uri_grants_external_effect",
        "theme_can_override_security_status_semantics",
        "theme_can_modify_lock_authentication",
        "system_palette_equals_committed_revision",
        "preference_save_proves_native_renderer_applied",
        "unsafe_asset_fallback_allowed", "network_asset_auto_fetch",
        "unreviewed_font_or_icon_install", "indeterminate_effect_replay",
    ):
        if doc[key] is not False:
            raise ValueError(f"unreviewed effect or unsafe inference: {key}")
    for key in (
        "preserve_ui_sdk_and_tokens", "preserve_s17_security_owner_isolation",
        "preserve_s21_display_topology_authority", "require_owner_authenticated_cas",
        "require_separate_preview_commit_and_applied_state",
        "require_safe_content_hash_asset_provenance",
        "require_semantic_contrast_focus_and_reduced_motion",
        "require_actual_renderer_revision_observation",
        "require_recoverable_no_model_offline_configuration",
    ):
        if doc[key] is not True:
            raise ValueError(f"protection weakened: {key}")
    visual = doc["existing_visual_foundation"]
    if (
        visual["sdk_module"] != "org.linura.UI"
        or visual["sdk_version"] != "1.0"
        or visual["system_palette_source"] != "SystemPalette"
        or visual["sdk_is_presentation_only"] is not True
        or visual["existing_theme_is_durable_preference_store"] is not False
    ):
        raise ValueError("S10/S16 presentation module contract changed")
    for section in (
        "proposed_local_preference_state", "proposed_renderer_observation",
        "preview", "assets", "semantic_safety",
    ):
        for key, value in doc[section].items():
            if isinstance(value, bool) and value is not True:
                raise ValueError(f"unsafe {section}.{key}")
    if doc["proposed_local_preference_state"]["schema_version"] != 1:
        raise ValueError("unreviewed preferences schema")
    if doc["preview"]["class"] != "experience-ephemeral":
        raise ValueError("preview incorrectly mutates state")
    if any(doc["unsupported_extensions"].values()):
        raise ValueError("unqualified theme executor or source enabled")
    operations = doc["candidate_operation"]
    ids = [x["id"] for x in operations]
    if len(ids) != len(set(ids)) or set(ids) != EXPECTED:
        raise ValueError("missing/duplicated/unexpected personalization operation")
    for op in operations:
        if op["enabled"] is not False:
            raise ValueError("candidate operation enabled")
        if not op["resource"].startswith("exact-"):
            raise ValueError("operation authorized by weak resource alias")
        if not op["requested_keys"] or not op["requires"]:
            raise ValueError("operation lacks typed material and preconditions")
        if op["risk_floor"] != "user-state":
            raise ValueError("unexpected unreviewed S25 risk floor")
        if op["id"] in LOCAL:
            if (
                op["provider"] != "linura-local-personalization"
                or op["observation"] != "linura.personalization.preference.observe"
                or op["class"] != "linura-owned-state"
            ):
                raise ValueError("local settings promoted to external effect")
            if not {"revision-checked", "atomic-local-commit"} <= set(op["requires"]):
                raise ValueError("local CAS boundary removed")
        else:
            if (
                op["class"] != "managed-external-effect"
                or op["provider"] not in {"desktop-wallpaper", "desktop-appearance"}
                or op["observation"] != "desktop.personalization.applied.observe"
            ):
                raise ValueError("native appearance effect downgraded")
            if not {"narrow-adapter-no-shell", "independent-reobserve"} <= set(
                op["requires"]
            ):
                raise ValueError("native appearance lacks narrow verifier")
    wall = next(x for x in operations if x["id"].endswith(".wallpaper.apply"))
    if not {"s21-output-topology-binding", "safe-content-hash-asset"} <= set(
        wall["requires"]
    ):
        raise ValueError("wallpaper lacks source/output identity")
    appearance = next(
        x for x in operations if x["id"].endswith(".appearance.configure")
    )
    if "typed-contrast-safe-palette" not in appearance["requires"]:
        raise ValueError("semantic contrast not protected")
    motion = next(x for x in operations if x["id"].endswith(".motion.configure"))
    if "accessibility-user-override" not in motion["requires"]:
        raise ValueError("reduced motion override lost")
    for key in (
        "mock_token_comparison_is_visual_proof",
        "snapshot_png_is_full_accessibility_proof",
        "vm_render_is_physical_display_proof",
    ):
        if doc["qualification"][key] is not False:
            raise ValueError("visual evidence falsely promoted")
    for key, value in doc["qualification"].items():
        if key.startswith("require_") and value is not True:
            raise ValueError(f"missing S25 acceptance invariant: {key}")


class S25ProposedArchitectureTests(unittest.TestCase):
    def test_scope_and_inactive_contract(self):
        doc = read(DESIGN)
        self.assertEqual(
            (doc["schema_version"], doc["slice"], doc["milestone"]),
            (1, "S25", "v0.10.0"),
        )
        self.assertEqual(
            (doc["dependency"], doc["profile"]),
            ("S16", "arch-hyprland-v1"),
        )
        self.assertEqual(doc["unsupported_behavior"], "fail-closed")
        validate_inert(doc)

    def test_s10_s16_sdk_and_s17_fonts_are_unchanged_foundations(self):
        doc = read(DESIGN)
        ui = doc["existing_visual_foundation"]
        tokens = json.loads((ROOT / ui["tokens"]).read_text(encoding="utf-8"))
        self.assertEqual(tokens["schema_version"], 1)
        for key in (
            "background", "surface", "foreground", "muted", "accent",
            "danger", "warning", "success", "focus",
        ):
            self.assertIn(key, tokens["semantic"])
        theme = (ROOT / ui["theme"]).read_text(encoding="utf-8")
        cmake = (ROOT / ui["component_manifest"]).read_text(encoding="utf-8")
        self.assertIn("SystemPalette", theme)
        self.assertIn("LinuraTheme.qml", cmake)
        self.assertIn("URI org.linura.UI", cmake)
        self.assertIn("VERSION 1.0", cmake)
        secure = (
            ROOT / "apps/linura-shell/security-owner/fonts.conf"
        ).read_text(encoding="utf-8")
        self.assertIn("/usr/share/fonts", secure)
        self.assertIn("DejaVu Sans", secure)

    def test_unregistered_operations_preserve_control_authority(self):
        reg = read(REGISTRY)
        self.assertEqual(
            reg["classification_owner"],
            "trusted-operation-registry-and-linura-control",
        )
        self.assertFalse(reg["client_classification_authority"])
        self.assertFalse(reg["provider_classification_authority"])
        self.assertEqual(reg["unknown_effect_behavior"], "fail-closed")
        live = {x["operation_id"] for x in reg["registered_operations"].values()}
        self.assertFalse(EXPECTED & live)
        self.assertFalse(read(DESIGN)["register_runtime_operations"])

    def test_mutation_probes_reject_privilege_visual_and_cas_bypass(self):
        doc = read(DESIGN)
        for key, value in (
            ("activation", "active"),
            ("register_runtime_operations", True),
            ("new_persistent_preferences_enabled", True),
            ("theme_can_modify_lock_authentication", True),
            ("preference_save_proves_native_renderer_applied", True),
            ("require_owner_authenticated_cas", False),
            ("require_semantic_contrast_focus_and_reduced_motion", False),
        ):
            with self.subTest(key=key):
                bad = copy.deepcopy(doc)
                bad[key] = value
                with self.assertRaises(ValueError):
                    validate_inert(bad)
        for operation_id, field, value in (
            ("operation:personalization.wallpaper.apply", "enabled", True),
            ("operation:personalization.wallpaper.clear", "class",
             "transient-external-effect"),
            ("operation:personalization.desktop.color-scheme.set", "resource",
             "system-theme"),
            ("operation:personalization.appearance.configure", "provider",
             "desktop-appearance"),
            ("operation:personalization.wallpaper.configure", "class",
             "managed-external-effect"),
        ):
            with self.subTest(operation=operation_id, field=field):
                bad = copy.deepcopy(doc)
                next(
                    x for x in bad["candidate_operation"] if x["id"] == operation_id
                )[field] = value
                with self.assertRaises(ValueError):
                    validate_inert(bad)

    def test_adr_docs_threat_and_qualification_gate_routes(self):
        doc = read(DESIGN)
        for key in (
            "architecture", "source_audit", "qualification_document",
            "security_qualification",
        ):
            self.assertTrue((ROOT / doc[key]).is_file(), key)
        self.assertIn(
            "0053-s25-personalization-authority-and-safe-rendering.md",
            (ROOT / "docs/adr/README.md").read_text(),
        )
        self.assertIn(
            "v0.10.0-s25.md",
            (ROOT / "docs/milestones/v0.10.0.md").read_text(),
        )
        self.assertIn(
            "v0.10.0-s25-security.md",
            (ROOT / "docs/qualification/v0.10.0.md").read_text(),
        )
        self.assertIn("ADR 0053", (ROOT / "docs/threat-model.md").read_text())
        matrix = read(ROOT / "contracts/qualification-gate-matrix.toml")
        gate = next(x for x in matrix["gate"] if x["id"] == "v010-workstation")
        expected = {
            "contracts/v010-s25-design.toml", doc["architecture"],
            doc["qualification_document"], doc["security_qualification"],
            "tests/tooling/test_v010_s25_design.py",
        }
        self.assertTrue(expected <= set(gate["paths"]))
        routes = {x["path"]: x["gates"] for x in matrix["contract"]}
        self.assertIn("v010-workstation", routes["contracts/v010-s25-design.toml"])
        workflow = (ROOT / ".github/workflows/v010-qualification.yml").read_text()
        for path in expected:
            self.assertIn(f'"{path}"', workflow)

    def test_s25_product_and_physical_qualification_unpromoted(self):
        doc = read(DESIGN)
        ledger = {
            x["id"]: x
            for x in read(ROOT / "contracts/v010-workstation-slices.toml")["slice"]
        }
        self.assertEqual(ledger["S25"]["status"], "planned")
        self.assertEqual(ledger["S25"]["depends_on"], ["S16"])
        self.assertEqual(ledger["S25"]["evidence_prs"], [])
        self.assertEqual(ledger["S27"]["depends_on"].count("S25"), 1)
        self.assertEqual(ledger["S16"]["status"], "complete")
        self.assertFalse(doc["qualification"]["vm_render_is_physical_display_proof"])
        self.assertTrue(doc["qualification"]["require_s17_lock_chrome_and_font_isolation"])


if __name__ == "__main__":
    unittest.main()
