"""S23 WIP read-only implementations: guard authority and coupling against regressions.

These checks validate source and contract consistency, not native Arch/Hyprland
qualification or runtime safety. The native unit tests and release gates remain
independently required.
"""
from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "contracts/v010-s23-design.toml"
REGISTRY = ROOT / "contracts/operation-semantics.toml"
DAEMON = ROOT / "apps/linurad/src/main.rs"
OBS_LIB = ROOT / "crates/linura-linux-observation/src/lib.rs"
PLANNER_LIB = ROOT / "crates/linura-planner/src/lib.rs"
ALPM = ROOT / "crates/linura-linux-observation/src/alpm_installed.rs"
XDG = ROOT / "crates/linura-linux-observation/src/xdg_applications.rs"
MIME = ROOT / "crates/linura-linux-observation/src/xdg_mimeapps.rs"
PLANNER = ROOT / "crates/linura-planner/src/package_impact.rs"

PROVIDERS = (
    ("AlpmInstalledObserver", "alpm_installed.rs", "alpm.package.installed.observe"),
    ("XdgApplicationObserver", "xdg_applications.rs", "desktop.application.observe"),
    ("XdgMimeAppsObserver", "xdg_mimeapps.rs", "xdg.mime.association.observe"),
)


class S23WipImplementationGuards(unittest.TestCase):
    def test_read_only_observers_use_control_registration(self) -> None:
        daemon = DAEMON.read_text(encoding="utf-8")
        lib = OBS_LIB.read_text(encoding="utf-8")
        for class_name, path, capability in PROVIDERS:
            with self.subTest(class_name=class_name):
                source = (ALPM.parent / path).read_text(encoding="utf-8")
                self.assertIn("impl Observer for " + class_name, source)
                self.assertIn('"' + capability + '"', source)
                self.assertIn("pub use ", lib)
                self.assertIn(f"Box::new({class_name}::", daemon)
                self.assertIn("ObservationAuthority::Filesystem", source)
                self.assertIn("next_sequence(&self.sequence)", source)
                self.assertIn("effect_authorized", source)
                # Both ownership and execution authority remain outside providers.
                actual = source.split("\n#[cfg(test)]\nmod tests", maxsplit=1)[0]
                self.assertNotRegex(actual, r"Command::new|std::process::Command|systemd_run|pacman\s+-")
                self.assertNotRegex(actual, r"(?<![A-Za-z])write_all\s*\(|\bremove_file\s*\(|\bset_permissions\s*\(")

    def test_mime_never_claims_candidate_is_effective(self) -> None:
        source = MIME.read_text(encoding="utf-8")
        self.assertIn('"effective_handler_verified"', source)
        self.assertIn('"association_verified"', source)
        self.assertIn("ObservedValue::Bool(false)", source)
        self.assertIn("fn parse_mime_file(", source)
        self.assertIn("fn read_mime_file(", source)
        self.assertIn("OFlags::NOFOLLOW", source)
        self.assertIn("MAX_FILE_BYTES", source)

    def test_alpm_local_db_never_claims_signed_frozen_repository(self) -> None:
        source = ALPM.read_text(encoding="utf-8")
        self.assertIn('"/var/lib/pacman/local"', source)
        self.assertIn('"/var/lib/pacman/db.lck"', source)
        self.assertIn('one("SIZE")', source)
        self.assertIn('fields.get("REASON")', source)
        self.assertNotIn('one("ISIZE")', source)
        self.assertIn('"signed_repository_verified"', source)
        self.assertIn('"complete_transaction_preflight"', source)
        self.assertIn("OFlags::NOFOLLOW", source)

    def test_package_impact_remains_pure_non_executable(self) -> None:
        source = PLANNER.read_text(encoding="utf-8")
        self.assertIn("pub fn review_package_impact(", source)
        self.assertIn("execution_authorized: false", source)
        self.assertIn("PackageBlocker::UnqualifiedExecutor", source)
        self.assertIn("PackageBlocker::PartialUpgradeRisk", source)
        self.assertIn("PackageBlocker::ProtectedPackage", source)
        self.assertIn("PackageBlocker::ReverseDependency", source)
        self.assertNotRegex(source, r"\bunsafe\s*\{|\bCommand::new|\bexecute_package\s*\(")
        self.assertIn("pub mod package_impact;", PLANNER_LIB.read_text())

    def test_planned_effects_stay_disabled(self) -> None:
        design = tomllib.loads(DESIGN.read_text(encoding="utf-8"))
        self.assertEqual(design["activation"], "none")
        self.assertFalse(design["register_runtime_operations"])
        self.assertFalse(design["implements_effects"])
        self.assertFalse(design["runtime_support_promotion"])
        self.assertFalse(design["partial_upgrades_allowed"])
        self.assertTrue(design["pr_decomposition"]["unqualified_package_operations_remain_disabled"])
        for operation in design["candidate_operation"]:
            self.assertFalse(operation["enabled"], operation["id"])
        registry = tomllib.loads(REGISTRY.read_text(encoding="utf-8"))
        registered = str(registry.get("registered_operations", {}))
        for effect in (
            "operation:package.install", "operation:package.remove",
            "operation:package.reinstall", "operation:package.orphans.remove",
            "operation:application.default.set", "operation:application.default.reset",
            "operation:application.association.add", "operation:application.association.remove",
        ):
            self.assertNotIn(effect, registered)

    def test_no_implementation_pull_requests_from_wip(self) -> None:
        design = tomllib.loads(DESIGN.read_text(encoding="utf-8"))
        self.assertEqual(design["pr_decomposition"]["branch"], "wip/v010-s23-applications")
        self.assertFalse(design["pr_decomposition"]["merge_wip_directly"])


if __name__ == "__main__":
    unittest.main()
