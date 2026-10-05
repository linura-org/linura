from __future__ import annotations

from pathlib import Path
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import v09_qualification_scope as routing  # noqa: E402


class QualificationScopeTests(unittest.TestCase):
    def setUp(self):
        self.contract = tomllib.loads(
            (ROOT / "contracts/v09-qualification-routing.toml").read_text(encoding="utf-8"))

    def test_shared_authority_and_qualification_dependencies_are_full(self):
        protected = (
            "crates/linura-control/src/lib.rs",
            "crates/linura-agent-runtime/src/lib.rs",
            "crates/linura-dbus/src/lib.rs",
            "crates/linura-library/src/lib.rs",
            "crates/linura-lifecycle/src/lib.rs",
            "crates/linura-provider-sdk/src/lib.rs",
            "crates/linura-policy/src/lib.rs",
            "crates/linura-protocol/src/lib.rs",
            "crates/linura-observation/src/lib.rs",
            "crates/linura-observation-control/src/lib.rs",
            "crates/linura-linux-observation/src/lib.rs",
            "crates/linura-planner/src/lib.rs",
            "crates/linura-persistence-sqlite/src/lib.rs",
            "crates/linura-transaction/src/lib.rs",
            "apps/linura-authorityd/src/main.rs",
            "apps/linura-authorityd/build.rs",
            "apps/linurad/src/main.rs",
            "apps/linuractl/src/main.rs",
            "crates/linura-sdk/src/lib.rs",
            "executors/linura-executor-systemd/src/lib.rs",
            "verifiers/linura-verifier-systemd/src/lib.rs",
            "interfaces/dbus/org.linura.Authority1.xml",
            "crates/linura-bootstrap/src/lib.rs",
            "crates/linura-update/src/lib.rs",
            "Cargo.lock", ".cargo/config", ".cargo/config.toml",
            "packaging/wireplumber/linura-session-audio.lua",
            "tools/image.py", "contracts/stability.toml",
            "tools/acceptance.py",
            "scripts/qualification/v09-adversarial-guest.sh",
            "tests/acceptance/008-control1-plan-preview.json",
        )
        for path in protected:
            with self.subTest(path=path):
                self.assertTrue(routing.requires_full_qualification(
                    [path], self.contract))

    def test_authority_and_firstboot_manifest_dependencies_are_full(self):
        # A new direct runtime or test dependency must update the routing contract.
        for manifest_path in (
            "apps/linura-authorityd/Cargo.toml",
            "apps/linura-firstboot/Cargo.toml",
            "crates/linura-control/Cargo.toml",
            "apps/linurad/Cargo.toml",
            "apps/linuractl/Cargo.toml",
            "crates/linura-sdk/Cargo.toml",
        ):
            manifest = ROOT / manifest_path
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, spec in data.get(group, {}).items():
                    if not isinstance(spec, dict) or "path" not in spec:
                        continue
                    with self.subTest(manifest=manifest_path, dependency=name):
                        dependency_root = (manifest.parent / spec["path"]).resolve()
                        self.assertTrue(dependency_root.is_relative_to(ROOT))
                        prefix = dependency_root.relative_to(ROOT).as_posix() + "/"
                        self.assertTrue(
                            any(prefix.startswith(route)
                                for route in self.contract["full_prefixes"]),
                            f"unqualified direct dependency: {prefix}")

    def test_routing_governance_inputs_are_always_full(self):
        protected = (
            ".github/workflows/v09-qualification.yml",
            "contracts/v09-qualification-routing.toml",
            "tools/v09_qualification_scope.py",
            "tests/tooling/test_v09_qualification_scope.py",
            "tools/check_validation_gates.py",
            "tests/tooling/test_validation_gates.py",
        )
        for path in protected:
            with self.subTest(path=path):
                self.assertIn(path, self.contract["full_exact"])
                self.assertTrue(routing.requires_full_qualification(
                    [path], self.contract))

    def test_qualification_harness_changes_cannot_use_fast_regression(self):
        for path in ("tools/acceptance.py", "scripts/qualification/v09-adversarial-guest.sh"):
            with self.subTest(path=path):
                self.assertIn(path, self.contract["full_exact"])
                self.assertTrue(routing.requires_full_qualification(
                    [path], self.contract))
                self.assertTrue(routing.requires_full_qualification(
                    ["docs/development-infrastructure.md", path], self.contract))

    def test_guidance_only_remains_fast_without_hiding_mixed_code(self):
        guidance = [
            "crates/linura-control/AGENTS.md",
            "crates/linura-control/README.md",
            "apps/linura-authorityd/AGENTS.md",
            "apps/linura-authorityd/README.md",
            "docs/development-infrastructure.md",
        ]
        for path in guidance:
            with self.subTest(path=path):
                self.assertFalse(routing.requires_full_qualification(
                    [path], self.contract))
        self.assertTrue(routing.requires_full_qualification(
            guidance + ["crates/linura-control/src/lib.rs"], self.contract))
        self.assertTrue(routing.requires_full_qualification(
            ["apps/linura-authorityd/AGENTS.md",
             "apps/linura-authorityd/build.rs"], self.contract))

    def test_rename_cannot_hide_original_protected_path(self):
        self.assertTrue(routing.requires_full_qualification(
            ["crates/linura-control/src/lib.rs", "docs/retired.rs"],
            self.contract))

    def test_ambiguous_impact_and_mutated_exemptions_fail_closed(self):
        self.assertTrue(routing.requires_full_qualification([], self.contract))
        for path in ("", "/absolute", "../escape", "path/../escape", "src/"):
            with self.subTest(path=path):
                with self.assertRaises(routing.RoutingError):
                    routing.requires_full_qualification([path], self.contract)
        for broken in (dict(self.contract, full_exact=[]),
                       dict(self.contract, guidance_only_basenames=["lib.rs"])):
            with self.assertRaises(routing.RoutingError):
                routing.requires_full_qualification(
                    ["docs/development-infrastructure.md"], broken)

    def test_reusable_and_manual_runs_remain_forced_full(self):
        workflow = (ROOT / ".github/workflows/v09-qualification.yml").read_text(
            encoding="utf-8")
        self.assertIn('if [[ "$GITHUB_EVENT_NAME" != "pull_request" ]]; then',
                      workflow)
        self.assertIn("full_qualification=true", workflow)
        self.assertIn("full = requires_full_qualification(changed, contract)",
                      workflow)


if __name__ == "__main__":
    unittest.main()
