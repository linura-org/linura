from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class V05ExecutorVerifierBoundaryTests(unittest.TestCase):
    def _manifest_dependencies(self, relative: str) -> set[str]:
        manifest = tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))
        dependencies = manifest.get("dependencies", {})
        self.assertIsInstance(dependencies, dict)
        names: set[str] = set()
        for alias, spec in dependencies.items():
            if isinstance(spec, dict) and isinstance(spec.get("package"), str):
                names.add(spec["package"])
            else:
                names.add(alias)
        return names

    def test_executor_cannot_gain_control_plane_or_persistence_authority(self) -> None:
        dependencies = self._manifest_dependencies(
            "executors/linura-executor-systemd/Cargo.toml"
        )
        forbidden = {
            "linura-control",
            "linura-policy",
            "linura-planner",
            "linura-transaction",
            "linura-persistence-sqlite",
            "linura-linux-observation",
            "linura-observation-control",
            "linura-agent-runtime",
            "linura-sdk",
        }
        self.assertTrue(
            forbidden.isdisjoint(dependencies), sorted(forbidden & dependencies)
        )

    def test_verifier_is_pure_and_cannot_import_executor_or_native_transport(
        self,
    ) -> None:
        dependencies = self._manifest_dependencies(
            "verifiers/linura-verifier-systemd/Cargo.toml"
        )
        forbidden = {
            "zbus",
            "dbus",
            "linura-executor-systemd",
            "linura-linux-observation",
            "linura-control",
            "linura-policy",
            "linura-transaction",
            "linura-persistence-sqlite",
        }
        self.assertTrue(
            forbidden.isdisjoint(dependencies), sorted(forbidden & dependencies)
        )

        source = (ROOT / "verifiers/linura-verifier-systemd/src/lib.rs").read_text(
            encoding="utf-8"
        )
        for marker in (
            "zbus::",
            "Connection::",
            "RestartUnit",
            "linura_executor_systemd",
        ):
            self.assertNotIn(marker, source)
        self.assertIn("ObservationAuthority::NativeApi", source)
        self.assertIn("FreshnessState::Current", source)
        self.assertIn("active_enter_timestamp_monotonic", source)

    def test_executor_effect_is_fixed_namespaced_systemd_restart(self) -> None:
        source = (ROOT / "executors/linura-executor-systemd/src/lib.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'QUALIFICATION_UNIT_PREFIX: &str = "linura-v05-qualification-"', source
        )
        self.assertIn('const QUALIFICATION_OPERATION: &str = "restart-unit"', source)
        self.assertIn('proxy.call("RestartUnit"', source)
        self.assertIn('Command::new("/usr/bin/pkcheck")', source)
        self.assertIn(
            'QUALIFICATION_ACTION_ID: &str = "org.linura.executor.systemd.qualify-restart"',
            source,
        )
        for marker in (
            'Command::new("/bin/sh")',
            'Command::new("/bin/bash")',
            'Command::new("sh")',
            'Command::new("bash")',
            '"-c"',
        ):
            self.assertNotIn(marker, source)

    def test_canonical_observer_owns_restart_machine_truth(self) -> None:
        observer = (ROOT / "crates/linura-linux-observation/src/lib.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'snapshot_property(&properties, "ActiveEnterTimestampMonotonic")', observer
        )
        self.assertIn('"active_enter_timestamp_monotonic"', observer)
        self.assertIn("ObservationAuthority::NativeApi", observer)

    def test_production_policy_is_not_the_vm_qualification_grant(self) -> None:
        policy = (
            ROOT / "packaging/polkit-1/actions/org.linura.executor.systemd.policy"
        ).read_text(encoding="utf-8")
        self.assertIn("<allow_any>no</allow_any>", policy)
        self.assertIn("<allow_inactive>no</allow_inactive>", policy)
        self.assertIn("<allow_active>auth_admin</allow_active>", policy)
        self.assertNotIn("linura-v05-qualifier", policy)

        test_rule = (
            ROOT / "tests/acceptance/v05/49-linura-v05-qualification.rules"
        ).read_text(encoding="utf-8")
        self.assertIn('subject.user === "linura-v05-qualifier"', test_rule)
        self.assertIn(
            'action.id === "org.linura.executor.systemd.qualify-restart"', test_rule
        )

    def test_executor_service_keeps_empty_capability_sets_and_os_hardening(
        self,
    ) -> None:
        unit = (
            ROOT / "packaging/systemd/system/linura-executor-systemd.service"
        ).read_text(encoding="utf-8")
        for marker in (
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateDevices=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "RestrictNamespaces=yes",
            "MemoryDenyWriteExecute=yes",
            "CapabilityBoundingSet=\n",
            "AmbientCapabilities=\n",
        ):
            self.assertIn(marker, unit)

    def test_qualification_protocol_does_not_become_public_cli_surface(self) -> None:
        forbidden_markers = (
            "QualifyRestart",
            "qualify_restart",
            "org.linura.Executor.Systemd1",
        )
        for root in (ROOT / "apps", ROOT / "crates"):
            for path in root.rglob("*.rs"):
                text = path.read_text(encoding="utf-8")
                for marker in forbidden_markers:
                    self.assertNotIn(
                        marker,
                        text,
                        f"qualification executor leaked into product surface: {path}",
                    )

    def test_vm_protocol_is_versioned_and_evidence_bounded(self) -> None:
        workflow = (ROOT / ".github/workflows/v05-executor-verifier-vm.yml").read_text(
            encoding="utf-8"
        )
        host = ROOT / "tests/acceptance/v05/qualify-host.sh"
        guest = ROOT / "tests/acceptance/v05/qualify-guest.sh"
        self.assertTrue(host.is_file())
        self.assertTrue(guest.is_file())
        self.assertIn("bash tests/acceptance/v05/qualify-host.sh", workflow)
        self.assertIn('"managed_mutation_support": "none"', workflow)
        self.assertIn('"complete_lifecycle": False', workflow)
        self.assertIn("ordinary caller denied by Polkit", workflow)
        self.assertIn(
            "independent verifier satisfied without executor receipt", workflow
        )


if __name__ == "__main__":
    unittest.main()
