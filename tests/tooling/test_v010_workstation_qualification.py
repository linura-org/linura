from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[2]


class V010WorkstationQualificationTests(unittest.TestCase):
    def _run(
        self,
        root: Path,
        *,
        expected_source_sha: str | None = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        expected_linurad_sha256: str | None = None,
        expected_shell_bridge_sha256: str | None = None,
        require_binary_binding: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if expected_source_sha is None:
            env.pop("LINURA_EXPECTED_SOURCE_SHA", None)
        else:
            env["LINURA_EXPECTED_SOURCE_SHA"] = expected_source_sha
        for name, value in (
            ("LINURA_EXPECTED_LINURAD_SHA256", expected_linurad_sha256),
            ("LINURA_EXPECTED_SHELL_BRIDGE_SHA256", expected_shell_bridge_sha256),
        ):
            if value is None:
                env.pop(name, None)
            else:
                env[name] = value
        if require_binary_binding:
            env["LINURA_REQUIRE_BINARY_BINDING"] = "1"
        else:
            env.pop("LINURA_REQUIRE_BINARY_BINDING", None)
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_v010_workstation_qualification.py"), str(root)],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    def _copy_fixture(self, destination: Path) -> None:
        paths = (
            "contracts/roadmap.toml",
            "contracts/v010-workstation-qualification.toml",
            "contracts/v010-workstation-slices.toml",
            "contracts/operation-semantics.toml",
            "profiles/arch-hyprland-v1.toml",
            "hardware/support-matrix.json",
            "docs/qualification/v0.10.0.md",
            "docs/adr/0031-v010-many-interfaces-one-authority-path.md",
            "docs/adr/0033-v010-complete-workstation-product-boundary.md",
            "packaging/arch/archiso/packages.linura",
            "visual/baselines/manifest.json",
        )
        for rel in paths:
            source = ROOT / rel
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def _rewrite_contract(self, root: Path, old: str, new: str) -> None:
        path = root / "contracts/v010-workstation-qualification.toml"
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def _refresh_profile_digest(self, root: Path) -> None:
        profile = root / "profiles/arch-hyprland-v1.toml"
        digest = hashlib.sha256(profile.read_bytes()).hexdigest()
        contract = root / "contracts/v010-workstation-qualification.toml"
        text = contract.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        old = data["profile_sha256"]
        contract.write_text(text.replace(old, digest, 1), encoding="utf-8")

    def _required_packages(self, root: Path) -> list[str]:
        path = root / "packaging/arch/archiso/packages.linura"
        return sorted(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    def _write_frozen_manifest(self, root: Path, *, omit: str | None = None) -> Path:
        manifest = root / "qualification/v010/arch-packages.tsv"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        records = []
        packages = set(self._required_packages(root))
        packages.update({"qt6-base", "systemd"})
        for package in sorted(packages):
            if package == omit:
                continue
            records.append(f"core\t{package}\t1:1.0.0-1\tx86_64")
        manifest.write_text(
            "# linura-arch-package-manifest-v1\n"
            "# snapshot_date=2026-09-16\n"
            "# architecture=x86_64\n"
            + "\n".join(records)
            + "\n",
            encoding="utf-8",
        )
        return manifest

    def _freeze_contract(self, root: Path, manifest: Path) -> None:
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self._rewrite_contract(
            root,
            'state = "source-pinned-package-set-pending"',
            'state = "frozen"',
        )
        self._rewrite_contract(
            root,
            'package_manifest = ""',
            'package_manifest = "qualification/v010/arch-packages.tsv"',
        )
        self._rewrite_contract(
            root,
            'package_manifest_sha256 = ""',
            f'package_manifest_sha256 = "{digest}"',
        )
        self._rewrite_contract(
            root,
            "release_qualification_ready = false",
            "release_qualification_ready = true",
        )

    def _write_interactive_workstation_evidence(
        self,
        root: Path,
        *,
        physical_hardware: bool = True,
        gpu_driver: str = "amdgpu",
        source_commit_sha: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ) -> Path:
        package_manifest = self._write_frozen_manifest(root)
        self._freeze_contract(root, package_manifest)
        package_manifest_digest = hashlib.sha256(package_manifest.read_bytes()).hexdigest()
        package_versions: dict[str, str] = {}
        for line in package_manifest.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            _repository, name, version, _architecture = line.split("\t")
            package_versions[name] = version

        provider_ids = ("networkmanager", "bluez", "pipewire", "wireplumber", "udisks2", "polkit")
        provider_versions = {provider_id: package_versions[provider_id] for provider_id in provider_ids}
        evidence_dir = root / "qualification/v010/interactive-workstation"
        machine_dir = evidence_dir / "machine"
        provenance_dir = evidence_dir / "provenance"
        machine_dir.mkdir(parents=True, exist_ok=True)
        provenance_dir.mkdir(parents=True, exist_ok=True)

        run_id = "q11-fixture-run"
        boot_id = "11111111-2222-3333-4444-555555555555"
        case_observations = {
            "bounded-installer-lane": [
                "installer-started-from-supported-media",
                "arch-hyprland-v1-constructed-or-adopted",
                "disk-encryption-baseline-verified",
                "firewall-default-deny-verified",
                "ssh-disabled-default-verified",
                "owner-enrollment-completed",
                "install-interruption-injected",
                "interrupted-install-recovered",
                "post-install-first-boot-completed",
            ],
            "physical-session-start": ["physical-hardware-present", "wayland-session-active", "hyprland-session-active"],
            "session-supervision": [
                "hyprland-session-target-active",
                "graphical-session-target-active",
                "linura-shell-active-through-session-target",
                "linura-shell-binds-to-session-target",
                "linura-shell-part-of-session-target",
                "linura-shell-stopped-with-graphical-session",
            ],
            "shell-render-and-input": ["shell-rendered", "keyboard-input", "pointer-input"],
            "display-scale-and-hidpi": ["display-enumerated", "scale-applied", "hidpi-render-captured"],
            "accessibility-and-visual": [
                "screen-reader-semantics-verified",
                "focus-navigation-verified",
                "reduced-motion-verified",
                "visual-artifact-retained",
            ],
            "provider-runtime-identities": ["networkmanager-version", "bluez-version", "pipewire-version", "wireplumber-version", "udisks2-version", "polkit-version"],
            "restart-recovery": ["shell-restart", "authority-restart", "state-reobserved"],
        }
        source = {
            "commit_sha": source_commit_sha,
            "linurad_sha256": "b" * 64,
            "shell_bridge_sha256": "c" * 64,
        }
        hardware = {
            "cpu": {"architecture": "x86_64", "vendor": "AuthenticAMD", "model": "fixture-cpu"},
            "gpu": {
                "vendor_id": "1002",
                "device_id": "fixture-gpu",
                "driver": gpu_driver,
                "driver_version": "fixture-driver-1",
            },
            "displays": [
                {
                    "connector": "DP-1",
                    "width": 320,
                    "height": 180,
                    "refresh_millihz": 60000,
                    "scale": 1.0,
                }
            ],
        }

        def binding(path: Path) -> dict[str, str]:
            return {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        package_inventory = machine_dir / "package-inventory.tsv"
        package_inventory.write_text(
            "".join(f"{name}\t{package_versions[name]}\n" for name in sorted(package_versions)),
            encoding="utf-8",
        )
        os_release = machine_dir / "os-release.txt"
        os_release.write_text("ID=arch\n", encoding="utf-8")
        root_filesystem = machine_dir / "root-filesystem.txt"
        root_filesystem.write_text("btrfs\n", encoding="utf-8")
        virtualization = machine_dir / "virtualization.txt"
        virtualization.write_text("none\n", encoding="utf-8")
        boot_id_probe = machine_dir / "boot-id.txt"
        boot_id_probe.write_text(boot_id + "\n", encoding="utf-8")
        hardware_probe = machine_dir / "hardware.json"
        hardware_probe.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "artifact_type": "linura-v010-physical-hardware-probe",
                    "source_commit_sha": source_commit_sha,
                    "run_id": run_id,
                    "hardware": hardware,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        contract_path = root / "contracts/v010-workstation-qualification.toml"
        contract_data = tomllib.loads(contract_path.read_text(encoding="utf-8"))
        environment_path = machine_dir / "environment.json"
        environment_payload = {
            "schema_version": 1,
            "artifact_type": "linura-v010-physical-workstation-environment",
            "source_commit_sha": source_commit_sha,
            "run_id": run_id,
            "profile_id": "arch-hyprland-v1",
            "profile_sha256": contract_data["profile_sha256"],
            "machine_class": "workstation",
            "package_manifest_sha256": package_manifest_digest,
            "execution": {
                "scope": "machine",
                "kind": "physical",
                "architecture": "x86_64",
                "boot_id": boot_id,
                "virtualization": "none",
            },
            "package_inventory": binding(package_inventory),
            "hardware_probe": binding(hardware_probe),
            "probes": {
                "os_release": binding(os_release),
                "root_filesystem": binding(root_filesystem),
                "virtualization": binding(virtualization),
                "boot_id": binding(boot_id_probe),
            },
        }
        environment_path.write_text(
            json.dumps(environment_payload, indent=2) + "\n",
            encoding="utf-8",
        )
        environment_binding = binding(environment_path)

        cases = []
        mechanisms = {
            "bounded-installer-lane": "physical-installer-execution",
            "physical-session-start": "physical-session-observation",
            "session-supervision": "systemd-session-observation",
            "shell-render-and-input": "physical-input-observation",
            "display-scale-and-hidpi": "physical-display-observation",
            "accessibility-and-visual": "physical-accessibility-visual-observation",
            "provider-runtime-identities": "physical-provider-observation",
            "restart-recovery": "physical-restart-observation",
        }
        for name, observations in case_observations.items():
            mechanism = mechanisms[name]
            event_log = provenance_dir / f"{name}.log"
            event_log.write_text(
                f"case={name}\n"
                "controller=maintainer-console\n"
                f"mechanism={mechanism}\n"
                f"environment_sha256={environment_binding['sha256']}\n"
                f"source_commit_sha={source_commit_sha}\n"
                f"run_id={run_id}\n"
                "scope=machine\n"
                f"boot_id={boot_id}\n",
                encoding="utf-8",
            )
            provenance_path = provenance_dir / f"{name}.json"
            provenance_payload = {
                "schema_version": 1,
                "artifact_type": "linura-v010-physical-workstation-case-provenance",
                "source_commit_sha": source_commit_sha,
                "run_id": run_id,
                "case": name,
                "environment_sha256": environment_binding["sha256"],
                "boot_id": boot_id,
                "scope": "machine",
                "controller": "maintainer-console",
                "mechanism": mechanism,
                "external_controller": True,
                "process_local_mock": False,
                "event_log": binding(event_log),
            }
            provenance_path.write_text(
                json.dumps(provenance_payload, indent=2) + "\n",
                encoding="utf-8",
            )
            provenance_binding = binding(provenance_path)

            evidence = evidence_dir / f"{name}.json"
            payload = {
                "schema_version": 1,
                "attestation_type": "linura-v010-qualification-case",
                "case": name,
                "result": "passed",
                "run_id": run_id,
                "captured_at_utc": "2026-09-27T00:00:00Z",
                "runner": {"id": "qualification/v010/workstation-runner", **source},
                "machine_execution": {
                    "scope": "machine",
                    "environment_sha256": environment_binding["sha256"],
                    "boot_id": boot_id,
                    "controller": "maintainer-console",
                    "mechanism": mechanism,
                    "provenance": provenance_binding,
                },
                "observations": [
                    {
                        "name": observation,
                        "result": "passed",
                        "value": (
                            provider_versions[observation.removesuffix("-version")]
                            if observation.endswith("-version")
                            else True
                        ),
                    }
                    for observation in observations
                ],
            }
            if name == "accessibility-and-visual":
                visual_artifact = evidence_dir / "accessibility-and-visual.png"
                display = hardware["displays"][0]
                visual_artifact.write_bytes(
                    self._png_bytes(
                        display["width"],
                        display["height"],
                        pixel_value=96,
                        pattern_values=(16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 255),
                    )
                )
                payload["visual_artifact"] = {
                    **binding(visual_artifact),
                    "environment_sha256": environment_binding["sha256"],
                    "execution_provenance_sha256": provenance_binding["sha256"],
                    "capture": {
                        "kind": "full-output",
                        "coordinate_space": "physical-pixels",
                        "connector": display["connector"],
                        "pixel_width": display["width"],
                        "pixel_height": display["height"],
                        "scale": display["scale"],
                    },
                }
            evidence.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            cases.append(
                {
                    "name": name,
                    "result": "passed",
                    "evidence": evidence.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                }
            )

        manifest = root / "qualification/v010/interactive-workstation-evidence.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest_payload = {
            "schema_version": 1,
            "milestone": "v0.10.0",
            "profile_id": "arch-hyprland-v1",
            "machine_class": "workstation",
            "evidence_type": "maintainer-physical-workstation",
            "evidence_tier": "maintainer_hardware",
            "physical_hardware": physical_hardware,
            "result": "passed",
            "run_id": run_id,
            "captured_at_utc": "2026-09-27T00:00:00Z",
            "package_manifest_sha256": package_manifest_digest,
            "source": source,
            "machine_environment": environment_binding,
            "hardware": hardware,
            "session": {
                "protocol": "wayland",
                "compositor": "hyprland",
                "compositor_version": package_versions["hyprland"],
                "quickshell_version": package_versions["quickshell"],
                "qt_version": package_versions["qt6-base"],
                "kernel_version": package_versions["linux"],
                "systemd_version": package_versions["systemd"],
            },
            "providers": provider_versions,
            "cases": cases,
        }
        manifest.write_text(json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8")
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self._rewrite_contract(
            root,
            '[interactive_workstation]\nevidence_ready = false\nevidence_manifest = "qualification/v010/interactive-workstation-evidence.json"\nevidence_manifest_sha256 = ""',
            '[interactive_workstation]\nevidence_ready = true\nevidence_manifest = "qualification/v010/interactive-workstation-evidence.json"\n'
            f'evidence_manifest_sha256 = "{digest}"',
        )
        return manifest

    def _release_matrix_mechanism(self, evidence_type: str, case_name: str) -> str:
        q12 = {
            "update-success": "machine-update",
            "migration-v09-v010": "machine-migration",
            "pre-migration-backup": "machine-backup",
            "migration-failure-restore-retry": "externally-injected-migration-failure",
            "update-interruption": "externally-interrupted-update",
            "restart-reobservation": "machine-reboot",
            "crash-before-dispatch": "external-process-termination",
            "crash-after-effect-start": "external-process-termination",
            "crash-around-durable-commit": "external-process-termination",
            "indeterminate-external-outcome": "external-response-loss",
            "deterministic-reconciliation": "external-state-drift",
            "power-loss-recovery": "machine-power-cut",
            "snapshot-rollback": "snapper-rollback",
            "gui-unavailable-recovery": "shell-or-session-stop",
            "offline-local-recovery": "network-isolation",
            "corrupt-newer-state-fail-closed": "persistent-state-corruption",
        }
        q13 = {
            "inbound-firewall-default-deny": "inbound-network-probe",
            "ssh-disabled-default": "listener-and-unit-probe",
            "remote-exposure-typed-authority": "unauthorized-remote-exposure-attempt",
            "untrusted-package-source-denied": "untrusted-package-source-attempt",
            "polkit-authorization": "cross-principal-polkit-probe",
            "privilege-boundary": "privilege-boundary-probe",
            "binding-substitution-rejection": "binding-substitution-attempt",
            "independent-verification": "executor-self-report-tamper",
            "authority-ceiling": "surface-authority-probe",
            "secret-redaction": "secret-injection",
            "adversarial-input": "malformed-input-injection",
            "malicious-inputs": "malicious-input-corpus",
            "recovery-boundary": "gui-and-model-unavailability",
        }
        mapping = q12 if evidence_type == "exact-source-q12-update-recovery" else q13
        return mapping.get(case_name, f"legacy-{case_name}")

    def _refresh_release_matrix_contract_digest(
        self,
        root: Path,
        *,
        section: str,
        manifest: Path,
    ) -> None:
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        contract = root / "contracts/v010-workstation-qualification.toml"
        text = contract.read_text(encoding="utf-8")
        old = tomllib.loads(text)[section]["evidence_manifest_sha256"]
        contract.write_text(text.replace(old, digest, 1), encoding="utf-8")

    def _write_release_matrix_evidence(
        self,
        root: Path,
        *,
        section: str,
        manifest_name: str,
        evidence_type: str,
        case_observations: dict[str, list[str]],
        source_commit_sha: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ) -> Path:
        contract_path = root / "contracts/v010-workstation-qualification.toml"
        contract_data = tomllib.loads(contract_path.read_text(encoding="utf-8"))
        if contract_data["substrate"]["state"] != "frozen":
            package_manifest = self._write_frozen_manifest(root)
            self._freeze_contract(root, package_manifest)
            contract_data = tomllib.loads(contract_path.read_text(encoding="utf-8"))
        else:
            package_manifest = root / contract_data["substrate"]["package_manifest"]

        package_manifest_digest = hashlib.sha256(package_manifest.read_bytes()).hexdigest()
        package_versions: dict[str, str] = {}
        for line in package_manifest.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            _repository, name, version, _architecture = line.split("\t")
            package_versions[name] = version

        run_id = f"{section}-fixture-run"
        evidence_dir = root / "qualification/v010/release-matrix" / section
        machine_dir = evidence_dir / "machine"
        provenance_dir = evidence_dir / "provenance"
        machine_dir.mkdir(parents=True, exist_ok=True)
        provenance_dir.mkdir(parents=True, exist_ok=True)

        boot_id = "11111111-2222-3333-4444-555555555555"
        package_inventory = machine_dir / "package-inventory.tsv"
        package_inventory.write_text(
            "".join(f"{name}\t{package_versions[name]}\n" for name in sorted(package_versions)),
            encoding="utf-8",
        )
        os_release = machine_dir / "os-release.txt"
        os_release.write_text("ID=arch\n", encoding="utf-8")
        root_filesystem = machine_dir / "root-filesystem.txt"
        root_filesystem.write_text("btrfs\n", encoding="utf-8")
        virtualization = machine_dir / "virtualization.txt"
        virtualization.write_text("qemu\n", encoding="utf-8")
        boot_id_probe = machine_dir / "boot-id.txt"
        boot_id_probe.write_text(boot_id + "\n", encoding="utf-8")

        def binding(path: Path) -> dict[str, str]:
            return {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        environment_path = machine_dir / "environment.json"
        environment_payload = {
            "schema_version": 1,
            "artifact_type": "linura-v010-machine-environment",
            "source_commit_sha": source_commit_sha,
            "run_id": run_id,
            "profile_id": "arch-hyprland-v1",
            "profile_sha256": contract_data["profile_sha256"],
            "machine_class": "workstation",
            "package_manifest_sha256": package_manifest_digest,
            "execution": {
                "scope": "machine",
                "kind": "virtual-machine",
                "architecture": "x86_64",
                "boot_id": boot_id,
                "virtualization": "qemu",
            },
            "storage": {
                "root_filesystem": "btrfs",
                "snapshot_provider": "snapper",
            },
            "package_inventory": binding(package_inventory),
            "probes": {
                "os_release": binding(os_release),
                "root_filesystem": binding(root_filesystem),
                "virtualization": binding(virtualization),
                "boot_id": binding(boot_id_probe),
            },
        }
        environment_path.write_text(
            json.dumps(environment_payload, indent=2) + "\n",
            encoding="utf-8",
        )
        environment_binding = {
            "evidence": environment_path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(environment_path.read_bytes()).hexdigest(),
        }

        cases = []
        boot_transition_mechanisms = {"machine-reboot", "machine-power-cut"}
        recovered_boot_id = "66666666-7777-8888-9999-aaaaaaaaaaaa"
        for name, observations in case_observations.items():
            mechanism = self._release_matrix_mechanism(evidence_type, name)
            requires_boot_transition = mechanism in boot_transition_mechanisms

            event_log = provenance_dir / f"{name}.log"
            event_lines = [
                f"case={name}",
                "controller=qemu-host",
                f"mechanism={mechanism}",
                f"environment_sha256={environment_binding['sha256']}",
                f"source_commit_sha={source_commit_sha}",
                f"run_id={run_id}",
                "scope=machine",
            ]
            if requires_boot_transition:
                event_lines.extend(
                    [
                        f"pre_boot_id={boot_id}",
                        f"post_boot_id={recovered_boot_id}",
                    ]
                )
            else:
                event_lines.append(f"boot_id={boot_id}")
            event_log.write_text("\n".join(event_lines) + "\n", encoding="utf-8")

            provenance_path = provenance_dir / f"{name}.json"
            provenance_payload = {
                "schema_version": 1,
                "artifact_type": "linura-v010-machine-case-provenance",
                "source_commit_sha": source_commit_sha,
                "run_id": run_id,
                "case": name,
                "environment_sha256": environment_binding["sha256"],
                "scope": "machine",
                "controller": "qemu-host",
                "mechanism": mechanism,
                "external_controller": True,
                "process_local_mock": False,
                "event_log": binding(event_log),
            }
            machine_execution = {
                "scope": "machine",
                "environment_sha256": environment_binding["sha256"],
                "controller": "qemu-host",
                "mechanism": mechanism,
            }
            if requires_boot_transition:
                post_boot_probe = provenance_dir / f"{name}-post-boot-id.txt"
                post_boot_probe.write_text(recovered_boot_id + "\n", encoding="utf-8")
                provenance_payload.update(
                    {
                        "pre_boot_id": boot_id,
                        "post_boot_id": recovered_boot_id,
                        "post_boot_probe": binding(post_boot_probe),
                    }
                )
                machine_execution.update(
                    {
                        "pre_boot_id": boot_id,
                        "post_boot_id": recovered_boot_id,
                    }
                )
            else:
                provenance_payload["boot_id"] = boot_id
                machine_execution["boot_id"] = boot_id

            provenance_path.write_text(
                json.dumps(provenance_payload, indent=2) + "\n",
                encoding="utf-8",
            )
            machine_execution["provenance"] = binding(provenance_path)

            evidence = evidence_dir / f"{name}.json"
            payload = {
                "schema_version": 1,
                "attestation_type": "linura-v010-release-qualification-case",
                "case": name,
                "result": "passed",
                "source_commit_sha": source_commit_sha,
                "run_id": run_id,
                "captured_at_utc": "2026-09-27T00:00:00Z",
                "runner": {
                    "id": "qualification/v010/release-matrix-runner",
                    "version": "1.0",
                    "commit_sha": source_commit_sha,
                },
                "machine_execution": machine_execution,
                "observations": [
                    {"name": observation, "result": "passed", "value": True}
                    for observation in observations
                ],
            }
            evidence.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            cases.append(
                {
                    "name": name,
                    "result": "passed",
                    "evidence": evidence.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                }
            )

        manifest = root / "qualification/v010" / manifest_name
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest_payload = {
            "schema_version": 1,
            "milestone": "v0.10.0",
            "evidence_type": evidence_type,
            "profile_id": "arch-hyprland-v1",
            "machine_class": "workstation",
            "result": "passed",
            "source_commit_sha": source_commit_sha,
            "run_id": run_id,
            "captured_at_utc": "2026-09-27T00:00:00Z",
            "machine_environment": environment_binding,
            "cases": cases,
        }
        manifest.write_text(json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8")
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()

        text = contract_path.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        old_digest = data[section]["evidence_manifest_sha256"]
        text = text.replace(
            f"[{section}]\nevidence_ready = false",
            f"[{section}]\nevidence_ready = true",
            1,
        )
        if old_digest:
            text = text.replace(old_digest, digest, 1)
        else:
            marker = f'[{section}]\nevidence_ready = true\nevidence_manifest = "qualification/v010/{manifest_name}"\nevidence_manifest_sha256 = ""'
            replacement = (
                f'[{section}]\nevidence_ready = true\nevidence_manifest = "qualification/v010/{manifest_name}"\n'
                f'evidence_manifest_sha256 = "{digest}"'
            )
            self.assertIn(marker, text)
            text = text.replace(marker, replacement, 1)
        contract_path.write_text(text, encoding="utf-8")
        return manifest

    def _q10_case_observations(self) -> dict[str, list[str]]:
        return {
            "manual-no-model-workflow": ["model-providers-absent", "manual-path-completed", "configuration-path-completed", "keyboard-path-completed"],
            "cross-interface-operation-class-convergence": ["cli-class-bound", "control-center-class-bound", "configuration-class-bound", "palette-shortcut-class-bound", "quick-settings-class-bound", "agent-proposal-class-bound", "classes-converged"],
            "declarative-authority-smuggling-rejection": ["unknown-field-rejected", "shell-text-rejected", "authority-token-rejected", "policy-approval-material-rejected", "no-effect-dispatched"],
            "unregistered-palette-operation-rejection": ["unregistered-operation-presented", "operation-rejected", "no-privileged-shell-dispatched"],
            "operation-class-downgrade-rejection": ["stronger-effect-presented-as-transient", "trusted-registry-class-preserved", "downgrade-rejected"],
            "stale-quick-settings-external-change": ["stale-observation-injected", "concurrent-external-change-injected", "mutation-disabled-or-revalidated", "authoritative-state-reobserved"],
            "forged-premature-success-rejection": ["premature-success-injected", "final-success-withheld", "independent-verification-required"],
            "malformed-malicious-interface-request": ["malformed-or-malicious-request-injected", "authority-not-widened", "no-unauthorized-effect-dispatched"],
            "input-accessibility-regression-rejection": ["keyboard-or-pointer-regression-injected", "semantic-or-focus-regression-injected", "regression-detected"],
            "visual-evidence-regression-rejection": ["null-or-unreviewed-baseline-injected", "coverage-or-interaction-gap-injected", "unretained-failure-diff-injected", "qualification-rejected"],
            "offline-stale-error-reconnect": ["provider-or-network-unavailable", "stale-or-unknown-rendered", "success-not-fabricated", "reconnect-reobserved"],
            "restart-during-managed-mutation": ["managed-mutation-in-flight", "surface-restart-injected", "stale-approval-not-resurrected", "effect-not-replayed", "authoritative-lifecycle-reconstructed"],
        }

    def _write_q10_authority_evidence(
        self,
        root: Path,
        *,
        source_commit_sha: str,
    ) -> Path:
        run_id = "q10-fixture-run"
        evidence_dir = root / "qualification/v010/experience/authority"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        cases = []
        for name, observations in self._q10_case_observations().items():
            evidence = evidence_dir / f"{name}.json"
            payload = {
                "schema_version": 1,
                "attestation_type": "linura-v010-release-qualification-case",
                "case": name,
                "result": "passed",
                "source_commit_sha": source_commit_sha,
                "run_id": run_id,
                "captured_at_utc": "2026-09-27T00:00:00Z",
                "runner": {
                    "id": "qualification/v010/release-matrix-runner",
                    "version": "1.0",
                    "commit_sha": source_commit_sha,
                },
                "observations": [
                    {"name": observation, "result": "passed", "value": True}
                    for observation in observations
                ],
            }
            evidence.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            cases.append(
                {
                    "name": name,
                    "result": "passed",
                    "evidence": evidence.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                }
            )

        manifest = root / "qualification/v010/experience/authority-evidence.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "milestone": "v0.10.0",
                    "evidence_type": "exact-source-q10-experience-authority",
                    "profile_id": "arch-hyprland-v1",
                    "machine_class": "workstation",
                    "result": "passed",
                    "source_commit_sha": source_commit_sha,
                    "run_id": run_id,
                    "captured_at_utc": "2026-09-27T00:00:00Z",
                    "cases": cases,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self._refresh_q10_authority_evidence_digest(root)
        return manifest

    def _q12_case_observations(self) -> dict[str, list[str]]:
        return {
            "update-success": ["candidate-applied", "post-update-state-reobserved", "update-audit-bound"],
            "migration-v09-v010": ["v09-state-seeded", "v010-migration-applied", "persistent-state-reopened"],
            "pre-migration-backup": ["risky-migration-identified", "writer-safe-backup-created", "backup-integrity-verified"],
            "migration-failure-restore-retry": ["migration-failure-injected", "pre-migration-backup-restored", "retry-converged"],
            "update-interruption": ["candidate-update-started", "interruption-injected", "restart-detected-incomplete-update"],
            "restart-reobservation": ["restart-completed", "authoritative-state-reobserved", "reobserved-state-bound"],
            "crash-before-dispatch": ["pre-dispatch-crash-injected", "executor-not-dispatched", "recovery-converged"],
            "crash-after-effect-start": ["effect-start-confirmed", "post-effect-start-crash-injected", "reconciliation-converged"],
            "crash-around-durable-commit": ["commit-boundary-crash-injected", "durable-state-recovered", "commit-outcome-reconciled"],
            "indeterminate-external-outcome": ["external-outcome-made-indeterminate", "self-report-not-trusted", "authoritative-outcome-resolved"],
            "deterministic-reconciliation": ["drift-detected", "reconciliation-plan-deterministic", "verified-state-converged"],
            "power-loss-recovery": ["power-loss-injected", "durable-state-recovered", "external-state-reconciled"],
            "snapshot-rollback": ["btrfs-snapshot-identified", "snapper-rollback-applied", "rollback-state-verified"],
            "gui-unavailable-recovery": ["gui-unavailable", "native-recovery-invoked", "local-repair-completed"],
            "offline-local-recovery": ["model-unavailable", "network-unavailable", "local-material-recovery-completed"],
            "corrupt-newer-state-fail-closed": ["corrupt-state-injected", "unsupported-newer-state-injected", "state-open-failed-closed"],
        }

    def _q13_case_observations(self) -> dict[str, list[str]]:
        return {
            "inbound-firewall-default-deny": ["firewall-policy-loaded", "unsolicited-inbound-probe-denied", "no-exposure-created"],
            "ssh-disabled-default": ["ssh-unit-disabled", "ssh-listener-absent", "boot-state-verified"],
            "remote-exposure-typed-authority": ["remote-exposure-requested", "typed-authority-required", "unauthorized-enable-denied"],
            "untrusted-package-source-denied": ["untrusted-source-presented", "source-rejected", "no-package-effect-dispatched"],
            "polkit-authorization": ["polkit-policy-loaded", "unauthorized-caller-denied", "authorized-caller-bound"],
            "privilege-boundary": ["unprivileged-daemon-confirmed", "generic-root-shell-absent", "privileged-effect-denied-without-authority"],
            "binding-substitution-rejection": ["actor-substitution-rejected", "plan-substitution-rejected", "evidence-substitution-rejected", "session-substitution-rejected"],
            "independent-verification": ["executor-self-report-injected", "authoritative-reobservation-performed", "self-report-not-accepted-as-verification"],
            "authority-ceiling": ["gui-proposal-only", "model-proposal-only", "deterministic-protocol-authority-preserved"],
            "secret-redaction": ["secret-bearing-input-injected", "audit-redacted", "diagnostics-redacted"],
            "adversarial-input": ["malformed-input-rejected", "authority-not-widened", "no-effect-dispatched"],
            "malicious-inputs": ["malicious-client-rejected", "malicious-proposal-rejected", "malicious-profile-rejected", "malicious-import-rejected"],
            "recovery-boundary": ["gui-unavailable", "model-unavailable", "native-recovery-remains-available"],
        }

    def _png_bytes(
        self,
        width: int,
        height: int,
        *,
        pixel_value: int = 0,
        transparent_gray: int | None = None,
        extra_raw_bytes: int = 0,
        ancillary_chunks: tuple[tuple[bytes, bytes], ...] = (),
        pattern_values: tuple[int, ...] | None = None,
    ) -> bytes:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            return (
                struct.pack(">I", len(payload))
                + kind
                + payload
                + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
            )

        ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
        self.assertGreaterEqual(pixel_value, 0)
        self.assertLessEqual(pixel_value, 255)
        if transparent_gray is not None:
            self.assertGreaterEqual(transparent_gray, 0)
            self.assertLessEqual(transparent_gray, 255)
        self.assertGreaterEqual(extra_raw_bytes, 0)
        if pattern_values is None:
            row = bytes([pixel_value]) * width
        else:
            self.assertGreaterEqual(len(pattern_values), 2)
            for value in pattern_values:
                self.assertGreaterEqual(value, 0)
                self.assertLessEqual(value, 255)
            row = bytes(
                pattern_values[min((x * len(pattern_values)) // width, len(pattern_values) - 1)]
                for x in range(width)
            )
        rows = b"".join(b"\x00" + row for _ in range(height)) + (b"\x00" * extra_raw_bytes)
        result = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
        if transparent_gray is not None:
            result += chunk(b"tRNS", struct.pack(">H", transparent_gray))
        for kind, payload in ancillary_chunks:
            self.assertEqual(len(kind), 4)
            result += chunk(kind, payload)
        return result + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")

    def _refresh_experience_evidence_digest(self, root: Path) -> None:
        evidence = root / "qualification/v010/experience-evidence.json"
        digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
        contract = root / "contracts/v010-workstation-qualification.toml"
        text = contract.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        old_digest = data["experience"]["experience_evidence_manifest_sha256"]
        contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")

    def _refresh_q10_authority_evidence_digest(self, root: Path) -> None:
        evidence = root / "qualification/v010/experience/authority-evidence.json"
        digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
        contract = root / "contracts/v010-workstation-qualification.toml"
        text = contract.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        old_digest = data["experience"]["authority_evidence_manifest_sha256"]
        if old_digest:
            text = text.replace(old_digest, digest, 1)
        else:
            text = text.replace(
                'authority_evidence_manifest_sha256 = ""',
                f'authority_evidence_manifest_sha256 = "{digest}"',
                1,
            )
        contract.write_text(text, encoding="utf-8")

    def _refresh_visual_baseline_manifest_digest(self, root: Path) -> None:
        manifest = root / "visual/baselines/manifest.json"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        contract = root / "contracts/v010-workstation-qualification.toml"
        text = contract.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        old_digest = data["experience"]["visual_baseline_manifest_sha256"]
        contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")

    def _visual_failure_binding(
        self,
        baseline_id: str,
        baseline_sha256: str,
        failed_capture_sha256: str,
        diff_sha256: str,
    ) -> str:
        payload = (
            "linura-v010-visual-failure-v1\n"
            f"{baseline_id}\n"
            f"{baseline_sha256}\n"
            f"{failed_capture_sha256}\n"
            f"{diff_sha256}\n"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _complete_product_slices_for_q10(self, root: Path) -> None:
        path = root / "contracts/v010-workstation-slices.toml"
        text = path.read_text(encoding="utf-8")
        parts = text.split("[[slice]]")
        rewritten = [parts[0]]
        for block in parts[1:]:
            if any(f'id = "S{index:02d}"' in block for index in range(15, 29)):
                block = block.replace('status = "planned"', 'status = "complete"', 1)
                block = block.replace("evidence_prs = []", "evidence_prs = [999]", 1)
            rewritten.append("[[slice]]" + block)
        text = "".join(rewritten)
        text = text.replace("completed_slice_count = 14", "completed_slice_count = 28", 1)
        text = text.replace('next_slice = "S15"', 'next_slice = "S29"', 1)
        path.write_text(text, encoding="utf-8")

    def _write_complete_experience_evidence(
        self,
        root: Path,
        *,
        source_commit_sha: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ) -> None:
        self._complete_product_slices_for_q10(root)
        run_id = "q10-fixture-run"
        baseline_manifest = root / "visual/baselines/manifest.json"
        required_visual_surfaces = ["linura-firstboot","linura-installer","linura-control-center","command-palette","quick-settings","desktop-shell-integration","shell-panel-tray-status","launcher-workspace","notifications-osd","lock-session-controls","network-connectivity","bluetooth","audio-media","display-power","desktop-utilities","applications-packages","updates-snapshots-recovery","personalization"]
        baseline_records = [
            ("firstboot-1280x800-1x", "linura-firstboot", 1280, 800, 1.0),
            ("firstboot-1280x800-2x", "linura-firstboot", 1280, 800, 2.0),
            ("control-center-1440x900-1x", "linura-control-center", 1440, 900, 1.0),
        ]
        existing_surfaces = {record[1] for record in baseline_records}
        for surface in required_visual_surfaces:
            if surface in existing_surfaces:
                continue
            # Per-surface presence/interaction coverage does not need to pay the
            # full-resolution decode cost. The three representative records above
            # retain the qualified 1280x800/1440x900 and 1x/2x coverage; all other
            # surfaces use a compact structured image that still exercises PNG,
            # rendered-content, digest, pixel-equivalence, and surface binding.
            baseline_records.append(
                (f"{surface}-32x24-1x", surface, 32, 24, 1.0)
            )
        baselines = []
        visual_dir = root / "visual/baselines"
        visual_dir.mkdir(parents=True, exist_ok=True)
        qualification_dir = root / "qualification/v010"
        qualification_dir.mkdir(parents=True, exist_ok=True)
        comparisons = []
        render_pattern = (0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240)
        for baseline_id, surface, width, height, scale in baseline_records:
            baseline_rel = f"visual/baselines/{baseline_id}.png"
            baseline_path = root / baseline_rel
            baseline_path.write_bytes(
                self._png_bytes(width, height, pattern_values=render_pattern)
            )
            capture_rel = f"qualification/v010/{baseline_id}-capture.png"
            capture_path = root / capture_rel
            capture_path.write_bytes(
                self._png_bytes(width, height, pattern_values=render_pattern)
            )
            baselines.append(
                {
                    "id": baseline_id,
                    "surface": surface,
                    "width": width,
                    "height": height,
                    "scale": scale,
                    "baseline": baseline_rel,
                    "sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
                }
            )
            comparisons.append(
                {
                    "baseline_id": baseline_id,
                    "capture": capture_rel,
                    "capture_sha256": hashlib.sha256(capture_path.read_bytes()).hexdigest(),
                    "status": "pass",
                    "reviewed": True,
                }
            )
        baseline_manifest.write_text(
            json.dumps({"schema_version": 1, "baselines": baselines}, indent=2) + "\n",
            encoding="utf-8",
        )
        baseline_digest = hashlib.sha256(baseline_manifest.read_bytes()).hexdigest()
        self._rewrite_contract(
            root,
            'visual_baseline_manifest_sha256 = ""',
            f'visual_baseline_manifest_sha256 = "{baseline_digest}"',
        )

        # Keep retained-failure mechanics on a compact surface. Resolution
        # handling is already exercised by the representative full-size records.
        failed_baseline = next(
            item for item in baselines if item["surface"] == "linura-installer"
        )
        failed_capture_rel = "qualification/v010/visual-failure-capture.png"
        failed_capture_path = root / failed_capture_rel
        failed_capture_path.write_bytes(
            self._png_bytes(
                int(failed_baseline["width"]),
                int(failed_baseline["height"]),
                pixel_value=255,
            )
        )
        failed_capture_digest = hashlib.sha256(failed_capture_path.read_bytes()).hexdigest()
        diff_rel = "qualification/v010/visual-failure-diff.png"
        diff_path = root / diff_rel
        diff_path.write_bytes(
            self._png_bytes(
                int(failed_baseline["width"]),
                int(failed_baseline["height"]),
                pattern_values=tuple(255 - value for value in render_pattern),
            )
        )
        diff_digest = hashlib.sha256(diff_path.read_bytes()).hexdigest()
        baseline_digest = str(failed_baseline["sha256"])
        failure_binding = self._visual_failure_binding(
            str(failed_baseline["id"]),
            baseline_digest,
            failed_capture_digest,
            diff_digest,
        )

        required_surfaces = ["linura-firstboot","linura-installer","linura-control-center","command-palette","quick-settings","desktop-shell-integration","shell-panel-tray-status","launcher-workspace","notifications-osd","lock-session-controls","network-connectivity","bluetooth","audio-media","display-power","desktop-utilities","applications-packages","updates-snapshots-recovery","personalization"]
        workflow_observations_by_surface = {
            "linura-firstboot": ["owner-enrollment-workflow-completed", "qualified-profile-state-rendered", "manual-no-ai-completion-verified"],
            "linura-installer": ["supported-profile-install-plan-rendered", "destructive-step-review-completed", "installer-handoff-to-firstboot-verified"],
            "linura-control-center": ["authoritative-state-reobserved", "registered-typed-effect-dispatched", "post-effect-verification-rendered"],
            "command-palette": ["registered-target-resolved", "typed-operation-dispatched", "raw-privileged-shell-rejected"],
            "quick-settings": ["fresh-authoritative-state-rendered", "registered-typed-effect-dispatched", "stale-or-unavailable-mutation-disabled"],
            "desktop-shell-integration": ["verified-lifecycle-state-rendered", "shell-authority-escalation-absent", "session-restart-state-reconstructed"],
            "shell-panel-tray-status": ["authoritative-status-rendered", "entrypoint-navigation-completed", "status-surface-authority-escalation-absent"],
            "launcher-workspace": ["application-launch-completed", "workspace-navigation-completed", "ephemeral-navigation-not-recorded-as-durable-mutation"],
            "notifications-osd": ["verified-commit-precedes-success-notification", "failure-lifecycle-notification-rendered", "secret-bearing-material-redacted"],
            "lock-session-controls": ["authenticated-actor-bound", "registered-session-action-dispatched", "authority-unavailable-fails-closed"],
            "network-connectivity": ["fresh-networkmanager-state-observed", "registered-network-effect-dispatched", "post-effect-network-state-reobserved"],
            "bluetooth": ["fresh-bluez-state-observed", "registered-bluetooth-effect-dispatched", "post-effect-bluetooth-state-reobserved"],
            "audio-media": ["fresh-pipewire-wireplumber-state-observed", "registered-audio-effect-dispatched", "post-effect-audio-state-reobserved"],
            "display-power": ["fresh-display-power-state-observed", "supported-display-power-effect-dispatched", "unsupported-or-stale-state-rendered"],
            "desktop-utilities": ["screenshot-or-recording-workflow-completed", "clipboard-history-workflow-completed", "privileged-shell-shortcut-absent"],
            "applications-packages": ["typed-package-discovery-completed", "registered-package-install-remove-effect-dispatched", "arbitrary-package-or-shell-text-rejected"],
            "updates-snapshots-recovery": ["coordinated-update-workflow-completed", "snapshot-or-rollback-workflow-completed", "durable-recovery-state-reobserved"],
            "personalization": ["typed-preference-change-completed", "preference-persistence-reobserved", "authority-bearing-payload-rejected"],
        }
        interaction_records = []
        for surface in required_surfaces:
            report_rel = f"qualification/v010/{surface}-interaction-accessibility.json"
            report_path = root / report_rel
            report = {
                "schema_version": 1,
                "artifact_type": "linura-v010-interaction-accessibility",
                "surface": surface,
                "result": "pass",
                "source_commit_sha": source_commit_sha,
                "run_id": run_id,
                "runner": {
                    "name": "fixture-runner",
                    "version": "1.0",
                    "run_id": run_id,
                    "platform": "arch-hyprland-v1",
                    "commit_sha": source_commit_sha,
                },
                "checks": {
                    "keyboard": "pass",
                    "pointer": "pass",
                    "focus_navigation": "pass",
                    "screen_reader": "pass",
                    "reduced_motion": "pass",
                    "display_scaling": "pass",
                    "offline_error": "pass",
                    "reconnect": "pass",
                },
                "workflow_observations": {
                    observation: "pass"
                    for observation in workflow_observations_by_surface[surface]
                },
            }
            if surface in {
                "command-palette",
                "quick-settings",
                "desktop-shell-integration",
                "shell-panel-tray-status",
                "launcher-workspace",
                "notifications-osd",
            }:
                report["input_region"] = {
                    "noninteractive_regions": "pass-through",
                    "interactive_regions": "bounded-to-visible-controls",
                }
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            interaction_records.append(
                {
                    "surface": surface,
                    "report": report_rel,
                    "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                }
            )

        self._write_q10_authority_evidence(
            root,
            source_commit_sha=source_commit_sha,
        )

        evidence = {
            "schema_version": 1,
            "source_commit_sha": source_commit_sha,
            "run_id": run_id,
            "captured_at_utc": "2026-09-27T00:00:00Z",
            "visual_comparisons": comparisons,
            "retained_failure_diffs": [
                {
                    "baseline_id": failed_baseline["id"],
                    "baseline_sha256": baseline_digest,
                    "failed_capture": failed_capture_rel,
                    "failed_capture_sha256": failed_capture_digest,
                    "status": "fail",
                    "diff": diff_rel,
                    "diff_sha256": diff_digest,
                    "binding_sha256": failure_binding,
                    "reviewed": True,
                }
            ],
            "interaction_accessibility": interaction_records,
        }
        evidence_path = qualification_dir / "experience-evidence.json"
        evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        self._rewrite_contract(
            root,
            'experience_evidence_manifest_sha256 = ""',
            f'experience_evidence_manifest_sha256 = "{digest}"',
        )
        self._rewrite_contract(
            root,
            "experience_evidence_ready = false",
            "experience_evidence_ready = true",
        )

    def test_repository_contract_is_valid(self) -> None:
        result = self._run(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_interactive_workstation_evidence_requires_digest_bound_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                '[interactive_workstation]\nevidence_ready = false',
                '[interactive_workstation]\nevidence_ready = true',
            )
            manifest = root / "qualification/v010/interactive-workstation-evidence.json"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text("{}\n", encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation evidence manifest must carry a lowercase SHA-256 digest",
                result.stderr,
            )

    def test_interactive_workstation_evidence_requires_physical_hardware_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_interactive_workstation_evidence(
                root,
                physical_hardware=False,
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation evidence must attest physical_hardware=true",
                result.stderr,
            )

    def test_digest_bound_interactive_workstation_evidence_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_interactive_workstation_evidence(root)
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_interactive_workstation_case_digest_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_interactive_workstation_evidence(root)
            evidence = root / "qualification/v010/interactive-workstation/physical-session-start.json"
            evidence.write_text("tampered\n", encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation case physical-session-start evidence digest mismatch",
                result.stderr,
            )

    def test_interactive_workstation_source_must_match_expected_release_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_interactive_workstation_evidence(root)
            result = self._run(root, expected_source_sha="dddddddddddddddddddddddddddddddddddddddd")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation source.commit_sha does not match the expected release source",
                result.stderr,
            )

    def test_interactive_workstation_rejects_package_manifest_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["package_manifest_sha256"] = "d" * 64
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "package_manifest_sha256 must match the frozen qualification package manifest",
                result.stderr,
            )

    def test_interactive_workstation_rejects_provider_version_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["providers"]["networkmanager"] = "9.9.9"
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("provider networkmanager must match frozen package version", result.stderr)

    def test_interactive_workstation_rejects_session_version_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["session"]["compositor_version"] = "9.9.9"
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("session.compositor_version must match frozen hyprland version", result.stderr)

    def test_interactive_workstation_rejects_qt_kernel_and_systemd_version_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            for key in ("qt_version", "kernel_version", "systemd_version"):
                payload["session"][key] = "9.9.9"
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")

            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "session.qt_version must match frozen qt6-base version",
                result.stderr,
            )
            self.assertIn(
                "session.kernel_version must match frozen linux version",
                result.stderr,
            )
            self.assertIn(
                "session.systemd_version must match frozen systemd version",
                result.stderr,
            )

    def test_interactive_workstation_rejects_cpu_architecture_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["hardware"]["cpu"]["architecture"] = "aarch64"
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation CPU architecture must match the frozen qualification substrate",
                result.stderr,
            )

    def test_interactive_workstation_release_binding_rejects_binary_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_interactive_workstation_evidence(root)
            result = self._run(
                root,
                expected_linurad_sha256="d" * 64,
                expected_shell_bridge_sha256="c" * 64,
                require_binary_binding=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "source.linurad_sha256 does not match independently qualified runtime artifact",
                result.stderr,
            )

    def test_interactive_workstation_requires_session_supervision_case(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["cases"] = [
                case for case in payload["cases"] if case["name"] != "session-supervision"
            ]
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation evidence must contain exactly the required Q11 cases",
                result.stderr,
            )

    def test_interactive_workstation_requires_executed_bounded_installer_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "bounded-installer-lane")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["machine_execution"]["mechanism"] = "process-local-installer"
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("machine_execution mechanism must be physical-installer-execution", result.stderr)

    def test_interactive_workstation_requires_physical_accessibility_visual_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "accessibility-and-visual")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation.pop("visual_artifact")
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation physical accessibility visual artifact binding must be an object",
                result.stderr,
            )

    def test_interactive_workstation_rejects_accessibility_visual_environment_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "accessibility-and-visual")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["visual_artifact"]["environment_sha256"] = "d" * 64
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "physical accessibility visual artifact must bind the physical machine environment",
                result.stderr,
            )


    def test_interactive_workstation_rejects_accessibility_visual_display_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "accessibility-and-visual")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["visual_artifact"]["capture"]["connector"] = "HDMI-A-99"
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "physical accessibility visual artifact capture.connector must match an identified physical display",
                result.stderr,
            )

    def test_interactive_workstation_rejects_accessibility_visual_png_dimension_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "accessibility-and-visual")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            visual_path = root / attestation["visual_artifact"]["path"]
            visual_path.write_bytes(self._png_bytes(160, 90, pixel_value=96))
            attestation["visual_artifact"]["sha256"] = hashlib.sha256(visual_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "physical accessibility visual artifact PNG width does not match reviewed metadata",
                result.stderr,
            )

    def test_interactive_workstation_rejects_blank_accessibility_visual_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "accessibility-and-visual")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            visual_path = root / attestation["visual_artifact"]["path"]
            visual_path.write_bytes(self._png_bytes(320, 180, pixel_value=96))
            attestation["visual_artifact"]["sha256"] = hashlib.sha256(visual_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "must contain representative non-uniform rendered content",
                result.stderr,
            )

    def test_interactive_workstation_rejects_accessibility_visual_scale_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "accessibility-and-visual")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["visual_artifact"]["capture"]["scale"] = 2.0
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "physical accessibility visual artifact capture.scale must match the identified physical display",
                result.stderr,
            )

    def test_interactive_workstation_rejects_false_success_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "physical-session-start")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["observations"][0]["value"] = False
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must carry the typed success value True", result.stderr)

    def test_interactive_workstation_rejects_numeric_boolean_success_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "physical-session-start")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["observations"][0]["value"] = 1
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must carry the typed success value True", result.stderr)

    def test_interactive_workstation_case_requires_structured_runner_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = payload["cases"][0]
            old_path = root / case["evidence"]
            replacement = old_path.with_suffix(".txt")
            replacement.write_text("self-authored summary\n", encoding="utf-8")
            case["evidence"] = replacement.relative_to(root).as_posix()
            case["sha256"] = hashlib.sha256(replacement.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be a structured JSON runner attestation", result.stderr)


    def test_interactive_workstation_requires_digest_bound_physical_machine_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload.pop("machine_environment")
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation machine environment binding must be an object",
                result.stderr,
            )

    def test_interactive_workstation_rejects_virtualized_machine_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            environment_path = root / payload["machine_environment"]["path"]
            environment = json.loads(environment_path.read_text(encoding="utf-8"))
            environment["execution"]["kind"] = "virtual-machine"
            environment["execution"]["virtualization"] = "qemu"
            virtualization_probe = root / environment["probes"]["virtualization"]["path"]
            virtualization_probe.write_text("qemu\n", encoding="utf-8")
            environment["probes"]["virtualization"]["sha256"] = hashlib.sha256(
                virtualization_probe.read_bytes()
            ).hexdigest()
            environment_path.write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
            payload["machine_environment"]["sha256"] = hashlib.sha256(
                environment_path.read_bytes()
            ).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation machine environment execution.kind must be physical",
                result.stderr,
            )
            self.assertIn(
                "interactive workstation machine environment virtualization must be none",
                result.stderr,
            )

    def test_interactive_workstation_case_requires_external_execution_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "physical-session-start")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation.pop("machine_execution")
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interactive workstation case evidence physical-session-start missing machine_execution provenance",
                result.stderr,
            )

    def test_interactive_workstation_rejects_stale_execution_log_run_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_interactive_workstation_evidence(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "physical-session-start")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            provenance_path = root / attestation["machine_execution"]["provenance"]["path"]
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            event_log = root / provenance["event_log"]["path"]
            event_text = event_log.read_text(encoding="utf-8")
            event_log.write_text(
                event_text.replace(
                    f"run_id={payload['run_id']}\n",
                    "run_id=stale-physical-run\n",
                    1,
                ),
                encoding="utf-8",
            )
            provenance["event_log"]["sha256"] = hashlib.sha256(event_log.read_bytes()).hexdigest()
            provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
            attestation["machine_execution"]["provenance"]["sha256"] = hashlib.sha256(
                provenance_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old_digest = tomllib.loads(text)["interactive_workstation"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")

            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "machine execution event log must bind the case, controller, mechanism, environment, source, run, scope, and boot identity",
                result.stderr,
            )

    def test_q12_q13_release_matrix_runner_attestations_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            self._write_release_matrix_evidence(
                root,
                section="security_qualification",
                manifest_name="security-evidence.json",
                evidence_type="exact-source-q13-workstation-security",
                case_observations=self._q13_case_observations(),
            )
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_q12_release_matrix_rejects_unqualified_machine_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            environment_path = root / payload["machine_environment"]["evidence"]
            environment = json.loads(environment_path.read_text(encoding="utf-8"))
            environment["profile_id"] = "unrelated-host"
            environment_path.write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
            payload["machine_environment"]["sha256"] = hashlib.sha256(environment_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_release_matrix_contract_digest(
                root,
                section="update_recovery_qualification",
                manifest=manifest,
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("machine environment must bind arch-hyprland-v1", result.stderr)

    def test_q12_release_matrix_rejects_frozen_package_inventory_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            environment_path = root / payload["machine_environment"]["evidence"]
            environment = json.loads(environment_path.read_text(encoding="utf-8"))
            inventory_path = root / environment["package_inventory"]["path"]
            inventory = inventory_path.read_text(encoding="utf-8")
            self.assertIn("hyprland\t1:1.0.0-1", inventory)
            inventory_path.write_text(
                inventory.replace("hyprland\t1:1.0.0-1", "hyprland\t9.9.9", 1),
                encoding="utf-8",
            )
            environment["package_inventory"]["sha256"] = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
            environment_path.write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
            payload["machine_environment"]["sha256"] = hashlib.sha256(environment_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_release_matrix_contract_digest(
                root,
                section="update_recovery_qualification",
                manifest=manifest,
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("installed package inventory must exactly match the frozen package manifest", result.stderr)

    def test_q12_release_matrix_rejects_process_local_fault_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "power-loss-recovery")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            provenance_path = root / attestation["machine_execution"]["provenance"]["path"]
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            provenance["external_controller"] = False
            provenance["process_local_mock"] = True
            provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
            attestation["machine_execution"]["provenance"]["sha256"] = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_release_matrix_contract_digest(
                root,
                section="update_recovery_qualification",
                manifest=manifest,
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("machine execution provenance must prove external control", result.stderr)
            self.assertIn("process_local_mock must be false", result.stderr)

    def test_q12_release_matrix_rejects_unbound_nonempty_execution_log(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "crash-before-dispatch")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            provenance_path = root / attestation["machine_execution"]["provenance"]["path"]
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            event_log = root / provenance["event_log"]["path"]
            event_log.write_text("x\n", encoding="utf-8")
            provenance["event_log"]["sha256"] = hashlib.sha256(event_log.read_bytes()).hexdigest()
            provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
            attestation["machine_execution"]["provenance"]["sha256"] = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_release_matrix_contract_digest(
                root,
                section="update_recovery_qualification",
                manifest=manifest,
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "machine execution event log must bind the case, controller, mechanism, environment, source, run, scope, and boot identity",
                result.stderr,
            )

    def test_q12_restart_reobservation_requires_distinct_boot_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "restart-reobservation")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["machine_execution"]["post_boot_id"] = attestation["machine_execution"]["pre_boot_id"]
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_release_matrix_contract_digest(
                root,
                section="update_recovery_qualification",
                manifest=manifest,
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pre_boot_id and post_boot_id must differ", result.stderr)

    def test_q12_power_loss_recovery_requires_matching_recovered_boot_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "power-loss-recovery")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            provenance_path = root / attestation["machine_execution"]["provenance"]["path"]
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            post_boot_probe = root / provenance["post_boot_probe"]["path"]
            post_boot_probe.write_text(provenance["pre_boot_id"] + "\n", encoding="utf-8")
            provenance["post_boot_probe"]["sha256"] = hashlib.sha256(post_boot_probe.read_bytes()).hexdigest()
            provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
            attestation["machine_execution"]["provenance"]["sha256"] = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_release_matrix_contract_digest(
                root,
                section="update_recovery_qualification",
                manifest=manifest,
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("recovered boot probe must match post_boot_id", result.stderr)

    def test_q13_release_matrix_rejects_process_scoped_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="security_qualification",
                manifest_name="security-evidence.json",
                evidence_type="exact-source-q13-workstation-security",
                case_observations=self._q13_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            environment_path = root / payload["machine_environment"]["evidence"]
            environment = json.loads(environment_path.read_text(encoding="utf-8"))
            environment["execution"]["scope"] = "process"
            environment_path.write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
            payload["machine_environment"]["sha256"] = hashlib.sha256(environment_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_release_matrix_contract_digest(
                root,
                section="security_qualification",
                manifest=manifest,
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("machine environment execution.scope must be machine", result.stderr)

    def test_q12_legacy_partial_matrix_cannot_satisfy_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations={
                    "update-success": ["candidate-applied", "post-update-state-reobserved", "update-audit-bound"],
                    "migration-success": ["pre-migration-backup-created", "migration-completed", "persistent-state-reopened"],
                    "update-interruption-recovery": ["interruption-injected", "restart-detected-incomplete-update", "recovery-converged"],
                    "power-loss-recovery": ["power-loss-injected", "durable-state-recovered", "external-state-reconciled"],
                    "snapshot-rollback": ["snapshot-identified", "rollback-applied", "rollback-state-verified"],
                    "offline-repair": ["network-unavailable", "gui-unavailable", "local-repair-completed"],
                },
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must contain exactly the required cases", result.stderr)

    def test_q13_legacy_partial_matrix_cannot_satisfy_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_release_matrix_evidence(
                root,
                section="security_qualification",
                manifest_name="security-evidence.json",
                evidence_type="exact-source-q13-workstation-security",
                case_observations={
                    "privilege-boundary": ["unprivileged-daemon-confirmed", "generic-root-shell-absent", "privileged-effect-denied-without-authority"],
                    "polkit-authorization": ["polkit-policy-loaded", "unauthorized-caller-denied", "authorized-caller-bound"],
                    "untrusted-package-source-denied": ["untrusted-source-presented", "source-rejected", "no-package-effect-dispatched"],
                    "secret-redaction": ["secret-bearing-input-injected", "audit-redacted", "diagnostics-redacted"],
                    "adversarial-input": ["malformed-input-rejected", "authority-not-widened", "no-effect-dispatched"],
                    "recovery-boundary": ["gui-unavailable", "model-unavailable", "native-recovery-remains-available"],
                },
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must contain exactly the required cases", result.stderr)

    def test_q12_release_matrix_rejects_false_success_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "power-loss-recovery")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["observations"][0]["value"] = False
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old = tomllib.loads(text)["update_recovery_qualification"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must carry boolean true", result.stderr)

    def test_q12_release_matrix_rejects_missing_runner_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="update_recovery_qualification",
                manifest_name="update-recovery-evidence.json",
                evidence_type="exact-source-q12-update-recovery",
                case_observations=self._q12_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = payload["cases"][0]
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            del attestation["runner"]
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old = tomllib.loads(text)["update_recovery_qualification"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing runner provenance", result.stderr)

    def test_q13_release_matrix_rejects_incomplete_case_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_release_matrix_evidence(
                root,
                section="security_qualification",
                manifest_name="security-evidence.json",
                evidence_type="exact-source-q13-workstation-security",
                case_observations=self._q13_case_observations(),
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(item for item in payload["cases"] if item["name"] == "adversarial-input")
            evidence_path = root / case["evidence"]
            attestation = json.loads(evidence_path.read_text(encoding="utf-8"))
            attestation["observations"] = attestation["observations"][:-1]
            evidence_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            old = tomllib.loads(text)["security_qualification"]["evidence_manifest_sha256"]
            contract.write_text(text.replace(old, digest, 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("observation set does not prove the required case", result.stderr)

    def test_profile_cannot_self_promote_before_release_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            profile = root / "profiles/arch-hyprland-v1.toml"
            profile.write_text(
                profile.read_text(encoding="utf-8").replace(
                    'status = "development"',
                    'status = "release-qualified"',
                    1,
                ),
                encoding="utf-8",
            )
            self._refresh_profile_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must remain development", result.stderr)

    def test_support_matrix_cannot_promote_target_profile_early(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            matrix = root / "hardware/support-matrix.json"
            payload = json.loads(matrix.read_text(encoding="utf-8"))
            payload["machine_classes"]["workstation"]["release_qualified_profiles"] = [
                "arch-hyprland-v1"
            ]
            matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot be release-qualified", result.stderr)

    def test_protected_post_release_closure_accepts_status_only_profile_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)

            roadmap = root / "contracts/roadmap.toml"
            roadmap_text = roadmap.read_text(encoding="utf-8")
            milestone_marker = 'version = "v0.10.0"\ntitle = "complete Experimental Linura workstation"\nstatus = "planned"'
            self.assertIn(milestone_marker, roadmap_text)
            roadmap.write_text(
                roadmap_text.replace(
                    milestone_marker,
                    'version = "v0.10.0"\ntitle = "complete Experimental Linura workstation"\nstatus = "released"',
                    1,
                ),
                encoding="utf-8",
            )

            profile = root / "profiles/arch-hyprland-v1.toml"
            qualified_digest = hashlib.sha256(profile.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            contract_text = contract.read_text(encoding="utf-8")
            current_digest = tomllib.loads(contract_text)["profile_sha256"]
            self.assertEqual(current_digest, qualified_digest)
            profile.write_text(
                profile.read_text(encoding="utf-8").replace(
                    'status = "development"',
                    'status = "release-qualified"',
                    1,
                ),
                encoding="utf-8",
            )

            matrix = root / "hardware/support-matrix.json"
            payload = json.loads(matrix.read_text(encoding="utf-8"))
            payload["machine_classes"]["workstation"]["release_qualified_profiles"] = [
                "arch-hyprland-v1"
            ]
            matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)

            profile.write_text(
                profile.read_text(encoding="utf-8").replace(
                    'network = "networkmanager"',
                    'network = "systemd-networkd"',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "content does not match the qualification-bound profile_sha256",
                result.stderr,
            )

    def test_profile_provider_identity_cannot_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            profile = root / "profiles/arch-hyprland-v1.toml"
            profile.write_text(
                profile.read_text(encoding="utf-8").replace(
                    'network = "networkmanager"',
                    'network = "systemd-networkd"',
                    1,
                ),
                encoding="utf-8",
            )
            self._refresh_profile_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("provider identity drifted", result.stderr)

    def test_mutable_archive_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                'repository_url = "https://archive.archlinux.org/repos/2026/09/16/$repo/os/$arch"',
                'repository_url = "https://archive.archlinux.org/repos/last/$repo/os/$arch"',
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exact dated Arch Linux Archive", result.stderr)

    def test_pending_package_set_cannot_claim_release_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                "release_qualification_ready = false",
                "release_qualification_ready = true",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot be release_qualification_ready", result.stderr)

    def test_frozen_package_set_requires_digest_bound_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                'state = "source-pinned-package-set-pending"',
                'state = "frozen"',
            )
            self._rewrite_contract(
                root,
                "release_qualification_ready = false",
                "release_qualification_ready = true",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires package_manifest", result.stderr)
            self.assertIn("requires lowercase package_manifest_sha256", result.stderr)

    def test_frozen_package_manifest_requires_typed_required_package_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_frozen_manifest(root, omit="hyprland")
            self._freeze_contract(root, manifest)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing required versioned packages: hyprland", result.stderr)

    def test_frozen_package_manifest_rejects_empty_or_unrelated_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "qualification/v010/arch-packages.tsv"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text("", encoding="utf-8")
            self._freeze_contract(root, manifest)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("identity headers", result.stderr)

    def test_frozen_package_manifest_rejects_malformed_or_nonofficial_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_frozen_manifest(root)
            text = manifest.read_text(encoding="utf-8")
            first_record = text.splitlines()[3]
            manifest.write_text(
                text.replace(first_record, first_record.replace("core\t", "aur\t", 1), 1),
                encoding="utf-8",
            )
            self._freeze_contract(root, manifest)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-official repository", result.stderr)

    def test_frozen_package_manifest_must_live_in_qualification_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_frozen_manifest(root)
            self._freeze_contract(root, manifest)
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            contract.write_text(
                text.replace(
                    'package_manifest = "qualification/v010/arch-packages.tsv"',
                    'package_manifest = "docs/qualification/v0.10.0.md"',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be a .tsv file under qualification/v010/", result.stderr)

    def test_frozen_package_manifest_digest_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_frozen_manifest(root)
            self._freeze_contract(root, manifest)
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)

            manifest.write_text(
                manifest.read_text(encoding="utf-8") + "extra\tzstd\t1.0-1\tx86_64\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("package manifest digest mismatch", result.stderr)

    def test_experience_evidence_cannot_be_ready_with_null_visual_baselines(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "visual/baselines/manifest.json"
            manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self._rewrite_contract(
                root,
                'visual_baseline_manifest_sha256 = ""',
                f'visual_baseline_manifest_sha256 = "{manifest_digest}"',
            )
            self._rewrite_contract(
                root,
                "experience_evidence_ready = false",
                "experience_evidence_ready = true",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("visual baseline artifact", result.stderr)

    def test_nonexistent_visual_baseline_strings_do_not_satisfy_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "visual/baselines/manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            for item in payload["baselines"]:
                item["baseline"] = f"visual/baselines/{item['id']}.png"
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self._rewrite_contract(
                root,
                'visual_baseline_manifest_sha256 = ""',
                f'visual_baseline_manifest_sha256 = "{manifest_digest}"',
            )
            self._rewrite_contract(
                root,
                "experience_evidence_ready = false",
                "experience_evidence_ready = true",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing or not a regular file", result.stderr)

    def test_experience_readiness_requires_all_product_slices(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            slices = root / "contracts/v010-workstation-slices.toml"
            text = slices.read_text(encoding="utf-8")
            parts = text.split("[[slice]]")
            rewritten = [parts[0]]
            for block in parts[1:]:
                if 'id = "S28"' in block:
                    block = block.replace('status = "complete"', 'status = "planned"', 1)
                    block = block.replace("evidence_prs = [999]", "evidence_prs = []", 1)
                rewritten.append("[[slice]]" + block)
            text = "".join(rewritten)
            text = text.replace("completed_slice_count = 28", "completed_slice_count = 27", 1)
            text = text.replace('next_slice = "S29"', 'next_slice = "S28"', 1)
            slices.write_text(text, encoding="utf-8")

            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "experience evidence cannot be ready until product slices S01-S28 are complete: S28",
                result.stderr,
            )

    def test_complete_artifact_backed_experience_evidence_can_become_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)


    def test_q10_rejects_blank_reviewed_visual_baseline_and_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            baseline_manifest_path = root / "visual/baselines/manifest.json"
            baseline_manifest = json.loads(baseline_manifest_path.read_text(encoding="utf-8"))
            baseline = next(item for item in baseline_manifest["baselines"] if item["id"] == "firstboot-1280x800-2x")
            baseline_path = root / baseline["baseline"]
            baseline_path.write_bytes(self._png_bytes(int(baseline["width"]), int(baseline["height"]), pixel_value=0))
            baseline["sha256"] = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
            baseline_manifest_path.write_text(json.dumps(baseline_manifest, indent=2) + "\n", encoding="utf-8")
            self._refresh_visual_baseline_manifest_digest(root)

            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = next(item for item in evidence["visual_comparisons"] if item["baseline_id"] == baseline["id"])
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(self._png_bytes(int(baseline["width"]), int(baseline["height"]), pixel_value=0))
            comparison["capture_sha256"] = hashlib.sha256(capture_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            self._refresh_experience_evidence_digest(root)

            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("visual baseline artifact firstboot-1280x800-2x must contain representative non-uniform rendered content", result.stderr)
            self.assertIn("visual capture for firstboot-1280x800-2x must contain representative non-uniform rendered content", result.stderr)

    def test_q10_requires_surface_specific_functional_workflow_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            record = next(item for item in evidence["interaction_accessibility"] if item["surface"] == "network-connectivity")
            report_path = root / record["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["workflow_observations"].pop("post-effect-network-state-reobserved")
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            record["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            self._refresh_experience_evidence_digest(root)

            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("interaction/accessibility report network-connectivity must contain exactly the required workflow observations", result.stderr)

    def test_q10_requires_focus_navigation_for_every_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            record = next(
                item for item in evidence["interaction_accessibility"]
                if item["surface"] == "personalization"
            )
            report_path = root / record["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["checks"].pop("focus_navigation")
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            record["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            self._refresh_experience_evidence_digest(root)

            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interaction/accessibility report personalization checks.focus_navigation must be pass",
                result.stderr,
            )

    def test_q10_overlay_input_regions_must_pass_through_and_remain_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

            for surface, key, value in (
                ("notifications-osd", "noninteractive_regions", "captures-full-screen"),
                ("command-palette", "interactive_regions", "full-screen"),
            ):
                record = next(
                    item for item in evidence["interaction_accessibility"]
                    if item["surface"] == surface
                )
                report_path = root / record["report"]
                report = json.loads(report_path.read_text(encoding="utf-8"))
                report["input_region"][key] = value
                report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                record["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()

            evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            self._refresh_experience_evidence_digest(root)

            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interaction/accessibility report notifications-osd must bind pass-through noninteractive regions and bounded interactive controls",
                result.stderr,
            )
            self.assertIn(
                "interaction/accessibility report command-palette must bind pass-through noninteractive regions and bounded interactive controls",
                result.stderr,
            )

    def test_q10_authority_evidence_requires_exact_case_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            manifest = root / "qualification/v010/experience/authority-evidence.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["cases"] = [
                case
                for case in payload["cases"]
                if case["name"] != "restart-during-managed-mutation"
            ]
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_q10_authority_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Q10 experience authority/adversarial evidence must contain exactly the required cases",
                result.stderr,
            )

    def test_q10_authority_evidence_rejects_false_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            manifest = root / "qualification/v010/experience/authority-evidence.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            case = next(
                item
                for item in payload["cases"]
                if item["name"] == "operation-class-downgrade-rejection"
            )
            evidence_path = root / case["evidence"]
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["observations"][0]["value"] = False
            evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            case["sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self._refresh_q10_authority_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Q10 experience authority/adversarial case operation-class-downgrade-rejection observation stronger-effect-presented-as-transient must carry boolean true",
                result.stderr,
            )

    def test_experience_evidence_must_match_expected_release_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            result = self._run(
                root,
                expected_source_sha="dddddddddddddddddddddddddddddddddddddddd",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "v0.10 experience evidence source_commit_sha does not match the expected release source",
                result.stderr,
            )

    def test_interaction_report_must_bind_parent_experience_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            record = evidence["interaction_accessibility"][0]
            report_path = root / record["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["source_commit_sha"] = "d" * 40
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            record["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "source must match the experience evidence manifest",
                result.stderr,
            )

    def test_experience_evidence_manifest_digest_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence = root / "qualification/v010/experience-evidence.json"
            evidence.write_text(
                evidence.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("experience evidence manifest digest mismatch", result.stderr)

    def test_truncated_digest_valid_png_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(self._png_bytes(1280, 800)[:33])
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing IDAT image data", result.stderr)

    def test_visual_pass_requires_independent_pixel_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(
                self._png_bytes(1280, 800, pixel_value=255)
            )
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "visual comparison for firstboot-1280x800-1x does not match baseline pixels",
                result.stderr,
            )

    def test_png_transparency_is_part_of_pixel_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(
                self._png_bytes(1280, 800, pixel_value=0, transparent_gray=0)
            )
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "visual comparison for firstboot-1280x800-1x does not match baseline pixels",
                result.stderr,
            )

    def test_png_color_management_metadata_is_rejected_before_pixel_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(
                self._png_bytes(
                    1280,
                    800,
                    ancillary_chunks=((b"gAMA", struct.pack(">I", 45455)),),
                )
            )
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsupported color-management PNG chunk gAMA", result.stderr)

    def test_png_overlong_inflate_is_rejected_under_declared_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(
                self._png_bytes(1280, 800, extra_raw_bytes=4 * 1024 * 1024)
            )
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("overlong PNG image data", result.stderr)

    def test_retained_failure_diff_must_bind_an_actual_failed_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            failure = evidence["retained_failure_diffs"][0]
            baseline_manifest = json.loads(
                (root / "visual/baselines/manifest.json").read_text(encoding="utf-8")
            )
            baseline = next(
                item
                for item in baseline_manifest["baselines"]
                if item["id"] == failure["baseline_id"]
            )
            baseline_path = root / baseline["baseline"]
            failed_capture_path = root / failure["failed_capture"]
            failed_capture_path.write_bytes(baseline_path.read_bytes())
            failure["failed_capture_sha256"] = hashlib.sha256(
                failed_capture_path.read_bytes()
            ).hexdigest()
            failure["binding_sha256"] = self._visual_failure_binding(
                failure["baseline_id"],
                failure["baseline_sha256"],
                failure["failed_capture_sha256"],
                failure["diff_sha256"],
            )
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not represent an actual failed pixel comparison", result.stderr)

    def test_retained_failure_diff_pixels_must_match_bound_failed_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            failure = evidence["retained_failure_diffs"][0]
            baseline_manifest = json.loads(
                (root / "visual/baselines/manifest.json").read_text(encoding="utf-8")
            )
            baseline = next(
                item
                for item in baseline_manifest["baselines"]
                if item["id"] == failure["baseline_id"]
            )
            baseline_path = root / baseline["baseline"]
            diff_path = root / failure["diff"]
            diff_path.write_bytes(baseline_path.read_bytes())
            failure["diff_sha256"] = hashlib.sha256(diff_path.read_bytes()).hexdigest()
            failure["binding_sha256"] = self._visual_failure_binding(
                failure["baseline_id"],
                failure["baseline_sha256"],
                failure["failed_capture_sha256"],
                failure["diff_sha256"],
            )
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "pixels do not match the canonical failed-pair diff",
                result.stderr,
            )

    def test_accessibility_claims_require_digest_bound_runner_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            record = evidence["interaction_accessibility"][0]
            report_path = root / record["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["checks"]["screen_reader"] = "fail"
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            record["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interaction/accessibility report linura-firstboot checks.screen_reader must be pass",
                result.stderr,
            )

    def test_experience_artifact_digest_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            baseline = root / "visual/baselines/firstboot-1280x800-1x.png"
            baseline.write_bytes(self._png_bytes(640, 480))
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("visual baseline artifact firstboot-1280x800-1x digest mismatch", result.stderr)

    def test_experience_requires_visual_baselines_for_every_supported_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            manifest = root / "visual/baselines/manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["baselines"] = [
                item
                for item in payload["baselines"]
                if item["surface"] != "notifications-osd"
            ]
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            data = tomllib.loads(contract.read_text(encoding="utf-8"))
            old_digest = data["experience"]["visual_baseline_manifest_sha256"]
            contract.write_text(
                contract.read_text(encoding="utf-8").replace(old_digest, digest, 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("visual baseline coverage missing required surfaces: notifications-osd", result.stderr)

    def test_interaction_adr_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "docs/adr/0031-v010-many-interfaces-one-authority-path.md").unlink()
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("interaction ADR 0031 is missing", result.stderr)

    def test_product_scope_adr_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "docs/adr/0033-v010-complete-workstation-product-boundary.md").unlink()
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("product-scope ADR 0033 is missing", result.stderr)

    def test_operation_semantics_contract_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "contracts/operation-semantics.toml").unlink()
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("operation-semantics contract file is missing", result.stderr)

    def test_roadmap_must_bind_machine_readable_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            roadmap = root / "contracts/roadmap.toml"
            roadmap.write_text(
                roadmap.read_text(encoding="utf-8").replace(
                    'qualification_contract = "contracts/v010-workstation-qualification.toml"\n',
                    "",
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qualification_contract must point", result.stderr)


if __name__ == "__main__":
    unittest.main()
