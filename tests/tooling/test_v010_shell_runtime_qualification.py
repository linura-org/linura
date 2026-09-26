from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

FIXTURE_PATHS = (
    "contracts/v010-shell-runtime-qualification.toml",
    "contracts/v010-shell-runtime-substrate.toml",
    "contracts/v010-workstation-qualification.toml",
    ".github/workflows/v010-shell-runtime-qualification.yml",
    ".github/workflows/v010-qualification.yml",
    "packaging/systemd/user/linura-shell.service",
    "packaging/systemd/user/linurad.service",
    "packaging/wireplumber/linura-session-audio.lua",
    "packaging/arch/archiso/packages.linura",
    "apps/linurad/Cargo.toml",
    "crates/linura-agent-runtime/Cargo.toml",
    "crates/linura-capability-sdk/Cargo.toml",
    "crates/linura-control/Cargo.toml",
    "crates/linura-core/Cargo.toml",
    "crates/linura-dbus/Cargo.toml",
    "crates/linura-graph/Cargo.toml",
    "crates/linura-hardware/Cargo.toml",
    "crates/linura-intent/Cargo.toml",
    "crates/linura-library/Cargo.toml",
    "crates/linura-lifecycle/Cargo.toml",
    "crates/linura-linux-observation/Cargo.toml",
    "crates/linura-observation/Cargo.toml",
    "crates/linura-observation-control/Cargo.toml",
    "crates/linura-planner/Cargo.toml",
    "crates/linura-policy/Cargo.toml",
    "crates/linura-protocol/Cargo.toml",
    "crates/linura-provenance/Cargo.toml",
    "crates/linura-provider-sdk/Cargo.toml",
    "crates/linura-transaction/Cargo.toml",
    "apps/linura-shell/qualification-controller.qml",
    "apps/linura-shell/qualification-palette.qml",
    "apps/linura-shell/qualification-quick-settings.qml",
    "apps/linura-shell/bridge/CMakeLists.txt",
    "apps/linura-shell/bridge/audio_session_controller.h",
    "apps/linura-shell/bridge/audio_session_controller.cpp",
    "apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml",
    "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml",
    "apps/linura-shell/plugins/command-palette/CommandPalette.qml",
    "apps/linura-shell/ui/CMakeLists.txt",
    "qualification/v010/shell-runtime/provision-shell-runtime.sh",
    "qualification/v010/shell-runtime/run-shell-runtime.sh",
    "qualification/v010/shell-runtime/start-vm.sh",
    "qualification/v010/shell-runtime/prepare-substrate.sh",
    "qualification/v010/shell-runtime/verify-substrate.py",
    "qualification/v010/shell-runtime/fixtures/linger-app",
    "qualification/v010/shell-runtime/fixtures/forking-app",
    "qualification/v010/shell-runtime/fixtures/linura-shell-qualification.service",
    "qualification/v010/shell-runtime/fixtures/linura-palette-qualification.service",
    "qualification/v010/shell-runtime/fixtures/linura-quick-settings-qualification.service",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationVisible.desktop",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationHidden.desktop",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationTerminal.desktop",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationForking.desktop",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationStale.desktop",
)


class V010ShellRuntimeQualificationTests(unittest.TestCase):
    def _copy_fixture(self, root: Path) -> None:
        for relative in FIXTURE_PATHS:
            source = ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def _run(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/check_v010_shell_runtime_qualification.py"),
                str(root),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_runtime_qualification_contract_is_valid(self) -> None:
        result = self._run(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_substrate_cache_policy_cannot_cache_qualification_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            substrate = root / "contracts/v010-shell-runtime-substrate.toml"
            text = substrate.read_text(encoding="utf-8")
            marker = "qualification_evidence = false"
            self.assertIn(marker, text)
            substrate.write_text(
                text.replace(marker, "qualification_evidence = true", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cache_policy.qualification_evidence", result.stderr)

    def test_substrate_cache_policy_cannot_cache_linura_build_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            substrate = root / "contracts/v010-shell-runtime-substrate.toml"
            text = substrate.read_text(encoding="utf-8")
            marker = "linura_build_outputs = false"
            self.assertIn(marker, text)
            substrate.write_text(
                text.replace(marker, "linura_build_outputs = true", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cache_policy.linura_build_outputs", result.stderr)

    def test_builder_prepared_cache_key_must_bind_contract_and_builder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "key: linura-v010-prepared-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('contracts/v010-shell-runtime-substrate.toml', 'qualification/v010/shell-runtime/prepare-substrate.sh') }}"
            self.assertGreaterEqual(text.count(marker), 2)
            workflow.write_text(
                text.replace(marker, "key: linura-v010-prepared-v1-unbound", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prepared runtime cache key must bind", result.stderr)

    def test_runtime_prepared_cache_key_must_bind_contract_and_builder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "key: linura-v010-prepared-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('contracts/v010-shell-runtime-substrate.toml', 'qualification/v010/shell-runtime/prepare-substrate.sh') }}"
            index = text.rfind(marker)
            self.assertGreaterEqual(index, 0)
            workflow.write_text(
                text[:index] + "key: linura-v010-prepared-v1-unbound" + text[index + len(marker):],
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prepared runtime cache key must bind", result.stderr)

    def test_builder_cached_base_image_must_still_be_digest_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "if [[ -f \"$image\" ]] && ! printf '%s  %s\\n' \"$digest\" \"$image\" | sha256sum --check --strict; then"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, 'if [[ -f "$image" ]]; then', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("digest-verify a restored official base image", result.stderr)

    def test_substrate_must_include_pipewire_audio_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            substrate = root / "contracts/v010-shell-runtime-substrate.toml"
            text = substrate.read_text(encoding="utf-8")
            marker = '  "pipewire-audio",\n'
            self.assertIn(marker, text)
            substrate.write_text(text.replace(marker, "", 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("runtime_packages", result.stderr)

    def test_prepared_substrate_builder_must_install_contract_package_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            builder = root / "qualification/v010/shell-runtime/prepare-substrate.sh"
            text = builder.read_text(encoding="utf-8")
            marker = "pacman -Syu"
            self.assertIn(marker, text)
            builder.write_text(
                text.replace(marker, "pacman -S", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prepared substrate builder missing fail-closed invariant", result.stderr)

    def test_runtime_package_evidence_must_include_pipewire_audio_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = "seatd pipewire pipewire-audio wireplumber networkmanager sqlite"
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, "seatd pipewire wireplumber networkmanager sqlite", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pipewire-audio", result.stderr)

    def test_pipewire_fixture_must_be_declarative_and_daemon_owned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            self.assertIn("context.objects = [", text)
            self.assertIn("factory.name = support.null-audio-sink", text)
            self.assertIn("monitor.channel-volumes = true", text)
            self.assertIn("monitor.passthrough = true", text)
            self.assertIn("adapter.auto-port-config = {", text)
            self.assertIn("node.param.Props = {", text)
            self.assertIn("channelVolumes = [ 0.064 0.064 ]", text)
            self.assertNotIn("pw-cli create-node adapter", text)
            script.write_text(
                text.replace("context.objects = [", "context.objects_disabled = [", 1)
                + "\npw-cli create-node adapter\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("daemon-owned declarative context.objects", result.stderr)

    def test_pipewire_fixture_must_be_installed_before_pipewire_starts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            fixture = "context.objects = ["
            start = "systemctl --user start pipewire.service"
            self.assertLess(text.index(fixture), text.index(start))
            script.write_text(
                text.replace(fixture, "context.objects_disabled = [", 1)
                + "\ncontext.objects = [\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be installed before PipeWire starts", result.stderr)

    def test_pipewire_fixture_must_enable_monitor_channel_volumes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = "      monitor.channel-volumes = true\n"
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, "", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("monitor.channel-volumes = true", result.stderr)

    def test_pipewire_fixture_must_expose_mixer_controllable_props(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = """      node.param.Props = {
        mute = false
        channelVolumes = [ 0.064 0.064 ]
      }
"""
            self.assertIn(marker, text)
            script.write_text(text.replace(marker, "", 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("node.param.Props = {", result.stderr)

    def test_prepared_substrate_builder_must_sanitize_guest_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            builder = root / "qualification/v010/shell-runtime/prepare-substrate.sh"
            text = builder.read_text(encoding="utf-8")
            marker = "cloud-init clean --logs --seed"
            self.assertIn(marker, text)
            builder.write_text(
                text.replace(marker, "cloud-init clean", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prepared substrate builder missing fail-closed invariant", result.stderr)

    def test_pipewire_fixture_must_discover_identity_without_production_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = "pipewire_fixture_identity()"
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, "audio_snapshot()", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("PipeWire fixture readiness stages", result.stderr)

    def test_pipewire_fixture_must_establish_props_before_helper_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'pw-cli set-param "$qualification_sink_id" Props'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'printf "Props not established"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pw-cli set-param", result.stderr)

    def test_pipewire_fixture_must_verify_props_in_retained_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'pw-cli enum-params "$qualification_sink_id" Props > "$evidence_root/pipewire-fixture-props.txt"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(
                    marker,
                    'pw-cli enum-params "$qualification_sink_id" Props >/dev/null',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pipewire-fixture-props.txt", result.stderr)

    def test_pipewire_fixture_must_wait_for_wireplumber_mixer_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'wpctl get-volume "$qualification_sink_id"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, "true # mixer readiness bypassed", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("wpctl get-volume", result.stderr)

    def test_qualified_runtime_must_not_use_wpctl_for_volume_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            script.write_text(
                text + '\nwpctl set-volume "$qualification_sink_id" 50%\n',
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not use wpctl set-volume", result.stderr)

    def test_pipewire_fixture_failure_must_retain_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = '} > "$evidence_root/pipewire-fixture-diagnostics.txt" 2>&1'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(
                    marker,
                    '} > "$evidence_root/discarded-pipewire-diagnostics.txt" 2>&1',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pipewire-fixture-diagnostics.txt", result.stderr)

    def test_runtime_must_not_cache_qualification_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8")
                + "\n# linura-v010-evidence-cache\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not cache evidence or Linura build outputs", result.stderr)

    def test_parent_contract_and_runtime_must_remain_parallel(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "  shell-runtime:\n    name: v0.10 shell runtime qualification\n"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, marker + "    needs: contract\n", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("parallel independent gates", result.stderr)

    def test_runtime_cargo_cache_must_not_include_target_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "            ~/.cargo/git/db\n"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, marker + "            target\n", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Linura build outputs", result.stderr)

    def test_mutable_latest_arch_image_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/v010-shell-runtime-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            text = text.replace(
                "images/v20260915.594445/Arch-Linux-x86_64-cloudimg-20260915.594445.qcow2",
                "images/latest/Arch-Linux-x86_64-cloudimg.qcow2",
            )
            contract.write_text(text, encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("version-addressed", result.stderr)

    def test_vm_launcher_cannot_drop_virtio_gpu(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            launcher = root / "qualification/v010/shell-runtime/start-vm.sh"
            text = launcher.read_text(encoding="utf-8")
            marker = "-device virtio-gpu-pci"
            self.assertIn(marker, text)
            launcher.write_text(
                text.replace(marker, "-device graphical-device-omitted", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("virtio-gpu-pci", result.stderr)

    def test_vm_launcher_cannot_drift_qualification_nic_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            launcher = root / "qualification/v010/shell-runtime/start-vm.sh"
            text = launcher.read_text(encoding="utf-8")
            marker = "mac=$nic_mac"
            self.assertIn(marker, text)
            launcher.write_text(
                text.replace(marker, "mac=52:54:00:12:34:57", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mac=$nic_mac", result.stderr)

    def test_cloud_init_network_cannot_drift_from_qualification_nic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = 'macaddress: "$QUALIFICATION_NIC_MAC"'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, 'name: "en*"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('macaddress: "$QUALIFICATION_NIC_MAC"', result.stderr)

    def test_runtime_workflow_cannot_drop_guest_disk_growth_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = 'qemu-img resize "$vm_image" "${QUALIFICATION_DISK_GIB}G"'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, 'qemu-img info "$vm_image"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qemu-img resize", result.stderr)

    def test_pinned_archive_transport_must_remain_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            builder = root / "qualification/v010/shell-runtime/prepare-substrate.sh"
            text = builder.read_text(encoding="utf-8")
            marker = "timeout --signal=TERM --kill-after=10s 720"
            self.assertIn(marker, text)
            builder.write_text(
                text.replace(marker, "sudo -n", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("kill-after=10s 720", result.stderr)

    def test_runtime_workflow_cannot_depend_on_shared_vm_harness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "bash qualification/v010/shell-runtime/start-vm.sh"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, "python3 tools/vm.py start", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("shared disposable VM harness", result.stderr)

    def test_shell_sandbox_cannot_be_weakened(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            service = (
                root
                / "qualification/v010/shell-runtime/fixtures/linura-shell-qualification.service"
            )
            text = service.read_text(encoding="utf-8")
            marker = "RestrictAddressFamilies=AF_UNIX"
            self.assertIn(marker, text)
            service.write_text(
                text.replace(marker, "RestrictAddressFamilies=AF_UNIX AF_INET", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must preserve production shell sandbox line", result.stderr)

    def test_guest_graphics_failure_diagnostics_cannot_be_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = '"$ARTIFACT_DIR/seat-drm-setup.log"'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, '"$ARTIFACT_DIR/silent-seat-setup.log"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("seat-drm-setup.log", result.stderr)

    def test_headless_seatd_contract_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "Environment=SEATD_VTBOUND=0"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, "true", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SEATD_VTBOUND=0", result.stderr)

    def test_hyprland_ipc_readiness_must_remain_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'hyprland_ipc_deadline=$((SECONDS + 45))'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'hyprland_ipc_deadline=$SECONDS', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SECONDS + 45", result.stderr)

    def test_runtime_must_exclude_drm_connector_entries_from_card_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = '[[ "$card_name" =~ ^card[0-9]+$ ]] || continue'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, '[[ "$card_name" == card* ]] || continue', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("^card[0-9]+$", result.stderr)

    def test_runtime_cannot_accept_an_unbound_drm_card_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'qualification_gpu_device_id="0x1050"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'qualification_gpu_device_id="0x1041"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('qualification_gpu_device_id="0x1050"', result.stderr)

    def test_seat_backend_cannot_be_weakened(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = "export LIBSEAT_BACKEND=seatd"
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, "export LIBSEAT_BACKEND=logind", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("LIBSEAT_BACKEND=seatd", result.stderr)

    def test_seat_runtime_case_cannot_disappear(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'pass_case "seat-drm-readiness"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'echo "seat readiness omitted"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("seat-drm-readiness", result.stderr)

    def test_required_runtime_case_cannot_disappear(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'pass_case "shell-service-restart-survival"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'echo "case omitted"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("shell-service-restart-survival", result.stderr)

    def test_runtime_workflow_cannot_be_continue_on_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "    timeout-minutes: 90\n"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, marker + "    continue-on-error: true\n", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("continue-on-error:", result.stderr)

    def test_parent_v010_workflow_must_trigger_on_session_authority_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = '      - "apps/linurad/**"'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, '      - "apps/unrelated/**"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("apps/linurad/**", result.stderr)

    def test_parent_v010_workflow_must_trigger_on_protocol_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = '      - "crates/linura-protocol/**"'
            self.assertIn(marker, text)
            workflow.write_text(text.replace(marker + "\n", "", 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("crates/linura-protocol/**", result.stderr)

    def test_production_arch_profile_must_ship_qualified_pipewire_audio(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            packages = root / "packaging/arch/archiso/packages.linura"
            lines = packages.read_text(encoding="utf-8").splitlines()
            self.assertIn("pipewire-audio", lines)
            packages.write_text(
                "\n".join(line for line in lines if line != "pipewire-audio") + "\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "production Arch package contract must include pipewire-audio",
                result.stderr,
            )

    def test_parent_v010_workflow_must_cover_transitive_linurad_dependency_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = '      - "crates/linura-graph/**"'
            self.assertIn(marker, text)
            workflow.write_text(text.replace(marker + "\n", "", 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                'missing linurad local dependency trigger: "crates/linura-graph/**"',
                result.stderr,
            )

    def test_parent_v010_workflow_must_call_runtime_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "uses: ./.github/workflows/v010-shell-runtime-qualification.yml"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, "uses: ./.github/workflows/v09-qualification.yml", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("parent qualification workflow", result.stderr)


    def test_vm_launcher_must_pin_qualification_gpu_pci_slot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            launcher = root / "qualification/v010/shell-runtime/start-vm.sh"
            text = launcher.read_text(encoding="utf-8")
            marker = "virtio-gpu-pci,id=linura-qualification-gpu,bus=pcie.0,addr=0x2"
            self.assertIn(marker, text)
            launcher.write_text(
                text.replace(marker, "virtio-gpu-pci,id=linura-qualification-gpu", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bus=pcie.0,addr=0x2", result.stderr)

    def test_gpu_identity_contract_cannot_drift_from_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/v010-shell-runtime-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            marker = 'vm_gpu_device_id = "0x1050"'
            self.assertIn(marker, text)
            contract.write_text(
                text.replace(marker, 'vm_gpu_device_id = "0x1041"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("vm_gpu_device_id", result.stderr)

    def test_vm_launcher_must_disable_implicit_vga(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            launcher = root / "qualification/v010/shell-runtime/start-vm.sh"
            text = launcher.read_text(encoding="utf-8")
            marker = "-vga none"
            self.assertIn(marker, text)
            launcher.write_text(
                text.replace(marker, "-vga std", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bounded graphical VM contract: -vga none", result.stderr)

    def test_seat_setup_pipeline_status_must_be_snapshotted_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = 'seat_setup_pipeline_status=("${PIPESTATUS[@]}")'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(
                    marker,
                    'seat_setup_status="${PIPESTATUS[0]}"\n'
                    '          seat_setup_tee_status="${PIPESTATUS[1]}"',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("seat_setup_pipeline_status", result.stderr)


    def test_controller_adapter_must_use_quickshell_root_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = root / "apps/linura-shell/qualification-controller.qml"
            text = controller.read_text(encoding="utf-8")
            marker = "import qs.integrations.xdg as Xdg"
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(
                    marker,
                    'import "../../../../apps/linura-shell/integrations/xdg" as Xdg',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qs.integrations.xdg", result.stderr)

    def test_palette_adapter_must_use_quickshell_root_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/qualification-palette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = 'import "plugins/command-palette" as Palette'
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(
                    marker,
                    'import "../../../../apps/linura-shell/plugins/command-palette" as Palette',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("plugins/command-palette", result.stderr)

    def test_qualification_service_must_launch_shell_root_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            service = (
                root
                / "qualification/v010/shell-runtime/fixtures/linura-shell-qualification.service"
            )
            text = service.read_text(encoding="utf-8")
            marker = (
                "ExecStart=/usr/bin/quickshell -n -p "
                "/opt/linura-source/apps/linura-shell/qualification-controller.qml"
            )
            self.assertIn(marker, text)
            service.write_text(
                text.replace(
                    marker,
                    "ExecStart=/usr/bin/quickshell -n -p "
                    "/opt/linura-source/qualification/v010/shell-runtime/controller-runtime",
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw qualification entrypoint", result.stderr)

    def test_ipc_readiness_must_fail_closed_when_service_exits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'fail "$service_name exited before publishing $target"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, "return 0", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exited before publishing", result.stderr)


    def test_qualification_entrypoints_must_have_distinct_shell_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/qualification-palette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = "//@ pragma ShellId linura-qualification-palette"
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(
                    marker,
                    "//@ pragma ShellId linura-qualification-controller",
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-qualification-palette", result.stderr)


    def test_tcg_qt_quick_backend_cannot_drift_from_software(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/v010-shell-runtime-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            marker = 'qt_quick_backend = "software"'
            self.assertIn(marker, text)
            contract.write_text(
                text.replace(marker, 'qt_quick_backend = "opengl"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qt_quick_backend", result.stderr)

    def test_qualification_service_must_pin_software_scenegraph_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            service = (
                root
                / "qualification/v010/shell-runtime/fixtures/linura-palette-qualification.service"
            )
            text = service.read_text(encoding="utf-8")
            marker = "Environment=QT_QUICK_BACKEND=software"
            self.assertIn(marker, text)
            service.write_text(
                text.replace(marker, "Environment=QT_QUICK_BACKEND=opengl", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("QT_QUICK_BACKEND=software", result.stderr)

    def test_production_shell_service_cannot_pin_qualification_renderer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            service = root / "packaging/systemd/user/linura-shell.service"
            service.write_text(
                service.read_text(encoding="utf-8")
                + "\nEnvironment=QT_QUICK_BACKEND=software\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("production shell service must not pin", result.stderr)

    def test_qt_quick_rendering_evidence_cannot_be_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'qt_quick_rendering_file="$evidence_root/qt-quick-rendering.env"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'qt_quick_rendering_file="/tmp/unbound-rendering.env"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qt-quick-rendering.env", result.stderr)

    def test_palette_ipc_failures_must_emit_service_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'fail "palette IPC call failed with status $status: $*"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'return "$status"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("palette IPC call failed", result.stderr)


    def test_quick_settings_runtime_case_cannot_disappear(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'pass_case "quick-settings-session1-volume-effect"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'echo "authority path omitted"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("quick-settings-session1-volume-effect", result.stderr)

    def test_precondition_drift_must_refresh_before_binding_second_draft(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = (
                'wait_until "fresh Quick Settings state before precondition-drift draft" '
                "quick_settings_ready_for_drift\n"
            )
            self.assertIn(marker, text)
            script.write_text(text.replace(marker, "", 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fresh Quick Settings state before precondition-drift draft", result.stderr)

    def test_quick_settings_runtime_fixture_must_import_quickshell_io(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            fixture = root / "apps/linura-shell/qualification-quick-settings.qml"
            text = fixture.read_text(encoding="utf-8")
            marker = "import Quickshell.Io\n"
            self.assertIn(marker, text)
            fixture.write_text(text.replace(marker, "", 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("import Quickshell.Io", result.stderr)

    def test_quick_settings_service_must_own_quickshell_runtime_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            service = (
                root
                / "qualification/v010/shell-runtime/fixtures/linura-quick-settings-qualification.service"
            )
            text = service.read_text(encoding="utf-8")
            marker = "RuntimeDirectory=quickshell\n"
            self.assertIn(marker, text)
            service.write_text(text.replace(marker, "", 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bounded Quickshell runtime directory", result.stderr)

    def test_exact_source_runtime_must_not_reinstall_arch_substrate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            runtime_index = text.index("  runtime:")
            workflow.write_text(
                text[:runtime_index] + text[runtime_index:].replace(
                    "Verify prepared runtime substrate before boot",
                    "Verify prepared runtime substrate before boot\n        run: pacman -Syu",
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not rebuild the prepared Arch package substrate", result.stderr)

    def test_runtime_prepared_restore_must_fail_closed_on_cache_miss(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "          fail-on-cache-miss: true\n"
            self.assertIn(marker, text)
            index = text.rfind(marker)
            workflow.write_text(text[:index] + text[index + len(marker):], encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fail closed if prepared substrate is unavailable", result.stderr)

    def test_runtime_cannot_boot_prepared_substrate_persistently(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "--image \"$VM_IMAGE\""
            self.assertIn(marker, text)
            runtime_index = text.index("  runtime:")
            runtime_text = text[runtime_index:]
            runtime_text = runtime_text.replace(marker, '--persistent ' + marker, 1)
            workflow.write_text(text[:runtime_index] + runtime_text, encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("snapshot/disposable", result.stderr)

    def test_quick_settings_runtime_fixture_cannot_replace_real_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            fixture = root / "apps/linura-shell/qualification-quick-settings.qml"
            text = fixture.read_text(encoding="utf-8")
            marker = "AudioSessionController {"
            self.assertIn(marker, text)
            fixture.write_text(
                text.replace(marker, "QtObject { // FakeAudio", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("real production binding", result.stderr)

    def test_exact_source_linurad_build_cannot_be_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "cargo build --locked --release -p linurad"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, 'echo "linurad build omitted"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cargo build --locked --release -p linurad", result.stderr)

    def test_runtime_must_assert_durable_audit_filesystem_and_schema_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = '[[ "$audit_mode" == "600" ]]'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, '[[ -n "$audit_mode" ]]', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('audit_mode" == "600', result.stderr)

    def test_runtime_must_bind_durable_transient_audit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'SELECT count(*) FROM transient_effect_audit'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, "SELECT 0", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("all four durable-audit count checkpoints", result.stderr)

    def test_runtime_must_prove_service_loss_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'pass_case "quick-settings-service-loss-fail-closed"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'echo "service-loss proof omitted"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("quick-settings-service-loss-fail-closed", result.stderr)

    def test_quick_settings_service_keeps_production_shell_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            service = (
                root
                / "qualification/v010/shell-runtime/fixtures/linura-quick-settings-qualification.service"
            )
            text = service.read_text(encoding="utf-8")
            marker = "NoNewPrivileges=yes"
            self.assertIn(marker, text)
            service.write_text(
                text.replace(marker, "NoNewPrivileges=no", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("preserve production shell sandbox", result.stderr)

    def test_runtime_versions_must_use_installed_systemctl_interface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = "systemctl --version"
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, "systemd --version", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("systemctl --version", result.stderr)


    def test_ui_module_linkage_evidence_cannot_be_optionalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/v010-shell-runtime-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            marker = "ui_module_linkage_required = true"
            self.assertIn(marker, text)
            contract.write_text(
                text.replace(marker, "ui_module_linkage_required = false", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ui_module_linkage_required", result.stderr)

    def test_runtime_must_prove_ui_plugin_dependency_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'ldd "$ui_plugin" > "$ui_linkage_file"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, ': > "$ui_linkage_file"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ui_linkage_file", result.stderr)

    def test_runtime_substrate_must_install_pipewire_audio_support_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            substrate = root / "contracts/v010-shell-runtime-substrate.toml"
            text = substrate.read_text(encoding="utf-8")
            marker = '  "pipewire-audio",\n'
            self.assertIn(marker, text)
            substrate.write_text(text.replace(marker, "", 1), encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("runtime_packages drifted", result.stderr)

    def test_runtime_must_prove_host_root_owned_exact_audio_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            self.assertIn('audio_helper_uid="$(stat -c \'%u\' "$audio_helper")"', text)
            self.assertIn('audio_helper_gid="$(stat -c \'%g\' "$audio_helper")"', text)
            self.assertIn('[[ "$audio_helper_uid" == "0" && "$audio_helper_gid" == "0" ]]', text)
            self.assertIn('cmp -s "$audio_helper" "$source_root/packaging/wireplumber/linura-session-audio.lua"', text)

    def test_pipewire_fixture_must_be_declarative_and_daemon_owned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            self.assertIn("context.objects = [", text)
            self.assertIn("factory.name = support.null-audio-sink", text)
            self.assertIn("monitor.channel-volumes = true", text)
            self.assertNotIn("pw-cli create-node adapter", text)
            script.write_text(
                text.replace("context.objects = [", "context.objects = [ # removed", 1)
                + "\npw-cli create-node adapter\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("daemon-owned declarative context.objects", result.stderr)

    def test_pipewire_fixture_must_be_installed_before_pipewire_starts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            fixture = "context.objects = ["
            start = "systemctl --user start pipewire.service"
            self.assertLess(text.index(fixture), text.index(start))
            script.write_text(
                text.replace(fixture, "context.objects_disabled = [", 1)
                + "\ncontext.objects = [\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be installed before PipeWire starts", result.stderr)

    def test_pipewire_fixture_failure_must_retain_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = '} > "$evidence_root/pipewire-fixture-diagnostics.txt" 2>&1'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(
                    marker,
                    '} > "$evidence_root/discarded-pipewire-diagnostics.txt" 2>&1',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pipewire-fixture-diagnostics.txt", result.stderr)

    def test_audio_fixture_evidence_cannot_be_optionalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/v010-shell-runtime-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            marker = "audio_fixture_evidence_required = true"
            self.assertIn(marker, text)
            contract.write_text(
                text.replace(marker, "audio_fixture_evidence_required = false", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("audio_fixture_evidence_required", result.stderr)

    def test_workflow_must_digest_bind_audio_fixture_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = 'quick_settings_audio_fixture = artifacts / "quick-settings-audio-fixture.txt"'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(
                    marker,
                    'quick_settings_audio_fixture = artifacts / "unbound-audio-fixture.txt"',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("quick-settings-audio-fixture.txt", result.stderr)

    def test_workflow_must_digest_bind_pipewire_props_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = 'pipewire_fixture_props = artifacts / "pipewire-fixture-props.txt"'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(
                    marker,
                    'pipewire_fixture_props = artifacts / "unbound-pipewire-fixture-props.txt"',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pipewire-fixture-props.txt", result.stderr)

    def test_runtime_must_prove_bridge_plugin_dependency_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'ldd "$bridge_plugin" > "$bridge_linkage_file"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, ': > "$bridge_linkage_file"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bridge_linkage_file", result.stderr)

    def test_provisioning_must_reject_unresolved_bridge_plugin_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/provision-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'bridge_linkage="$(ldd "$bridge_plugin")"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'bridge_linkage="unchecked"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("dependency-closure proof", result.stderr)

    def test_provisioning_must_reject_unresolved_ui_plugin_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/provision-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'ui_linkage="$(ldd "$ui_plugin")"'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'ui_linkage="unchecked"', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("dependency-closure proof", result.stderr)


    def test_session1_volume_failure_must_retain_bounded_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'quick-settings-session1-failure.txt'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'discarded-session1-failure.txt'),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("quick-settings-session1-failure.txt", result.stderr)

    def test_session1_volume_wait_must_remain_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            marker = 'quick_settings_effect_deadline=$((SECONDS + 30))'
            self.assertIn(marker, text)
            script.write_text(
                text.replace(marker, 'quick_settings_effect_deadline=$((SECONDS + 300))', 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SECONDS + 30", result.stderr)


    def test_evidence_package_set_must_include_pipewire_audio(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = '              "pipewire-audio",\n'
            self.assertIn(marker, text)
            evidence_start = text.index("required_packages = {")
            marker_index = text.index(marker, evidence_start)
            workflow.write_text(
                text[:marker_index] + text[marker_index + len(marker):],
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("evidence package set must include pipewire-audio", result.stderr)


    def test_quick_settings_draft_binding_must_be_atomic_with_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            atomic = "if quick_settings_bind_draft; then"
            self.assertIn(atomic, text)
            script.write_text(
                text.replace(atomic, "if quick_settings_ready; then", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "must atomically acquire the Quick Settings draft",
                result.stderr,
            )

    def test_quick_settings_audit_baseline_must_precede_panel_open(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            audit = 'audit_count_before="$(sqlite3 "$audio_audit" \'SELECT count(*) FROM transient_effect_audit;\' 2>/dev/null || printf \'0\')"'
            opened = "checked_quick_settings_call linura.quick-settings-qualification openSettings >/dev/null"
            self.assertLess(text.index(audit), text.index(opened))
            text = text.replace(audit + "\n", "", 1)
            text = text.replace(opened + "\n", opened + "\n" + audit + "\n", 1)
            script.write_text(text, encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must capture the transient-audit baseline before opening Quick Settings", result.stderr)


    def test_restart_recovery_must_use_a_defined_single_call_readiness_predicate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
            text = script.read_text(encoding="utf-8")
            definition = "quick_settings_recovered() {"
            wait = 'wait_until "Quick Settings recovery after linurad restart" quick_settings_recovered'
            self.assertIn(definition, text)
            self.assertIn(wait, text)
            script.write_text(
                text.replace(definition, "quick_settings_recovery_removed() {", 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("quick_settings_recovered", result.stderr)


if __name__ == "__main__":
    unittest.main()
