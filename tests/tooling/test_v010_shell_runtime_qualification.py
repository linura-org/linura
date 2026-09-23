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
    "contracts/v010-workstation-qualification.toml",
    ".github/workflows/v010-shell-runtime-qualification.yml",
    ".github/workflows/v010-qualification.yml",
    "packaging/systemd/user/linura-shell.service",
    "apps/linura-shell/qualification-controller.qml",
    "apps/linura-shell/qualification-palette.qml",
    "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml",
    "apps/linura-shell/plugins/command-palette/CommandPalette.qml",
    "apps/linura-shell/ui/CMakeLists.txt",
    "qualification/v010/shell-runtime/provision-shell-runtime.sh",
    "qualification/v010/shell-runtime/run-shell-runtime.sh",
    "qualification/v010/shell-runtime/start-vm.sh",
    "qualification/v010/shell-runtime/fixtures/linger-app",
    "qualification/v010/shell-runtime/fixtures/forking-app",
    "qualification/v010/shell-runtime/fixtures/linura-shell-qualification.service",
    "qualification/v010/shell-runtime/fixtures/linura-palette-qualification.service",
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
            workflow = root / ".github/workflows/v010-shell-runtime-qualification.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "timeout --signal=TERM --kill-after=10s 720"
            self.assertIn(marker, text)
            workflow.write_text(
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


if __name__ == "__main__":
    unittest.main()
