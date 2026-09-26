#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "contracts/v010-shell-runtime-qualification.toml"
WORKFLOW = ".github/workflows/v010-shell-runtime-qualification.yml"
PARENT_WORKFLOW = ".github/workflows/v010-qualification.yml"

EXPECTED_COMPONENTS = [
    "systemd-user",
    "wayland",
    "seatd-libseat",
    "drm",
    "hyprland",
    "quickshell",
    "qt6",
    "xdg-desktop-entries",
    "pipewire",
    "wireplumber",
    "linurad",
    "session1",
    "sqlite-transient-audit",
    "quick-settings",
]

EXPECTED_CASES = [
    "seat-drm-readiness",
    "headless-hyprland-runtime",
    "visible-application-discovery",
    "nodisplay-filtering",
    "terminal-entry-rejection",
    "exact-id-reresolution",
    "bounded-systemd-run-dispatch",
    "app-slice-isolation",
    "shell-service-restart-survival",
    "forking-application-cgroup-lifetime",
    "palette-session-generation-isolation",
    "quick-settings-authoritative-observation",
    "quick-settings-session1-volume-effect",
    "quick-settings-durable-audit-lineage",
    "quick-settings-precondition-drift-rejection",
    "quick-settings-service-loss-fail-closed",
    "quick-settings-restart-recovery",
]

RUNTIME_FILES = (
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
    "qualification/v010/shell-runtime/fixtures/linger-app",
    "qualification/v010/shell-runtime/fixtures/forking-app",
    "qualification/v010/shell-runtime/fixtures/linura-shell-qualification.service",
    "qualification/v010/shell-runtime/fixtures/linura-palette-qualification.service",
    "qualification/v010/shell-runtime/fixtures/linura-quick-settings-qualification.service",
    "packaging/systemd/user/linurad.service",
    "packaging/wireplumber/linura-session-audio.lua",
    "packaging/arch/archiso/packages.linura",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationVisible.desktop",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationHidden.desktop",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationTerminal.desktop",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationForking.desktop",
    "qualification/v010/shell-runtime/fixtures/org.linura.QualificationStale.desktop",
)

SANDBOX_LINES = (
    "NoNewPrivileges=yes",
    "PrivateTmp=yes",
    "ProtectSystem=strict",
    "RestrictAddressFamilies=AF_UNIX",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "UMask=0077",
)


def _load_toml(path: Path, label: str, failures: list[str]) -> dict:
    if not path.is_file() or path.is_symlink():
        failures.append(f"{label} missing or not a regular file: {path}")
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        failures.append(f"{label} is invalid: {error}")
        return {}


def _runtime_dependency_tables(document: dict) -> list[dict]:
    tables: list[dict] = []
    for key in ("dependencies", "build-dependencies"):
        table = document.get(key)
        if isinstance(table, dict):
            tables.append(table)
    targets = document.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for key in ("dependencies", "build-dependencies"):
                table = target.get(key)
                if isinstance(table, dict):
                    tables.append(table)
    return tables


def _local_runtime_dependency_paths(
    root: Path,
    start_manifest: str,
    failures: list[str],
) -> list[str]:
    root_resolved = root.resolve()
    start = root / start_manifest
    if not start.is_file() or start.is_symlink():
        failures.append(f"linurad runtime manifest missing or untrusted: {start_manifest}")
        return []

    pending = [start]
    seen: set[Path] = set()
    dependency_paths: set[str] = set()
    while pending:
        manifest = pending.pop()
        resolved_manifest = manifest.resolve()
        if resolved_manifest in seen:
            continue
        seen.add(resolved_manifest)
        document = _load_toml(
            manifest,
            f"runtime Cargo manifest {manifest.relative_to(root)}",
            failures,
        )
        if not document:
            continue
        for table in _runtime_dependency_tables(document):
            for specification in table.values():
                if not isinstance(specification, dict):
                    continue
                relative_path = specification.get("path")
                if not isinstance(relative_path, str):
                    continue
                raw_manifest = manifest.parent / relative_path / "Cargo.toml"
                if not raw_manifest.is_file() or raw_manifest.is_symlink():
                    failures.append(
                        f"local runtime dependency manifest missing or untrusted: {raw_manifest}"
                    )
                    continue
                resolved_dependency = raw_manifest.resolve()
                try:
                    relative_manifest = resolved_dependency.relative_to(root_resolved)
                except ValueError:
                    failures.append(
                        f"local runtime dependency escapes repository root: {relative_path}"
                    )
                    continue
                dependency_paths.add(relative_manifest.parent.as_posix())
                if resolved_dependency not in seen:
                    pending.append(raw_manifest)
    return sorted(dependency_paths)


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    contract = _load_toml(root / CONTRACT, "v0.10 shell runtime contract", failures)
    workstation = _load_toml(
        root / "contracts/v010-workstation-qualification.toml",
        "v0.10 workstation qualification contract",
        failures,
    )
    if not contract or not workstation:
        return failures

    if workstation.get("shell_runtime_qualification_contract") != CONTRACT:
        failures.append("v0.10 workstation qualification must bind the shell runtime qualification contract")

    expected_scalars = {
        "schema_version": 1,
        "id": "qualification/v010-shell-runtime",
        "milestone": "v0.10.0",
        "state": "development-gate",
        "claim": "development-runtime-evidence-only",
        "target_profile": "arch-hyprland-v1",
        "workflow": WORKFLOW,
        "runner": "github-hosted-ubuntu-qemu-tcg",
        "vm_acceleration": "tcg",
        "qt_quick_backend": "software",
        "vm_network_mac": "52:54:00:12:34:56",
        "vm_gpu_pci_bdf": "0000:00:02.0",
        "vm_gpu_vendor_id": "0x1af4",
        "vm_gpu_device_id": "0x1050",
        "vm_disk_size_gib": 16,
        "runtime_root": "qualification/v010/shell-runtime",
    }
    for key, expected in expected_scalars.items():
        if contract.get(key) != expected:
            failures.append(f"shell runtime contract {key} must remain {expected!r}")

    if contract.get("required_components") != EXPECTED_COMPONENTS:
        failures.append("shell runtime required_components drifted from the real authority/runtime matrix")
    if contract.get("required_cases") != EXPECTED_CASES:
        failures.append("shell runtime required_cases drifted from the executable qualification matrix")

    base_url = contract.get("base_image_url")
    checksum_url = contract.get("base_image_checksum_url")
    if not isinstance(base_url, str):
        failures.append("shell runtime base_image_url must be a string")
    else:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or parsed.netloc != "geo.mirror.pkgbuild.com":
            failures.append("shell runtime base image must use the official Arch mirror over HTTPS")
        if "/images/v" not in parsed.path or "/latest/" in parsed.path:
            failures.append("shell runtime base image must be version-addressed and never use latest")
        if not re.search(r"/Arch-Linux-x86_64-cloudimg-[0-9.]+\.qcow2$", parsed.path):
            failures.append("shell runtime base image must be an exact x86_64 Arch cloud image")
    if not isinstance(checksum_url, str) or not isinstance(base_url, str) or checksum_url != base_url + ".SHA256":
        failures.append("shell runtime checksum URL must bind the exact version-addressed base image")

    substrate = workstation.get("substrate", {})
    if contract.get("arch_archive_snapshot") != substrate.get("snapshot_date"):
        failures.append("shell runtime Arch archive snapshot must match the v0.10 workstation substrate")
    if contract.get("arch_archive_url") != substrate.get("repository_url"):
        failures.append("shell runtime Arch archive URL must match the v0.10 workstation substrate")

    evidence = contract.get("evidence")
    if not isinstance(evidence, dict):
        failures.append("shell runtime contract missing evidence")
    else:
        for key in (
            "source_sha_required",
            "base_image_digest_required",
            "runtime_versions_required",
            "package_versions_required",
            "guest_transcript_digest_required",
            "systemd_unit_evidence_required",
            "process_cgroup_evidence_required",
            "storage_capacity_required",
            "seat_drm_preflight_required",
            "ui_module_linkage_required",
            "qt_quick_backend_required",
            "authority_runtime_integrity_required",
            "audio_fixture_evidence_required",
            "transient_audit_evidence_required",
            "quick_settings_authority_path_required",
        ):
            if evidence.get(key) is not True:
                failures.append(f"shell runtime evidence.{key} must remain true")
        if evidence.get("schema_version") != 1:
            failures.append("shell runtime evidence schema_version must remain 1")
        if evidence.get("result") != "passed":
            failures.append("shell runtime evidence result contract must remain passed")
        if evidence.get("release_support_promotion") is not False:
            failures.append("shell runtime development evidence must never promote release support")

    for relative in RUNTIME_FILES:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            failures.append(f"shell runtime qualification file missing or untrusted: {relative}")

    workflow_path = root / WORKFLOW
    parent_path = root / PARENT_WORKFLOW
    workflow = workflow_path.read_text(encoding="utf-8") if workflow_path.is_file() else ""
    parent = parent_path.read_text(encoding="utf-8") if parent_path.is_file() else ""
    required_workflow_fragments = (
        "name: v0.10 shell runtime qualification",
        "workflow_call:",
        'runs-on: ubuntu-24.04',
        'timeout-minutes: 90',
        'python3 tools/check_v010_shell_runtime_qualification.py',
        "source tools/codex/versions.env",
        'rustup toolchain install "$RUST_VERSION" --profile minimal',
        "cargo build --locked --release -p linurad",
        'LINURAD_SHA256=%s',
        'SESSION_AUDIO_HELPER_SHA256=%s',
        "bash qualification/v010/shell-runtime/start-vm.sh",
        "cloud-localds",
        "QUALIFICATION_NIC_MAC: 52:54:00:12:34:56",
        'QUALIFICATION_GPU_PCI_BDF: "0000:00:02.0"',
        'QUALIFICATION_GPU_VENDOR_ID: "0x1af4"',
        'QUALIFICATION_GPU_DEVICE_ID: "0x1050"',
        "QUALIFICATION_DISK_GIB: 16",
        'qemu-img resize "$vm_image" "${QUALIFICATION_DISK_GIB}G"',
        "growpart:",
        'devices: ["/"]',
        "resize_rootfs: true",
        '"$ARTIFACT_DIR/guest-storage.txt"',
        "guest root filesystem capacity contract not met",
        'macaddress: "$QUALIFICATION_NIC_MAC"',
        "set-name: eth0",
        "renderer: networkd",
        '--nic-mac "$QUALIFICATION_NIC_MAC"',
        "deadline=$((SECONDS + 420))",
        "'timeout 240 cloud-init status --wait --long'",
        "--disable-download-timeout",
        "timeout --signal=TERM --kill-after=10s 720",
        "for attempt in 1 2 3",
        "pinned Arch runtime installation failed after 3 bounded attempts",
        "pipewire pipewire-audio wireplumber networkmanager sqlite",
        "git archive --format=tar.gz",
        'linura@127.0.0.1:/tmp/linurad-qualification',
        "installed linurad digest does not match exact-source build",
        "installed session-audio helper digest does not match exact source",
        "runtime-install-integrity.txt",
        "provision-shell-runtime.sh",
        "run-shell-runtime.sh",
        "sudo -n modprobe virtio_gpu",
        "Environment=SEATD_VTBOUND=0",
        'sudo -n systemctl enable seatd.service',
        'sudo -n systemctl start seatd.service',
        '"$ARTIFACT_DIR/seat-drm-setup.log"',
        "dump_graphics_state",
        "sudo -n journalctl -u seatd.service -b --no-pager",
        'seat_group="$(stat -c \'%G\' "$seat_socket")"',
        '[[ "$card_name" =~ ^card[0-9]+$ ]] || continue',
        '[[ "${#drm_cards[@]}" -eq 1 ]]',
        'qualification_bdf="$(basename "$qualification_device")"',
        '[[ "$qualification_bdf" == "$QUALIFICATION_GPU_PCI_BDF" ]]',
        '[[ "$qualification_vendor" == "$QUALIFICATION_GPU_VENDOR_ID" ]]',
        '[[ "$qualification_device_id" == "$QUALIFICATION_GPU_DEVICE_ID" ]]',
        'seat_setup_pipeline_status=("${PIPESTATUS[@]}")',
        "unexpected graphical seat setup pipeline width",
        'pipeline_status=("${PIPESTATUS[@]}")',
        '"$ARTIFACT_DIR/seatd-journal.log"',
        "ui-module-linkage.txt",
        "bridge-module-linkage.txt",
        "qt-quick-rendering.env",
        "authority-runtime-integrity.txt",
        "pipewire-fixture-create.txt",
        "pipewire-snapshot-initial.txt",
        "quick-settings-audio-fixture.txt",
        "quick-settings-observation.txt",
        "quick-settings-session1-effect.txt",
        "quick-settings-audit.txt",
        "quick-settings-precondition-drift.txt",
        "quick-settings-service-loss.txt",
        "quick-settings-restart-recovery.txt",
        '"qt_quick_backend": rendering_backend',
        'contract["qt_quick_backend"]',
        "package-versions.txt",
        '"runtime_packages": package_versions',
        '"linurad_sha256": os.environ["LINURAD_SHA256"]',
        '"session_audio_helper_sha256": os.environ["SESSION_AUDIO_HELPER_SHA256"]',
        '"scope": "real-session-authority"',
        '"disk_size_gib": contract["vm_disk_size_gib"]',
        "V010-SHELL-RUNTIME-EVIDENCE.json",
        "V010-SHELL-RUNTIME-EVIDENCE.sha256",
        "release_support_promotion",
    )
    for fragment in required_workflow_fragments:
        if fragment not in workflow:
            failures.append(f"shell runtime workflow missing: {fragment}")
    package_set_marker = "required_packages = {"
    if package_set_marker not in workflow:
        failures.append("shell runtime workflow missing exact runtime package evidence set")
    else:
        package_set = workflow.split(package_set_marker, 1)[1].split("}", 1)[0]
        if '"pipewire-audio"' not in package_set:
            failures.append("shell runtime evidence package set must include pipewire-audio")

    if isinstance(base_url, str) and f"BASE_IMAGE_URL: {base_url}" not in workflow:
        failures.append("shell runtime workflow base image does not match its contract")
    if isinstance(checksum_url, str) and f"BASE_IMAGE_CHECKSUM_URL: {checksum_url}" not in workflow:
        failures.append("shell runtime workflow checksum URL does not match its contract")
    archive_url = contract.get("arch_archive_url")
    if isinstance(archive_url, str) and f"ARCH_ARCHIVE_URL: {archive_url}" not in workflow:
        failures.append("shell runtime workflow archive URL does not match its contract")
    for forbidden in ("continue-on-error:", "/images/latest/", "runs-on: self-hosted"):
        if forbidden in workflow:
            failures.append(f"shell runtime workflow contains forbidden weakening: {forbidden}")

    parent_fragments = (
        '".github/workflows/v010-shell-runtime-qualification.yml"',
        '"contracts/v010-shell-runtime-qualification.toml"',
        '"apps/linura-shell/**"',
        '"apps/linurad/**"',
        '"packaging/systemd/user/linurad.service"',
        '"packaging/wireplumber/linura-session-audio.lua"',
        '"crates/linura-core/**"',
        '"crates/linura-dbus/**"',
        '"crates/linura-observation/**"',
        '"crates/linura-observation-control/**"',
        '"crates/linura-linux-observation/**"',
        '"crates/linura-protocol/**"',
        '"crates/linura-planner/**"',
        '"crates/linura-policy/**"',
        '"crates/linura-provider-sdk/**"',
        '"crates/linura-control/**"',
        '"Cargo.toml"',
        '"Cargo.lock"',
        '"qualification/v010/shell-runtime/**"',
        "shell-runtime:",
        "uses: ./.github/workflows/v010-shell-runtime-qualification.yml",
        "needs: contract",
        "source_sha: ${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}",
    )
    for fragment in parent_fragments:
        if fragment not in parent:
            failures.append(f"v0.10 parent qualification workflow missing shell runtime gate: {fragment}")

    for dependency_path in _local_runtime_dependency_paths(
        root,
        "apps/linurad/Cargo.toml",
        failures,
    ):
        trigger = f'"{dependency_path}/**"'
        if trigger not in parent:
            failures.append(
                f"v0.10 parent qualification workflow missing linurad local dependency trigger: {trigger}"
            )

    production_packages_path = root / "packaging/arch/archiso/packages.linura"
    if production_packages_path.is_file() and not production_packages_path.is_symlink():
        production_packages = {
            line.strip()
            for line in production_packages_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        if "pipewire-audio" not in production_packages:
            failures.append(
                "production Arch package contract must include pipewire-audio exercised by Quick Settings qualification"
            )

    production_service = (root / "packaging/systemd/user/linura-shell.service").read_text(encoding="utf-8")
    production_service_lines = set(production_service.splitlines())
    if any(
        line.startswith("Environment=QT_QUICK_BACKEND=")
        for line in production_service_lines
    ):
        failures.append(
            "production shell service must not pin the qualification-only Qt Quick software backend"
        )
    qualification_services = {
        "linura-shell-qualification.service":
            "ExecStart=/usr/bin/quickshell -n -p /opt/linura-source/apps/linura-shell/qualification-controller.qml",
        "linura-palette-qualification.service":
            "ExecStart=/usr/bin/quickshell -n -p /opt/linura-source/apps/linura-shell/qualification-palette.qml",
        "linura-quick-settings-qualification.service":
            "ExecStart=/usr/bin/quickshell -n -p /opt/linura-source/apps/linura-shell/qualification-quick-settings.qml",
    }
    for service_name, expected_exec_start in qualification_services.items():
        service = (
            root / "qualification/v010/shell-runtime/fixtures" / service_name
        ).read_text(encoding="utf-8")
        service_lines = set(service.splitlines())
        if expected_exec_start not in service_lines:
            failures.append(
                f"{service_name} must launch the raw qualification entrypoint from the Linura Shell root"
            )
        if "Environment=QT_QUICK_BACKEND=software" not in service_lines:
            failures.append(
                f"{service_name} must pin QT_QUICK_BACKEND=software for the QEMU/TCG development gate"
            )
        for line in SANDBOX_LINES:
            if line not in production_service_lines:
                failures.append(f"production shell service unexpectedly lacks sandbox line: {line}")
            if line not in service_lines:
                failures.append(f"{service_name} must preserve production shell sandbox line: {line}")

    controller = (root / "apps/linura-shell/qualification-controller.qml").read_text(encoding="utf-8")
    for fragment in (
        "//@ pragma ShellId linura-qualification-controller",
        "import qs.integrations.xdg as Xdg",
        "Xdg.ApplicationLauncherController {",
        'target: "linura.shell-qualification"',
        "function launch(applicationId: string, requestGeneration: int): string",
        "launcher.launchApplication(applicationId, requestGeneration)",
    ):
        if fragment not in controller:
            failures.append(f"controller runtime fixture missing production binding: {fragment}")
    if "../../../../apps/linura-shell" in controller:
        failures.append("controller runtime fixture must not use a cross-root relative QML import")

    palette = (root / "apps/linura-shell/qualification-palette.qml").read_text(encoding="utf-8")
    for fragment in (
        "//@ pragma ShellId linura-qualification-palette",
        'import "plugins/command-palette" as Palette',
        "Palette.CommandPalette {",
        'target: "linura.palette-qualification"',
        "palette.completeApplicationRequest(status, requestGeneration)",
    ):
        if fragment not in palette:
            failures.append(f"palette runtime fixture missing production binding: {fragment}")
    if "../../../../apps/linura-shell" in palette:
        failures.append("palette runtime fixture must not use a cross-root relative QML import")
    if "qs.plugins.command-palette" in palette:
        failures.append("palette runtime fixture must not use an invalid hyphenated qs module path")

    quick_settings = (root / "apps/linura-shell/qualification-quick-settings.qml").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "//@ pragma ShellId linura-qualification-quick-settings",
        "import org.linura.ShellBridge 1.0",
        'import "plugins/quick-settings" as QuickSettings',
        "AudioSessionController {",
        "QuickSettings.QuickSettingsPanel {",
        'target: "linura.quick-settings-qualification"',
        "audioController.beginVolumeDraft()",
        "audioController.setVolume(volumePercent)",
    ):
        if fragment not in quick_settings:
            failures.append(
                f"Quick Settings runtime fixture missing real production binding: {fragment}"
            )
    for forbidden in ("MockAudio", "FakeAudio", "wpctl", "wpexec", "SetAudioOutputVolume"):
        if forbidden in quick_settings:
            failures.append(
                f"Quick Settings runtime fixture must not bypass the production bridge: {forbidden}"
            )

    run_script = root / "qualification/v010/shell-runtime/run-shell-runtime.sh"
    provision_script = root / "qualification/v010/shell-runtime/provision-shell-runtime.sh"
    vm_launcher = root / "qualification/v010/shell-runtime/start-vm.sh"

    if provision_script.is_file():
        provision_text = provision_script.read_text(encoding="utf-8")
        for fragment in (
            'ui_module_dir=/usr/local/lib/qt6/qml/org/linura/UI',
            'ui_plugin="$ui_module_dir/liblinura-uiplugin.so"',
            'ui_backing="$ui_module_dir/liblinura-ui.so"',
            'ui_linkage="$(ldd "$ui_plugin")"',
            "Linura UI QML plugin has unresolved installed dependencies",
            "Linura UI QML plugin did not resolve its backing library from the module directory",
            'bridge_module_dir=/usr/local/lib/qt6/qml/org/linura/ShellBridge',
            'bridge_plugin="$bridge_module_dir/liblinura-shell-bridgeplugin.so"',
            'bridge_backing="$bridge_module_dir/liblinura-shell-bridge.so"',
            'bridge_linkage="$(ldd "$bridge_plugin")"',
            "Linura ShellBridge QML plugin has unresolved installed dependencies",
            "Linura ShellBridge QML plugin did not resolve its backing library from the module directory",
            "cmake --build",
            "cmake --install",
            "install -o root -g root -m 0755 \"$linurad_binary\" /usr/bin/linurad",
            "install -o root -g root -m 0644",
            "/usr/lib/linura/linura-session-audio.lua",
        ):
            if fragment not in provision_text:
                failures.append(
                    f"shell runtime provisioning missing QML module dependency-closure proof: {fragment}"
                )

    for script in (run_script, provision_script, vm_launcher):
        completed = subprocess.run(
            ["bash", "-n", str(script)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            failures.append(f"invalid shell runtime script {script.relative_to(root)}: {completed.stderr.strip()}")

    if run_script.is_file():
        run_text = run_script.read_text(encoding="utf-8")
        if "pw-cli create-node adapter" in run_text:
            failures.append(
                "runtime PipeWire fixture must be daemon-owned declarative context.objects, not pw-cli create-node"
            )
        fixture_index = run_text.find("context.objects = [")
        pipewire_start_index = run_text.find("systemctl --user start pipewire.service")
        if fixture_index < 0 or pipewire_start_index < 0 or fixture_index > pipewire_start_index:
            failures.append(
                "runtime PipeWire fixture config must be installed before PipeWire starts"
            )
        for case_id in EXPECTED_CASES:
            if f'pass_case "{case_id}"' not in run_text:
                failures.append(f"runtime protocol does not positively record required case: {case_id}")
        if run_text.count("SELECT count(*) FROM transient_effect_audit") != 4:
            failures.append(
                "runtime protocol must retain all four durable-audit count checkpoints "
                "(before/after verified effect and before/after precondition-drift rejection)"
            )
        if run_text.count("quick-settings-session1-failure.txt") != 2:
            failures.append(
                "runtime protocol must retain both write/read references for Session1 failure diagnostics"
            )
        draft_wait = "quick_settings_bind_draft() {"
        draft_attempt = 'checked_quick_settings_call linura.quick-settings-qualification beginDraft 2>/dev/null'
        draft_accept = "if quick_settings_bind_draft; then"
        authority_probe = '[[ "$(checked_quick_settings_call linura.quick-settings-qualification authority)" == "native-api" ]]'
        audit_baseline = 'audit_count_before="$(sqlite3 "$audio_audit" \'SELECT count(*) FROM transient_effect_audit;\' 2>/dev/null || printf \'0\')"'
        draft_wait_index = run_text.find(draft_wait)
        draft_attempt_index = run_text.find(draft_attempt)
        draft_accept_index = run_text.find(draft_accept)
        authority_index = run_text.find(authority_probe)
        audit_index = run_text.find(audit_baseline)
        open_index = run_text.find("checked_quick_settings_call linura.quick-settings-qualification openSettings")
        if (
            draft_wait_index < 0
            or draft_attempt_index < 0
            or draft_accept_index < 0
            or authority_index < 0
            or draft_wait_index > draft_attempt_index
            or draft_attempt_index > draft_accept_index
            or draft_accept_index > authority_index
        ):
            failures.append(
                "runtime protocol must atomically acquire the Quick Settings draft before post-bind evidence reads"
            )
        if "quick_settings_ready()" in run_text:
            failures.append(
                "runtime protocol must not split Quick Settings readiness and draft binding across separate IPC calls"
            )
        if audit_index < 0 or open_index < 0 or audit_index > open_index:
            failures.append(
                "runtime protocol must capture the transient-audit baseline before opening Quick Settings"
            )
        for fragment in (
            "systemctl --user restart linura-shell-qualification.service",
            'command -v systemctl >/dev/null || fail "systemctl is missing"',
            "systemctl --version",
            'shell_root="$source_root/apps/linura-shell"',
            'controller_config="$shell_root/qualification-controller.qml"',
            'palette_config="$shell_root/qualification-palette.qml"',
            'quick_settings_config="$shell_root/qualification-quick-settings.qml"',
            "wait_for_ipc_target()",
            'fail "$service_name exited before publishing $target"',
            "ExitType --value",
            "app.slice",
            "kill -0",
            "generation_two > generation_one",
            "hyprctl monitors -j",
            'hyprland_ipc_deadline=$((SECONDS + 45))',
            'while (( SECONDS < hyprland_ipc_deadline )); do',
            'systemctl --user is-active --quiet linura-hyprland-qualification.service',
            'fail "Hyprland exited before IPC became responsive"',
            'fail "Hyprland IPC readiness deadline exceeded"',
            "systemctl is-active --quiet seatd.service",
            'ui_module_dir=/usr/local/lib/qt6/qml/org/linura/UI',
            'ui_plugin="$ui_module_dir/liblinura-uiplugin.so"',
            'ui_backing="$ui_module_dir/liblinura-ui.so"',
            'ui_linkage_file="$evidence_root/ui-module-linkage.txt"',
            'ldd "$ui_plugin" > "$ui_linkage_file"',
            "Linura UI QML plugin has unresolved installed dependencies",
            "Linura UI QML plugin did not resolve its backing library from the module directory",
            'bridge_module_dir=/usr/local/lib/qt6/qml/org/linura/ShellBridge',
            'bridge_linkage_file="$evidence_root/bridge-module-linkage.txt"',
            'ldd "$bridge_plugin" > "$bridge_linkage_file"',
            "Linura ShellBridge QML plugin has unresolved installed dependencies",
            "Linura ShellBridge QML plugin did not resolve its backing library from the module directory",
            "seat_group=\"$(stat -c '%G' \"$seat_socket\")\"",
            'qualification_gpu_pci_bdf="0000:00:02.0"',
            'qualification_gpu_vendor_id="0x1af4"',
            'qualification_gpu_device_id="0x1050"',
            '[[ "$card_name" =~ ^card[0-9]+$ ]] || continue',
            '[[ "${#drm_cards[@]}" -eq 1 ]]',
            'qualification_bdf="$(basename "$qualification_device")"',
            '[[ "$qualification_bdf" == "$qualification_gpu_pci_bdf" ]]',
            '[[ "$qualification_vendor" == "$qualification_gpu_vendor_id" ]]',
            '[[ "$qualification_device_id" == "$qualification_gpu_device_id" ]]',
            "LIBSEAT_BACKEND=seatd",
            'AQ_DRM_DEVICES="$virtio_drm"',
            "export QT_QUICK_BACKEND=software",
            'qt_quick_rendering_file="$evidence_root/qt-quick-rendering.env"',
            'systemctl --user show "$service_name" -p Environment --value',
            'fail "$service_name did not retain the qualification-only Qt Quick software backend"',
            "checked_palette_call()",
            'fail "palette IPC call failed with status $status: $*"',
            "checked_quick_settings_call()",
            'fail "Quick Settings IPC call failed with status $status: $*"',
            'quick_settings_bind_draft() {',
            'checked_quick_settings_call linura.quick-settings-qualification beginDraft 2>/dev/null',
            'if quick_settings_bind_draft; then',
            'checked_quick_settings_call linura.quick-settings-qualification canCommitDraft',
            'pipewire_fixture_config="$pipewire_fixture_dir/90-linura-qualification-sink.conf"',
            "context.objects = [",
            "factory = adapter",
            "factory.name = support.null-audio-sink",
            "node.name = linura-qualification-sink",
            'node.description = "Linura Qualification Sink"',
            "media.class = Audio/Sink",
            "object.linger = true",
            "audio.position = [ FL FR ]",
            "monitor.channel-volumes = true",
            'chmod 0600 "$pipewire_fixture_config"',
            'cp "$pipewire_fixture_config" "$evidence_root/pipewire-fixture-create.txt"',
            'systemctl --user start pipewire.service',
            'systemctl --user start wireplumber.service',
            '} > "$evidence_root/pipewire-fixture-diagnostics.txt" 2>&1',
            'cat "$evidence_root/pipewire-fixture-diagnostics.txt" >&2',
            "pw-cli ls Node",
            'pipewire-fixture-create.txt',
            'pipewire-snapshot-initial.txt',
            'quick-settings-audio-fixture.txt',
            'wpctl set-default "$qualification_sink_id"',
            '/usr/bin/wpexec "$audio_helper"',
            'systemctl --user start linurad.service',
            'busctl --user status org.linura.Control1',
            'operation:audio.output.set-session-volume',
            'audio:session:output:$qualification_sink_id',
            'SELECT count(*) FROM transient_effect_audit',
            '[[ "$audit_mode" == "600" ]]',
            '[[ "$audit_links" == "1" ]]',
            "PRAGMA application_id;",
            "PRAGMA user_version;",
            '[[ "$audit_application_id" == "1280201810" ]]',
            '[[ "$audit_user_version" == "1" ]]',
            '[[ "${audit_journal_mode,,}" == "wal" ]]',
            '[[ "$audit_synchronous" == "2" ]]',
            '[[ "$audit_quick_check" == "ok" ]]',
            "sqlite_schema",
            '[[ "$audit_table_sql" == *"STRICT"* ]]',
            'audit_wal="${audio_audit}-wal"',
            '(( audit_wal_size <= 16777216 ))',
            '$audit_disposition" == "verified"',
            'quick_settings_effect_deadline=$((SECONDS + 30))',
            'quick-settings-session1-failure.txt',
            "'-- transient audit --'",
            'SELECT rowid,request_id,resource,disposition,failure_code,pre_effect_evidence_id,post_effect_evidence_id FROM transient_effect_audit ORDER BY rowid DESC LIMIT 3;',
            'pass_case "quick-settings-precondition-drift-rejection"',
            'pass_case "quick-settings-service-loss-fail-closed"',
            'quick_settings_recovered() {',
            'wait_until "Quick Settings recovery after linurad restart" quick_settings_recovered',
            'pass_case "quick-settings-restart-recovery"',
            "seat-drm-preflight.txt",
            'pacman -Q systemd hyprland quickshell qt6-base qt6-declarative qt6-wayland mesa vulkan-swrast seatd pipewire pipewire-audio wireplumber networkmanager sqlite',
            'package-versions.txt',
        ):
            if fragment not in run_text:
                failures.append(f"runtime protocol missing externally observable proof: {fragment}")

    if vm_launcher.is_file():
        launcher_text = vm_launcher.read_text(encoding="utf-8")
        for fragment in (
            "q35,accel=tcg",
            "-vga none",
            "-device virtio-gpu-pci,id=linura-qualification-gpu,bus=pcie.0,addr=0x2",
            "readonly=on",
            "-snapshot",
            "hostfwd=tcp:127.0.0.1:$ssh_port-:22",
            "--nic-mac)",
            "mac=$nic_mac",
        ):
            if fragment not in launcher_text:
                failures.append(
                    f"shell runtime VM launcher missing bounded graphical VM contract: {fragment}"
                )

    if "tools/vm.py" in workflow:
        failures.append(
            "shell runtime workflow must not modify or depend on the shared disposable VM harness"
        )

    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else ROOT
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("v0.10 shell runtime qualification contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
