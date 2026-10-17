#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from tools import development_workspace as storage  # noqa: E402
from tools import development_storage as storage_execution  # noqa: E402

OVERLAY = ROOT / "packaging/arch/archiso"
RELENG = Path("/usr/share/archiso/configs/releng")
OUT = ROOT / ".artifacts/iso"
WORK = ROOT / ".artifacts/archiso-work"
STAGED = ROOT / ".artifacts/archiso-profile"
DEFAULT_BINARIES = ROOT / "target/release"
SHELL_BRIDGE_SOURCE = ROOT / "apps/linura-shell/bridge"
SHELL_BRIDGE_BUILD = ROOT / ".artifacts/linura-shell-bridge-build"
UI_SDK_SOURCE = ROOT / "apps/linura-shell/ui"
UI_SDK_BUILD = ROOT / ".artifacts/linura-ui-build"


@dataclass(frozen=True)
class ImagePaths:
    output: Path
    work: Path
    staged: Path
    bridge: Path
    ui: Path


def reserve_image_paths(args: argparse.Namespace) -> ImagePaths:
    """Create only a new disposable image workspace on verified storage.

    Directory-relative, no-follow opens keep creation inside the selected tree.
    An existing image workspace is retained, never implicitly overwritten/purged.
    """
    paths = storage.execution_layout(ROOT, args, "archiso-build")
    parent = Path(paths["generated"]["cmake-build"])
    selected_root = storage.directory(args.storage_root)
    image = parent / "image"
    storage_execution.private_tree(selected_root, image, exclusive=True)
    return ImagePaths(
        image / "iso", image / "work", image / "profile", image / "bridge", image / "ui"
    )


SHELL_BRIDGE_QT_MODULES = ("Qt6Core", "Qt6DBus", "Qt6Qml")
UI_SDK_QT_MODULES = ("Qt6Core", "Qt6Qml", "Qt6Quick", "Qt6QuickControls2")
DOCTOR_QT_MODULES = tuple(dict.fromkeys(SHELL_BRIDGE_QT_MODULES + UI_SDK_QT_MODULES))

BINARIES = {
    "linurad": "usr/bin/linurad",
    "linuractl": "usr/bin/linuractl",
    "linura-firstboot": "usr/bin/linura-firstboot",
    "linura-update-guard": "usr/lib/linura/linura-update-guard",
    "linura-executor-systemd": "usr/lib/linura/linura-executor-systemd",
    "linura-authorityd": "usr/lib/linura/linura-authorityd",
}

RUNTIME_ASSETS = {
    ROOT
    / "packaging/wireplumber/linura-session-audio.lua": "usr/lib/linura/linura-session-audio.lua",
    ROOT
    / "packaging/systemd/user/linurad.service": "usr/lib/systemd/user/linurad.service",
    ROOT
    / "packaging/systemd/user/linura-shell.service": "usr/lib/systemd/user/linura-shell.service",
    ROOT / "apps/linura-shell/shell.qml": "usr/share/linura/shell/shell.qml",
    ROOT
    / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml": "usr/share/linura/shell/plugins/control-center/ControlCenterPanel.qml",
    ROOT
    / "apps/linura-shell/plugins/control-center/manifest.json": "usr/share/linura/shell/plugins/control-center/manifest.json",
    ROOT
    / "apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml": "usr/share/linura/shell/plugins/quick-settings/QuickSettingsPanel.qml",
    ROOT
    / "apps/linura-shell/plugins/quick-settings/manifest.json": "usr/share/linura/shell/plugins/quick-settings/manifest.json",
    ROOT
    / "apps/linura-shell/plugins/command-palette/CommandPalette.qml": "usr/share/linura/shell/plugins/command-palette/CommandPalette.qml",
    ROOT
    / "apps/linura-shell/plugins/command-palette/manifest.json": "usr/share/linura/shell/plugins/command-palette/manifest.json",
    ROOT
    / "apps/linura-shell/plugins/notifications-osd/LifecycleFeedback.qml": "usr/share/linura/shell/plugins/notifications-osd/LifecycleFeedback.qml",
    ROOT
    / "apps/linura-shell/plugins/notifications-osd/manifest.json": "usr/share/linura/shell/plugins/notifications-osd/manifest.json",
    ROOT
    / "apps/linura-shell/panel/WorkstationPanel.qml": "usr/share/linura/shell/panel/WorkstationPanel.qml",
    ROOT
    / "apps/linura-shell/tray/SystemTrayView.qml": "usr/share/linura/shell/tray/SystemTrayView.qml",
    ROOT
    / "apps/linura-shell/status/WorkstationStatus.qml": "usr/share/linura/shell/status/WorkstationStatus.qml",
    ROOT
    / "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml": "usr/share/linura/shell/integrations/hyprland/WorkspaceNavigationController.qml",
    ROOT
    / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml": "usr/share/linura/shell/integrations/xdg/ApplicationLauncherController.qml",
    ROOT
    / "apps/linura-shell/org.linura.ControlCenter.desktop": "usr/share/applications/org.linura.ControlCenter.desktop",
    ROOT
    / "apps/linura-shell/org.linura.QuickSettings.desktop": "usr/share/applications/org.linura.QuickSettings.desktop",
    ROOT
    / "apps/linura-shell/org.linura.CommandPalette.desktop": "usr/share/applications/org.linura.CommandPalette.desktop",
}


def mkarchiso_command(paths: ImagePaths) -> list[str]:
    return [
        "mkarchiso",
        "-v",
        "-w",
        str(paths.work),
        "-o",
        str(paths.output),
        str(paths.staged),
    ]


def have_qt_modules(modules: tuple[str, ...]) -> bool:
    return (
        subprocess.run(
            ["pkg-config", "--exists", *modules],
            check=False,
        ).returncode
        == 0
    )


def build_shell_bridge(profile: Path, build: Path) -> None:
    required_tools = ("cmake", "ninja", "pkg-config")
    missing_tools = [name for name in required_tools if shutil.which(name) is None]
    if missing_tools:
        raise RuntimeError(
            "missing shell-bridge build tools: " + ", ".join(missing_tools)
        )

    if not have_qt_modules(SHELL_BRIDGE_QT_MODULES):
        raise RuntimeError(
            "Qt6Core/Qt6DBus/Qt6Qml development metadata is required to build Linura Shell bridge"
        )

    subprocess.run(
        [
            "cmake",
            "-S",
            str(SHELL_BRIDGE_SOURCE),
            "-B",
            str(build),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
        ],
        check=True,
    )
    subprocess.run(
        ["cmake", "--build", str(build), "--parallel", "1"],
        check=True,
    )
    subprocess.run(
        [
            "cmake",
            "--install",
            str(build),
            "--prefix",
            str(profile / "airootfs/usr"),
        ],
        check=True,
    )


def build_ui_sdk(profile: Path, build: Path) -> None:
    required_tools = ("cmake", "ninja", "pkg-config")
    missing_tools = [name for name in required_tools if shutil.which(name) is None]
    if missing_tools:
        raise RuntimeError(
            "missing Linura UI SDK build tools: " + ", ".join(missing_tools)
        )

    if not have_qt_modules(UI_SDK_QT_MODULES):
        raise RuntimeError(
            "Qt6Core/Qt6Qml/Qt6Quick/Qt6QuickControls2 development metadata "
            "is required to build the Linura UI SDK"
        )

    subprocess.run(
        [
            "cmake",
            "-S",
            str(UI_SDK_SOURCE),
            "-B",
            str(build),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
        ],
        check=True,
    )
    subprocess.run(
        ["cmake", "--build", str(build), "--parallel", "1"],
        check=True,
    )
    subprocess.run(
        [
            "cmake",
            "--install",
            str(build),
            "--prefix",
            str(profile / "airootfs/usr"),
        ],
        check=True,
    )


def install_binaries(profile: Path, binaries_dir: Path) -> None:
    missing = [name for name in BINARIES if not (binaries_dir / name).is_file()]
    if missing:
        raise RuntimeError(
            f"missing release binaries in {binaries_dir}: {', '.join(missing)}; run cargo build --workspace --release --locked first"
        )
    for name, relative in BINARIES.items():
        destination = profile / "airootfs" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binaries_dir / name, destination)
        destination.chmod(0o755)
    for source, relative in RUNTIME_ASSETS.items():
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(
                f"missing or non-regular trusted runtime asset: {source}"
            )
        destination = profile / "airootfs" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        destination.chmod(0o644)

    user_unit_dir = profile / "airootfs/usr/lib/systemd/user"
    service_links = {
        user_unit_dir / "default.target.wants/linurad.service": "../linurad.service",
        user_unit_dir
        / "graphical-session.target.wants/linura-shell.service": "../linura-shell.service",
    }
    for link, target in service_links.items():
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(target)

    hook_dir = profile / "airootfs/etc/pacman.d/hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        ROOT / "packaging/arch/hooks/95-linura-update-guard.hook",
        hook_dir / "95-linura-update-guard.hook",
    )


def stage_profile(binaries_dir: Path, paths: ImagePaths) -> None:
    if not RELENG.is_dir():
        raise RuntimeError(f"ArchISO releng profile missing: {RELENG}")
    shutil.copytree(RELENG, paths.staged, symlinks=True)

    for name in ("profiledef.sh", "pacman.conf"):
        shutil.copy2(OVERLAY / name, paths.staged / name)
    shutil.copytree(OVERLAY / "airootfs", paths.staged / "airootfs", dirs_exist_ok=True)

    additions = [
        line.strip()
        for line in (OVERLAY / "packages.linura")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.startswith("#")
    ]
    package_file = paths.staged / "packages.x86_64"
    existing = [
        line.rstrip() for line in package_file.read_text(encoding="utf-8").splitlines()
    ]
    names = {
        line.strip() for line in existing if line.strip() and not line.startswith("#")
    }
    merged = existing + [package for package in additions if package not in names]
    package_file.write_text("\n".join(merged).rstrip() + "\n", encoding="utf-8")
    install_binaries(paths.staged, binaries_dir)
    build_shell_bridge(paths.staged, paths.bridge)
    build_ui_sdk(paths.staged, paths.ui)


def main() -> int:
    parser = argparse.ArgumentParser(description="Linura Arch image harness")
    parser.add_argument("command", choices=["plan", "stage", "build", "doctor"])
    parser.add_argument("--binaries-dir", type=Path, default=DEFAULT_BINARIES)
    storage.add_storage_options(parser)
    args = parser.parse_args()
    if args.command == "doctor":
        path = shutil.which("mkarchiso")
        print(f"mkarchiso: {path or 'missing'}")
        print(f"releng profile: {RELENG if RELENG.is_dir() else 'missing'}")
        missing = [
            name for name in BINARIES if not (args.binaries_dir / name).is_file()
        ]
        print(
            f"release binaries: {'missing ' + ', '.join(missing) if missing else 'present'}"
        )
        shell_tools = {
            name: shutil.which(name) for name in ("cmake", "ninja", "pkg-config")
        }
        print(
            "shell bridge tools: "
            + ", ".join(
                f"{name}={value or 'missing'}" for name, value in shell_tools.items()
            )
        )
        qt_ready = all(shell_tools.values()) and have_qt_modules(DOCTOR_QT_MODULES)
        print(f"shell/UI Qt6 dev metadata: {'present' if qt_ready else 'missing'}")
        return (
            0
            if path
            and RELENG.is_dir()
            and not missing
            and all(shell_tools.values())
            and qt_ready
            else 1
        )
    if args.command == "plan":
        print("1. cargo build --workspace --release --locked")
        print(f"2. copy {RELENG} -> {STAGED}")
        print(f"3. overlay Linura profile/security files from {OVERLAY}")
        print("4. merge packages.linura into releng packages.x86_64")
        print(
            f"5. stage Linura binaries from {args.binaries_dir}, trusted runtime assets, and the update guard hook"
        )
        print(
            "6. build and install the Linura Shell Qt/D-Bus QML bridge into the staged image"
        )
        print(
            "7. build and install the first-party org.linura.UI QML module into the staged image"
        )
        planned = ImagePaths(OUT, WORK, STAGED, SHELL_BRIDGE_BUILD, UI_SDK_BUILD)
        print(f"8. {shlex.join(mkarchiso_command(planned))}")
        print(
            "Execution requires dedicated storage and a new --run; these are preview paths only."
        )
        return 0
    if shutil.which("mkarchiso") is None:
        print(
            "mkarchiso is required to stage/build the Arch development image",
            file=sys.stderr,
        )
        return 2
    try:
        paths = reserve_image_paths(args)
        paths.work.mkdir(mode=0o700)
        # Private process environment only: image/CMake/compiler temporary work
        # cannot inherit a root-backed scratch directory from the invoking shell.
        os.environ["TMPDIR"] = str(paths.work)
        stage_profile(args.binaries_dir, paths)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        return 2
    print(f"staged profile: {paths.staged}")
    if args.command == "stage":
        return 0
    try:
        paths.output.mkdir(mode=0o700)
        print(shlex.join(mkarchiso_command(paths)))
        return subprocess.run(mkarchiso_command(paths), check=False).returncode
    except (OSError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
