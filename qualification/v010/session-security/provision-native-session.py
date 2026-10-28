#!/usr/bin/env python3
"""Install exact-source S17 runtime ONLY in the disposable Arch QEMU guest.

This creates a genuine local PAM/logind Wayland session, not qualification
evidence. Production attestation, capability guards and policy are unchanged.
The existing shell-runtime cases keep their own fixture and must still pass.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


SOURCE_ROOT = Path("/opt/linura-source")
BINARY_ROOT = Path("/tmp/linura-s17-binaries")
CANDIDATE_ROOT = Path("/opt/linura-s21-candidate")
SOURCE_SHA_FILE = Path("/etc/linura-qualification/s21-source-sha")
OWNER_BUILD_HEADER = Path("/etc/linura-qualification/s21-owner-build.h")
COMPOSITOR = Path("/usr/bin/Hyprland")


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True, timeout=15).strip()


def run_bounded_process_group(args: list[str], *, timeout: int) -> None:
    process = subprocess.Popen(args, start_new_session=True)
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode, args)


def native_owner_build_command(build_root: Path) -> list[str]:
    return [
        "cmake",
        "--build",
        str(build_root),
        "--target",
        "linura-security-owner",
        "--parallel",
        "4",
    ]


def require_disposable_guest() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("S17 provisioning requires root inside the disposable VM")
    if command("systemd-detect-virt", "--vm") not in {"qemu", "kvm"}:
        raise RuntimeError("S17 provisioning refuses non-QEMU/physical/container hosts")
    if os.uname().nodename != "linura-v010-shell":
        raise RuntimeError(
            "S17 provisioning requires the dedicated qualification guest"
        )
    if "ID=arch\n" not in Path("/etc/os-release").read_text(encoding="utf-8"):
        raise RuntimeError("S17 provisioning requires the pinned Arch substrate")
    for path in (
        Path("/opt"),
        SOURCE_ROOT,
        SOURCE_ROOT / "qualification/v010/session-security",
    ):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError(
                "exact-source qualification directory is not root immutable"
            )


def load_image_module():
    spec = importlib.util.spec_from_file_location(
        "linura_image", SOURCE_ROOT / "tools/image.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("exact-source image installer is unavailable")
    image = importlib.util.module_from_spec(spec)
    # Dataclass annotation resolution requires the module to be registered while
    # its exact-source code executes under Python 3.12.
    sys.modules[spec.name] = image
    try:
        spec.loader.exec_module(image)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return image


def require_root_file(path: Path) -> None:
    for parent in path.parents:
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("candidate installation parent is not root immutable")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
    ):
        raise RuntimeError("candidate installation asset is not root immutable")


def display_candidate(owner_header: Path | None = None):
    # Called only after the disposable-guest/root-immutable-source guard. Import
    # the checked repository helper; no caller-selected module or installer.
    sys.path.insert(0, str(SOURCE_ROOT))
    from tools import hyprland_display_candidate as candidate

    for name in (*candidate.FILES, candidate.MANIFEST):
        require_root_file(CANDIDATE_ROOT / name)
    require_root_file(SOURCE_SHA_FILE)
    sha = candidate.read_bounded(SOURCE_SHA_FILE, 41).decode("ascii").removesuffix("\n")
    metadata = candidate.verify(SOURCE_ROOT, CANDIDATE_ROOT, sha, owner_header)
    candidate.verify_runtime_packages(
        SOURCE_ROOT, CANDIDATE_ROOT, command("/usr/bin/pacman", "-Q")
    )
    return candidate, metadata


def install_display_candidate(owner_header: Path) -> None:
    require_disposable_guest()
    candidate, metadata = display_candidate(owner_header)
    require_root_file(COMPOSITOR)
    processes = list(Path("/proc").glob("[0-9]*/exe"))
    if len(processes) > 4096:
        raise RuntimeError("cannot bound compositor process enumeration")
    for process in processes:
        try:
            executable = process.readlink()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if str(executable).removesuffix(" (deleted)") == str(COMPOSITOR):
            raise RuntimeError(
                "reference compositor must exit before candidate installation"
            )
    staged = COMPOSITOR.with_name(".linura-s21-Hyprland")
    copied = candidate.artifacts._bind_file(
        CANDIDATE_ROOT / "Hyprland", staged, max_size=candidate.FILES["Hyprland"]
    )
    expected = metadata["files"]["Hyprland"]
    if copied != (expected["sha256"], expected["size"]):
        staged.unlink()
        raise RuntimeError("compositor candidate changed during installation")
    # Retain the actual freshly configured owner identity across guest reboots.
    candidate.artifacts._bind_file(
        owner_header,
        OWNER_BUILD_HEADER,
        max_size=candidate.FILES["integration-build.h"],
    )
    OWNER_BUILD_HEADER.chmod(0o644)
    staged.chmod(0o755)
    os.replace(staged, COMPOSITOR)
    descriptor = os.open(COMPOSITOR.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def inspect_display_candidate(compositor_pid: int) -> dict:
    require_disposable_guest()
    require_root_file(OWNER_BUILD_HEADER)
    require_root_file(COMPOSITOR)
    candidate, metadata = display_candidate(OWNER_BUILD_HEADER)
    process_image = Path(f"/proc/{compositor_pid}/exe")
    before = COMPOSITOR.stat()
    running = process_image.stat()
    if (running.st_dev, running.st_ino) != (before.st_dev, before.st_ino):
        raise RuntimeError(
            "native session is not executing the installed compositor candidate"
        )
    observed = candidate.artifacts._bind_file(
        COMPOSITOR, max_size=candidate.FILES["Hyprland"]
    )
    expected = metadata["files"]["Hyprland"]
    after = process_image.stat()
    if observed != (expected["sha256"], expected["size"]) or (
        after.st_dev,
        after.st_ino,
    ) != (before.st_dev, before.st_ino):
        raise RuntimeError(
            "executing native compositor differs from the built candidate"
        )
    return {
        "claim": "executing-exact-source-compositor-candidate",
        "source_sha": metadata["source_sha"],
        "binary_sha256": observed[0],
        "integration_source_digest": metadata["integration_source_digest"],
        "native_display_execution_qualified": False,
    }


def provision() -> None:
    require_disposable_guest()
    display_candidate()
    # Reuse the actual image asset graph instead of a looser qualification-only
    # runtime. Build outputs are installed afresh; never cached as substrate.
    image = load_image_module()
    for name in image.BINARIES:
        path = BINARY_ROOT / name
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("exact-source release binary is untrusted")
    with tempfile.TemporaryDirectory(
        prefix="linura-s17-install-", dir="/run"
    ) as directory:
        profile = Path(directory)
        image.install_binaries(profile, BINARY_ROOT)
        shutil.copytree(profile / "airootfs", "/", dirs_exist_ok=True, symlinks=True)
    subprocess.run(
        ["systemd-sysusers", "/usr/lib/sysusers.d/linura-authority.conf"],
        check=True,
        timeout=15,
    )
    build_root = Path(tempfile.mkdtemp(prefix="linura-s17-native-build-", dir="/tmp"))
    try:
        subprocess.run(
            [
                "cmake",
                "-S",
                str(SOURCE_ROOT / "apps/linura-shell/security-owner"),
                "-B",
                str(build_root),
                "-G",
                "Ninja",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DBUILD_TESTING=OFF",
                "-DLINURA_SECURITY_OWNER_NATIVE_AUTH=ON",
            ],
            check=True,
            timeout=60,
        )
        run_bounded_process_group(
            native_owner_build_command(build_root),
            timeout=900,
        )
        install_display_candidate(build_root / "linura-display-integration-build.h")
        subprocess.run(
            ["cmake", "--install", str(build_root), "--prefix", "/usr"],
            check=True,
            timeout=30,
        )
        # Read-only AT-SPI qualification client. It is not part of the product
        # image asset graph and receives no credentials or authority handles.
        probe_build = build_root / "native-probes"
        subprocess.run(
            [
                "cmake",
                "-S",
                str(SOURCE_ROOT / "qualification/v010/session-security"),
                "-B",
                str(probe_build),
                "-G",
                "Ninja",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DBUILD_TESTING=ON",
                "-DLINURA_DISPLAY_OWNER_ADMISSION_PROBE=ON",
            ],
            check=True,
            timeout=60,
        )
        run_bounded_process_group(
            ["cmake", "--build", str(probe_build), "--parallel", "2"],
            timeout=120,
        )
        run_bounded_process_group(
            ["ctest", "--test-dir", str(probe_build), "--output-on-failure"],
            timeout=30,
        )
        probe_destination = Path(
            "/usr/lib/linura/qualification/linura-s17-assistive-probe"
        )
        probe_destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(probe_build / "linura-s17-assistive-probe", probe_destination)
        probe_destination.chmod(0o755)
        admission_destination = (
            probe_destination.parent / "linura-s21-owner-admission-probe"
        )
        shutil.copyfile(probe_build / admission_destination.name, admission_destination)
        admission_destination.chmod(0o755)
    finally:
        shutil.rmtree(build_root)
    # Deliberate guest package-install boundary, AFTER final root ownership.
    # No host or component builder ever executes this helper.
    subprocess.run(
        ["/usr/lib/linura/linura-security-owner-install-capability"],
        check=True,
        timeout=15,
    )
    fixtures = SOURCE_ROOT / "qualification/v010/session-security/fixtures"
    for name, destination in (
        (
            "linura-s17-session.service",
            Path("/etc/systemd/system/linura-s17-session.service"),
        ),
        ("linura-s17-qualification.pam", Path("/etc/pam.d/linura-s17-qualification")),
        ("s17-hyprland.conf", Path("/etc/linura-qualification/s17-hyprland.conf")),
    ):
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(fixtures / name, destination)
        destination.chmod(0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=15)
    subprocess.run(["systemctl", "reload", "dbus.service"], check=True, timeout=15)
    subprocess.run(["systemctl", "restart", "polkit.service"], check=True, timeout=15)
    subprocess.run(
        ["systemctl", "start", "linura-authorityd.service"], check=True, timeout=30
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()  # No caller-selected user, source path or command.
    provision()


if __name__ == "__main__":
    main()
