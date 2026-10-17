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
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


SOURCE_ROOT = Path("/opt/linura-source")
BINARY_ROOT = Path("/tmp/linura-s17-binaries")


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True, timeout=15).strip()


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


def provision() -> None:
    require_disposable_guest()
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
        subprocess.run(
            ["cmake", "--build", str(build_root), "--parallel", "2"],
            check=True,
            timeout=900,
        )
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
            ],
            check=True,
            timeout=60,
        )
        subprocess.run(
            ["cmake", "--build", str(probe_build), "--parallel", "2"],
            check=True,
            timeout=120,
        )
        probe_destination = Path(
            "/usr/lib/linura/qualification/linura-s17-assistive-probe"
        )
        probe_destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(probe_build / "linura-s17-assistive-probe", probe_destination)
        probe_destination.chmod(0o755)
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
