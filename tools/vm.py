#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = ROOT / ".artifacts/linura-dev.qcow2"
ACCELERATORS = ("auto", "kvm", "tcg")
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def kvm_available() -> bool:
    """Return whether this process can actually open the KVM device read/write.

    Some CI hosts expose ``/dev/kvm`` while denying access to the job. Existence
    alone is therefore not evidence that QEMU can initialize KVM.
    """
    path = Path("/dev/kvm")
    if not path.exists():
        return False
    try:
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    except OSError:
        return False
    os.close(fd)
    return True


def resolve_acceleration(requested: str) -> str:
    if requested not in ACCELERATORS:
        raise ValueError(f"unsupported accelerator: {requested}")
    if requested == "auto":
        return "kvm" if kvm_available() else "tcg"
    return requested


def validate_uuid(value: str | None) -> str | None:
    if value is None:
        return None
    if not UUID_PATTERN.fullmatch(value) or value.lower() == "00000000-0000-0000-0000-000000000000":
        raise ValueError("--uuid must be a canonical nonzero UUID")
    return value.lower()


def qemu_command(
    image: Path,
    memory: int,
    cpus: int,
    ssh_port: int,
    seed: Path | None = None,
    acceleration: str = "auto",
    persistent: bool = False,
    hardware_uuid: str | None = None,
    ssh_guest_port: int = 22,
) -> list[str]:
    resolved_acceleration = resolve_acceleration(acceleration)
    hardware_uuid = validate_uuid(hardware_uuid)
    command = [
        "qemu-system-x86_64",
        "-machine",
        f"q35,accel={resolved_acceleration}",
        "-cpu",
        "host" if resolved_acceleration == "kvm" else "max",
        "-m",
        str(memory),
        "-smp",
        str(cpus),
        "-drive",
        f"file={image},if=virtio,format=qcow2",
    ]
    if seed is not None:
        command.extend(
            [
                "-drive",
                f"file={seed},if=virtio,format=raw,readonly=on",
            ]
        )
    if hardware_uuid is not None:
        command.extend(["-uuid", hardware_uuid])
    command.extend(
        [
            "-nic",
            (
                "user,model=virtio-net-pci,"
                f"hostfwd=tcp:127.0.0.1:{ssh_port}-:{ssh_guest_port}"
            ),
            "-display",
            "none",
            "-serial",
            "mon:stdio",
        ]
    )
    # Disposable acceptance remains snapshot-isolated by default. Durability
    # qualification opts into writes on an already disposable copied qcow2 so an
    # abrupt QEMU stop/restart can verify acknowledged state survives.
    if not persistent:
        command.append("-snapshot")
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description="Linura disposable QEMU/KVM harness")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "start"):
        command = sub.add_parser(name)
        command.add_argument("--image", type=Path, default=DEFAULT_IMAGE)
        command.add_argument("--seed", type=Path)
        command.add_argument("--memory", type=int, default=4096)
        command.add_argument("--cpus", type=int, default=4)
        command.add_argument("--ssh-port", type=int, default=2222)
        command.add_argument(
            "--ssh-guest-port",
            type=int,
            default=22,
            help="guest TCP port reached by the host SSH forward",
        )
        command.add_argument(
            "--accel",
            choices=ACCELERATORS,
            default="auto",
            help="QEMU accelerator: auto uses KVM only when /dev/kvm is actually openable",
        )
        command.add_argument(
            "--persistent",
            action="store_true",
            help=(
                "write to the supplied image instead of QEMU -snapshot mode; intended only "
                "for fault qualification on a disposable copied image"
            ),
        )
        command.add_argument(
            "--uuid",
            dest="hardware_uuid",
            help=(
                "explicit canonical nonzero QEMU system UUID; durability qualification should "
                "reuse it across restarts and change it deliberately for cloned-disk tests"
            ),
        )
    sub.add_parser("doctor")
    args = parser.parse_args()

    if args.command == "doctor":
        qemu = shutil.which("qemu-system-x86_64")
        ssh = shutil.which("ssh")
        if not Path("/dev/kvm").exists():
            kvm_status = "missing"
        elif kvm_available():
            kvm_status = "usable"
        else:
            kvm_status = "inaccessible"
        checks = {
            "qemu-system-x86_64": qemu or "missing",
            "ssh": ssh or "missing",
            "/dev/kvm": kvm_status,
        }
        for key, value in checks.items():
            print(f"{key}: {value}")
        return 0 if qemu and ssh else 1

    if args.command == "start" and args.accel == "kvm" and not kvm_available():
        print("KVM was explicitly requested but /dev/kvm is unavailable to this process", file=sys.stderr)
        return 2

    try:
        command = qemu_command(
            args.image,
            args.memory,
            args.cpus,
            args.ssh_port,
            args.seed,
            args.accel,
            args.persistent,
            args.hardware_uuid,
            args.ssh_guest_port,
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(shlex.join(command), flush=True)
    if args.command == "plan":
        return 0
    if shutil.which("qemu-system-x86_64") is None:
        print("qemu-system-x86_64 is required to start a disposable VM", file=sys.stderr)
        return 2
    if not args.image.is_file():
        print(f"image not found: {args.image}", file=sys.stderr)
        return 2
    if args.seed is not None and not args.seed.is_file():
        print(f"cloud-init seed not found: {args.seed}", file=sys.stderr)
        return 2

    # Replace the harness process with QEMU so callers can supervise and terminate
    # one PID without leaving an orphaned guest process behind.
    try:
        os.execvp(command[0], command)
    except OSError as error:
        print(f"failed to execute {command[0]}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
