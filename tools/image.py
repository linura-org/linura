#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "packaging/arch/archiso"
RELENG = Path("/usr/share/archiso/configs/releng")
OUT = ROOT / ".artifacts/iso"
WORK = ROOT / ".artifacts/archiso-work"
STAGED = ROOT / ".artifacts/archiso-profile"
DEFAULT_BINARIES = ROOT / "target/release"

BINARIES = {
    "linurad": "usr/bin/linurad",
    "linuractl": "usr/bin/linuractl",
    "linura-update-guard": "usr/lib/linura/linura-update-guard",
    "linura-executor-systemd": "usr/lib/linura/linura-executor-systemd",
    "linura-authorityd": "usr/lib/linura/linura-authorityd",
}


def mkarchiso_command(profile: Path = STAGED) -> list[str]:
    return ["mkarchiso", "-v", "-w", str(WORK), "-o", str(OUT), str(profile)]


def install_binaries(profile: Path, binaries_dir: Path) -> None:
    missing = [name for name in BINARIES if not (binaries_dir / name).is_file()]
    if missing:
        raise RuntimeError(f"missing release binaries in {binaries_dir}: {', '.join(missing)}; run cargo build --workspace --release --locked first")
    for name, relative in BINARIES.items():
        destination = profile / "airootfs" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binaries_dir / name, destination)
        destination.chmod(0o755)
    hook_dir = profile / "airootfs/etc/pacman.d/hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "packaging/arch/hooks/95-linura-update-guard.hook", hook_dir / "95-linura-update-guard.hook")


def stage_profile(binaries_dir: Path) -> None:
    if not RELENG.is_dir():
        raise RuntimeError(f"ArchISO releng profile missing: {RELENG}")
    if STAGED.exists():
        shutil.rmtree(STAGED)
    shutil.copytree(RELENG, STAGED, symlinks=True)

    for name in ("profiledef.sh", "pacman.conf"):
        shutil.copy2(OVERLAY / name, STAGED / name)
    shutil.copytree(OVERLAY / "airootfs", STAGED / "airootfs", dirs_exist_ok=True)

    additions = [line.strip() for line in (OVERLAY / "packages.linura").read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    package_file = STAGED / "packages.x86_64"
    existing = [line.rstrip() for line in package_file.read_text(encoding="utf-8").splitlines()]
    names = {line.strip() for line in existing if line.strip() and not line.startswith("#")}
    merged = existing + [package for package in additions if package not in names]
    package_file.write_text("\n".join(merged).rstrip() + "\n", encoding="utf-8")
    install_binaries(STAGED, binaries_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="Linura Arch image harness")
    parser.add_argument("command", choices=["plan", "stage", "build", "doctor"])
    parser.add_argument("--binaries-dir", type=Path, default=DEFAULT_BINARIES)
    args = parser.parse_args()
    if args.command == "doctor":
        path = shutil.which("mkarchiso")
        print(f"mkarchiso: {path or 'missing'}")
        print(f"releng profile: {RELENG if RELENG.is_dir() else 'missing'}")
        missing = [name for name in BINARIES if not (args.binaries_dir / name).is_file()]
        print(f"release binaries: {'missing ' + ', '.join(missing) if missing else 'present'}")
        return 0 if path and RELENG.is_dir() and not missing else 1
    if args.command == "plan":
        print(f"1. cargo build --workspace --release --locked")
        print(f"2. copy {RELENG} -> {STAGED}")
        print(f"3. overlay Linura profile/security files from {OVERLAY}")
        print("4. merge packages.linura into releng packages.x86_64")
        print(f"5. stage Linura binaries from {args.binaries_dir} and install update guard hook atomically")
        print(f"6. {shlex.join(mkarchiso_command())}")
        return 0
    if shutil.which("mkarchiso") is None:
        print("mkarchiso is required to stage/build the Arch development image", file=sys.stderr)
        return 2
    try:
        stage_profile(args.binaries_dir)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 2
    print(f"staged profile: {STAGED}")
    if args.command == "stage":
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    print(shlex.join(mkarchiso_command()))
    return subprocess.run(mkarchiso_command(), check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
