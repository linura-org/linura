#!/usr/bin/env python3
"""Capture a typed identity for a disposable qualification guest over SSH."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9._+-]+$")
SSH = Path("/usr/bin/ssh")
CAPTURE_KEYS = {
    "architecture",
    "kernel_release",
    "os_release_sha256",
    "distribution_id",
    "distribution_version",
    "package_manager",
    "package_manifest_sha256",
    "package_count",
    "virtualization",
}


class GuestIdentityError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GuestIdentityError(message)


def _remote_script(package_manager: str) -> str:
    if package_manager == "dpkg":
        manifest = "/usr/bin/dpkg-query -W -f=\'${binary:Package}\\t${Version}\\n\' | /usr/bin/sort > \"$manifest\""
    elif package_manager == "pacman":
        manifest = "/usr/bin/pacman -Q | /usr/bin/sort > \"$manifest\""
    else:
        raise GuestIdentityError(f"unsupported guest package manager: {package_manager}")
    return "\n".join([
        "set -euo pipefail",
        "export LANG=C LC_ALL=C",
        "os_release_target=\"$(/usr/bin/readlink -f /etc/os-release)\"",
        "case \"$os_release_target\" in",
        "  /etc/os-release|/usr/lib/os-release) ;;",
        "  *) printf \'%s\\n\' \"unsafe os-release target: $os_release_target\" >&2; exit 2 ;;",
        "esac",
        "architecture=\"$(/usr/bin/uname -m)\"",
        "kernel_release=\"$(/usr/bin/uname -r)\"",
        "virtualization=\"$(/usr/bin/systemd-detect-virt)\"",
        "os_release_sha256=\"$(/usr/bin/sha256sum \"$os_release_target\" | /usr/bin/awk \'{print $1}\')\"",
        "distribution_id=\"$(/usr/bin/sed -n \'s/^ID=//p\' /etc/os-release | /usr/bin/tr -d \'\\\"\')\"",
        "distribution_version=\"$(/usr/bin/sed -n \'s/^VERSION_ID=//p\' /etc/os-release | /usr/bin/tr -d \'\\\"\')\"",
        "if [[ -z \"$distribution_version\" ]]; then",
        "  distribution_version=\"$(/usr/bin/sed -n \'s/^BUILD_ID=//p\' /etc/os-release | /usr/bin/tr -d \'\\\"\')\"",
        "fi",
        "manifest=\"$(/usr/bin/mktemp)\"",
        "trap \'/usr/bin/rm -f \"$manifest\"\' EXIT",
        manifest,
        "package_manifest_sha256=\"$(/usr/bin/sha256sum \"$manifest\" | /usr/bin/awk \'{print $1}\')\"",
        "package_count=\"$(/usr/bin/wc -l < \"$manifest\" | /usr/bin/awk \'{print $1}\')\"",
        "printf \'architecture=%s\\n\' \"$architecture\"",
        "printf \'kernel_release=%s\\n\' \"$kernel_release\"",
        "printf \'os_release_sha256=%s\\n\' \"$os_release_sha256\"",
        "printf \'distribution_id=%s\\n\' \"$distribution_id\"",
        "printf \'distribution_version=%s\\n\' \"$distribution_version\"",
        f"printf \'package_manager=%s\\n\' \"{package_manager}\"",
        "printf \'package_manifest_sha256=%s\\n\' \"$package_manifest_sha256\"",
        "printf \'package_count=%s\\n\' \"$package_count\"",
        "printf \'virtualization=%s\\n\' \"$virtualization\"",
        "",
    ])


def _parse_capture_output(text: str, package_manager: str) -> dict:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        _require(separator == "=" and name and value, f"invalid guest identity record: {line!r}")
        _require(name not in parsed, f"duplicate guest identity record: {name}")
        parsed[name] = value
    _require(set(parsed) == CAPTURE_KEYS, "guest identity field set mismatch")
    _require(TOKEN.fullmatch(parsed["architecture"]) is not None, "invalid guest architecture")
    _require("\n" not in parsed["kernel_release"] and "\r" not in parsed["kernel_release"], "invalid guest kernel release")
    _require(HEX64.fullmatch(parsed["os_release_sha256"]) is not None, "invalid guest os-release digest")
    _require(TOKEN.fullmatch(parsed["distribution_id"]) is not None, "invalid guest distribution id")
    _require(TOKEN.fullmatch(parsed["distribution_version"]) is not None, "invalid guest distribution version")
    _require(parsed["package_manager"] == package_manager, "guest package manager mismatch")
    _require(HEX64.fullmatch(parsed["package_manifest_sha256"]) is not None, "invalid guest package manifest digest")
    _require(parsed["package_count"].isdigit() and int(parsed["package_count"]) > 0, "invalid guest package count")
    _require(TOKEN.fullmatch(parsed["virtualization"]) is not None, "invalid guest virtualization identity")
    return {
        "schema_version": 1,
        "kind": "virtual-machine",
        "architecture": parsed["architecture"],
        "kernel_release": parsed["kernel_release"],
        "os_release_sha256": parsed["os_release_sha256"],
        "distribution_id": parsed["distribution_id"],
        "distribution_version": parsed["distribution_version"],
        "package_manager": parsed["package_manager"],
        "package_manifest_sha256": parsed["package_manifest_sha256"],
        "package_count": int(parsed["package_count"]),
        "virtualization": parsed["virtualization"],
    }


def _trusted_ssh() -> str:
    try:
        resolved = SSH.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GuestIdentityError(f"trusted ssh client is unavailable: {exc}") from exc
    _require(resolved.is_file() and os.access(resolved, os.X_OK), "trusted ssh client is unavailable")
    info = resolved.stat()
    _require(info.st_uid == 0 and not (info.st_mode & 0o022), "trusted ssh client is writable or not root-owned")
    return str(resolved)


def capture_ssh(*, host: str, port: int, user: str, identity: Path, package_manager: str) -> dict:
    _require(identity.is_file() and not identity.is_symlink(), "SSH identity is missing or unsafe")
    _require(not (identity.stat().st_mode & 0o022), "SSH identity is group/world writable")
    command = [
        _trusted_ssh(),
        "-i", str(identity),
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-p", str(port),
        f"{user}@{host}",
        "/usr/bin/bash", "-s",
    ]
    completed = subprocess.run(
        command,
        input=_remote_script(package_manager),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    _require(completed.returncode == 0, "guest identity capture failed: " + completed.stderr.strip())
    return _parse_capture_output(completed.stdout, package_manager)


def _atomic_json(path: Path, payload: dict) -> None:
    _require(not path.exists() or not path.is_symlink(), "guest identity output may not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _append_github_env(path: Path, payload: dict) -> None:
    values = {
        "GUEST_ARCHITECTURE": payload["architecture"],
        "GUEST_KERNEL_RELEASE": payload["kernel_release"],
        "GUEST_OS_RELEASE_SHA256": payload["os_release_sha256"],
        "GUEST_DISTRIBUTION_ID": payload["distribution_id"],
        "GUEST_DISTRIBUTION_VERSION": payload["distribution_version"],
        "GUEST_PACKAGE_MANAGER": payload["package_manager"],
        "GUEST_PACKAGE_MANIFEST_SHA256": payload["package_manifest_sha256"],
        "GUEST_PACKAGE_COUNT": str(payload["package_count"]),
        "GUEST_VIRTUALIZATION": payload["virtualization"],
    }
    with path.open("a", encoding="utf-8") as handle:
        for name, value in values.items():
            _require("\n" not in value and "\r" not in value, f"unsafe GitHub environment value: {name}")
            handle.write(f"{name}={value}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture-ssh")
    capture.add_argument("--host", default="127.0.0.1")
    capture.add_argument("--port", required=True, type=int)
    capture.add_argument("--user", required=True)
    capture.add_argument("--identity", required=True, type=Path)
    capture.add_argument("--package-manager", choices=("dpkg", "pacman"), required=True)
    capture.add_argument("--output", required=True, type=Path)
    capture.add_argument("--github-env", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command != "capture-ssh":
            raise GuestIdentityError(f"unsupported command: {args.command}")
        payload = capture_ssh(
            host=args.host,
            port=args.port,
            user=args.user,
            identity=args.identity,
            package_manager=args.package_manager,
        )
        _atomic_json(args.output, payload)
        if args.github_env is not None:
            _append_github_env(args.github_env, payload)
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except GuestIdentityError as exc:
        print(f"guest identity error: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
