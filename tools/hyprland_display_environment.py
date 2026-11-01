#!/usr/bin/env python3
"""Verify and complete the pinned S21-2 SDK inside its disposable Arch guest.

Called by the existing substrate builder. Never installs packages on the host;
readiness and a prepared image are not native qualification evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/s21-hyprland-build-environment.toml"
DIGEST = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z0-9][a-z0-9@._+-]*")
VERSION = re.compile(r"[A-Za-z0-9:._+~-]+")
REQUIRED = {
    "base-devel",
    "cmake",
    "ninja",
    "pkgconf",
    "git",
    "meson",
    "hyprland",
    "hyprland-protocols",
    "hyprwayland-scanner",
    "xorgproto",
    "gtest",
    "libglvnd",
    "mesa",
    "glslang",
    "libei",
    "hyprwire",
    "wayland",
    "wayland-protocols",
    "aquamarine",
    "hyprutils",
    "hyprgraphics",
    "hyprlang",
    "hyprcursor",
    "gcc",
    "libinput",
    "lua",
    "re2",
    "muparser",
    "lcms2",
    "cairo",
    "pango",
    "pixman",
    "libdrm",
    "tomlplusplus",
    "systemd-libs",
}


def load_contract(path: Path) -> dict:
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("symlinked build environment contract")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    integration = tomllib.loads(
        (ROOT / "contracts/hyprland-display-integration.toml").read_text()
    )
    if (
        data.get("schema_version") != 1
        or data.get("id") != "qualification/s21-hyprland-build-substrate"
        or data.get("architecture") != "x86_64"
        or data.get("build_type") != "Debug"
        or data.get("fetchcontent_fully_disconnected") is not True
        or not DIGEST.fullmatch(data.get("base_image_sha256", ""))
    ):
        raise ValueError("unsupported compositor build environment")
    records = data.get("package", [])
    packages = {}
    for record in records:
        name, version, digest = (
            record.get(key, "") for key in ("name", "version", "sha256")
        )
        if (
            not NAME.fullmatch(name)
            or not VERSION.fullmatch(version)
            or not DIGEST.fullmatch(digest)
            or name in packages
        ):
            raise ValueError("malformed or duplicate SDK package lock")
        packages[name] = record
    if (
        not REQUIRED <= packages.keys()
        or not set(data.get("runtime_packages", [])) <= packages.keys()
    ):
        raise ValueError("incomplete compositor SDK dependency lock")
    if packages["hyprland"]["version"].split("-")[0] != integration["upstream_version"]:
        raise ValueError("compositor package/source version mismatch")
    repositories = data.get("repository_sha256", {})
    if set(repositories) != {"core", "extra"} or any(
        not DIGEST.fullmatch(value) for value in repositories.values()
    ):
        raise ValueError("incomplete pinned dependency repositories")
    archive = data.get("archived_package", {})
    if (
        archive.get("name") != "glaze"
        or archive.get("version") != "7.2.0-1"
        or archive.get("url")
        != "https://archive.archlinux.org/packages/g/glaze/glaze-7.2.0-1-any.pkg.tar.zst"
        or not DIGEST.fullmatch(archive.get("sha256", ""))
        or archive.get("signature_required") is not True
    ):
        raise ValueError("unsupported archived Glaze SDK")
    return data


def repository_script(data: dict) -> str:
    lines = ["set -euo pipefail", "sudo -n pacman -Syy --noconfirm"]
    for name, digest in sorted(data["repository_sha256"].items()):
        lines.append(
            f"printf '%s\\n' {shlex.quote(digest + '  /var/lib/pacman/sync/' + name + '.db')} | sha256sum --check --strict"
        )
    # The database digest fixes transitive resolution. Check that the reviewed
    # direct SDK package hashes and versions describe those same databases.
    verification = """import json,tarfile
expected=json.loads(EXPECTED)
observed={}
for repository in ('core','extra'):
    with tarfile.open('/var/lib/pacman/sync/'+repository+'.db') as archive:
        for member in archive:
            if not member.name.endswith('/desc'): continue
            stream=archive.extractfile(member)
            if stream is None: raise SystemExit('missing repository metadata')
            fields={}
            for section in stream.read().decode().strip().split('\\n\\n'):
                lines=section.splitlines()
                fields[lines[0].strip('%')]=lines[1:]
            observed[fields['NAME'][0]]=fields
for record in expected:
    entry=observed.get(record['name'],{})
    if entry.get('VERSION') != [record['version']] or entry.get('SHA256SUM') != [record['sha256']]:
        raise SystemExit('SDK package lock differs from pinned repository: '+record['name'])
""".replace("EXPECTED", repr(json.dumps(data["package"])))
    lines.append("python3 -c " + shlex.quote(verification))
    return "\n".join(lines) + "\n"


def dependency_script(data: dict) -> str:
    archive = data["archived_package"]
    lines = [
        "set -euo pipefail",
        "umask 077",
        "sdk_work=$(mktemp -d /tmp/linura-s21-sdk.XXXXXXXX)",
        # This removes only this script's fresh disposable-guest scratch.
        "trap 'rm -rf -- \"$sdk_work\"' EXIT",
        'cd "$sdk_work"',
        "curl --fail --location --max-time 120 --output glaze.pkg.tar.zst "
        + shlex.quote(archive["url"]),
        "curl --fail --location --max-time 120 --output glaze.pkg.tar.zst.sig "
        + shlex.quote(archive["url"] + ".sig"),
        "printf '%s\\n' "
        + shlex.quote(archive["sha256"] + "  glaze.pkg.tar.zst")
        + " | sha256sum --check --strict",
        "sudo -n pacman-key --verify glaze.pkg.tar.zst.sig glaze.pkg.tar.zst",
        "sudo -n pacman -U --noconfirm -- glaze.pkg.tar.zst",
    ]
    for record in [*data["package"], archive]:
        expected = record["name"] + " " + record["version"]
        lines.append(
            'test "$(pacman -Q -- '
            + shlex.quote(record["name"])
            + ')" = '
            + shlex.quote(expected)
        )
    lines.extend(
        [
            "test -f /usr/include/GLES3/gl3.h",
            "pkg-config --exists glesv2 egl wayland-server aquamarine hyprutils hyprgraphics hyprlang hyprcursor hyprwire libeis-1.0 libsystemd",
            "mkdir probe",
            "cat > probe/CMakeLists.txt <<'CMAKE'",
            "cmake_minimum_required(VERSION 3.30)",
            "project(linura_s21_sdk_probe LANGUAGES C CXX)",
            "find_package(OpenGL REQUIRED COMPONENTS GLES3)",
            "find_package(glaze 7...<8 REQUIRED)",
            "find_package(glslang CONFIG REQUIRED)",
            "find_package(hyprwayland-scanner 0.3.10 REQUIRED)",
            "CMAKE",
            "cmake -S probe -B probe-build -DFETCHCONTENT_FULLY_DISCONNECTED=ON",
            "printf '%s\\n' 'S21-2 compositor SDK verified; native qualification has not run.'",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument(
        "--phase", choices=("repositories", "dependencies"), required=True
    )
    args = parser.parse_args()
    data = load_contract(args.contract)
    script = (
        repository_script(data)
        if args.phase == "repositories"
        else dependency_script(data)
    )
    subprocess.run(
        [
            "ssh",
            "-i",
            str(args.ssh_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "-p",
            "2223",
            "linura@127.0.0.1",
            "timeout",
            "--signal=TERM",
            "--kill-after=10s",
            "300",
            "bash",
            "-s",
        ],
        input=script,
        text=True,
        check=True,
        timeout=320,
    )


if __name__ == "__main__":
    main()
