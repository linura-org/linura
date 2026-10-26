#!/usr/bin/env python3
"""Plan or explicitly prepare native development dependencies; never qualify them."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from tools.check_toolchain_env import validate as tool_pins  # noqa: E402
from tools.codex import doctor  # noqa: E402

SPEC = "tools/codex/native-profiles.toml"
MAX_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 4096
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+._-]{0,127}(?::(?:amd64|all))?")
# Observed foreign-architecture records are valid host state, not effect targets.
OBSERVED_PACKAGE = re.compile(
    r"[a-z0-9][a-z0-9+._-]{0,127}(?::[a-z0-9][a-z0-9_-]{0,31})?"
)
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}")
SHA256 = re.compile(r"[0-9a-f]{64}")


class PreparationError(ValueError):
    """Closed diagnostic code, never subprocess output or environment values."""


@dataclass(frozen=True)
class Completed:
    code: int
    output: bytes


class Commands:
    def __init__(self, root: Path = ROOT, home: Path | None = None) -> None:
        self.root = root
        self.home = home or Path.home()
        # No loader/interpreter/package-manager overrides or shell startup hooks.
        self.env = {
            "HOME": str(self.home),
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C.UTF-8",
            "RUSTUP_AUTO_INSTALL": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }

    def run(
        self,
        args: list[str],
        *,
        timeout: float = 60,
        capture: bool = True,
        cwd: Path | None = None,
    ) -> Completed:
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                args,
                cwd=cwd or self.root,
                env=self.env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                # Preserve the caller's session for terminal-scoped sudo tickets,
                # but isolate the process group for bounded descendant cleanup.
                process_group=0,
            )
            if not capture:
                return Completed(process.wait(timeout=timeout), b"")
            assert process.stdout is not None
            deadline = time.monotonic() + timeout
            output = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise PreparationError("command_timeout")
                    for key, _ in selector.select(remaining):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(data)
                            if len(output) > MAX_BYTES:
                                raise PreparationError("command_output_limit")
                return Completed(
                    process.wait(timeout=max(0, deadline - time.monotonic())),
                    bytes(output),
                )
        except subprocess.TimeoutExpired as exc:
            raise PreparationError("command_timeout") from exc
        except OSError as exc:
            raise PreparationError("command_unavailable") from exc
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                if process.stdout is not None:
                    process.stdout.close()

    def query(self, args: list[str], *, timeout: float = 60) -> bytes:
        result = self.run(args, timeout=timeout)
        if result.code != 0:
            raise PreparationError("native_query_failed")
        return result.output

    def effect(
        self, args: list[str], *, timeout: float = 1800, cwd: Path | None = None
    ) -> None:
        if self.run(args, timeout=timeout, capture=False, cwd=cwd).code != 0:
            raise PreparationError("preparation_command_failed_reobserve_required")


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def read_regular(path: Path, limit: int = MAX_BYTES) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PreparationError("input_not_regular")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = stream.read(limit + 1)
    finally:
        os.close(fd)
    if len(value) > limit:
        raise PreparationError("input_limit")
    return value


def load_spec(root: Path = ROOT) -> dict[str, Any]:
    spec = tomllib.loads(read_regular(root / SPEC).decode("utf-8"))
    if set(spec) != {
        "schema_version",
        "host_os",
        "host_arch",
        "ubuntu_releases",
        "arch_database_max_age_hours",
        "plan_max_age_seconds",
        "profile",
    }:
        raise PreparationError("invalid_native_contract")
    if (
        type(spec["schema_version"]) is not int
        or spec["schema_version"] != 1
        or spec["host_os"] != "Linux"
        or spec["host_arch"] != "x86_64"
        or spec["ubuntu_releases"] != ["24.04", "26.04"]
        or type(spec["arch_database_max_age_hours"]) is not int
        or spec["arch_database_max_age_hours"] != 24
        or type(spec["plan_max_age_seconds"]) is not int
        or spec["plan_max_age_seconds"] != 900
    ):
        raise PreparationError("invalid_native_contract")
    if not isinstance(spec["profile"], dict) or set(spec["profile"]) != set(
        doctor.PROFILES
    ):
        raise PreparationError("native_profile_inventory_drift")
    for name, profile in spec["profile"].items():
        if not isinstance(profile, dict):
            raise PreparationError("invalid_profile_contract")
        if (
            not {"requires", "ubuntu", "arch"}
            <= set(profile)
            <= {"requires", "ubuntu", "arch", "supported"}
        ):
            raise PreparationError("invalid_profile_contract")
        for key in ("requires", "ubuntu", "arch"):
            values = profile[key]
            if (
                not isinstance(values, list)
                or any(not isinstance(item, str) for item in values)
                or len(set(values)) != len(values)
            ):
                raise PreparationError("invalid_profile_contract")
        if any(item not in spec["profile"] for item in profile["requires"]):
            raise PreparationError("invalid_profile_dependency")
        if any(
            PACKAGE.fullmatch(item) is None
            for key in ("ubuntu", "arch")
            for item in profile[key]
        ):
            raise PreparationError("invalid_package_name")
        if "supported" in profile and profile["supported"] != ["arch"]:
            raise PreparationError("invalid_profile_platform")
    return spec


def profiles(selected: list[str], spec: dict[str, Any]) -> list[str]:
    result: set[str] = set()
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if name not in spec["profile"]:
            raise PreparationError("unknown_profile")
        if name in visiting:
            raise PreparationError("profile_dependency_cycle")
        if name in result:
            return
        visiting.add(name)
        for dependency in spec["profile"][name]["requires"]:
            visit(dependency)
        visiting.remove(name)
        result.add(name)

    for name in ["core", *selected]:
        visit(name)
    return sorted(result)


def host(spec: dict[str, Any]) -> dict[str, str]:
    if platform.system() != spec["host_os"] or platform.machine() != spec["host_arch"]:
        raise PreparationError("unsupported_native_host")
    release = platform.freedesktop_os_release()
    identity = release.get("ID", "")
    version = release.get("VERSION_ID", "")
    if identity != "arch" and not (
        identity == "ubuntu" and version in spec["ubuntu_releases"]
    ):
        raise PreparationError("unsupported_native_distribution")
    return {
        "id": identity,
        "version": version if identity == "ubuntu" else "rolling",
        "architecture": "x86_64",
    }


def source_state(commands: Commands) -> str:
    value = hashlib.sha256()
    for args in (
        ["rev-parse", "HEAD"],
        ["ls-files", "--stage", "-z"],
        ["diff", "--no-ext-diff", "--no-textconv", "--binary"],
        ["diff", "--cached", "--no-ext-diff", "--no-textconv", "--binary"],
    ):
        data = commands.query(
            ["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false", *args]
        )
        value.update(len(data).to_bytes(8, "big"))
        value.update(data)
    return value.hexdigest()


def input_identity(root: Path) -> str:
    names = [
        SPEC,
        "tools/codex/versions.env",
        "tools/codex/native.py",
        "tools/codex/native_install.py",
        "tools/codex/doctor.py",
        "tools/check_toolchain_env.py",
        "scripts/setup_codex_environment.sh",
        "scripts/preflight_codex_environment.sh",
        "scripts/lib/codex_source_state.sh",
        "scripts/lib/bootstrap_rustup.sh",
        "tools/python/ruff-requirements.lock",
        "bindings/python/build-requirements.lock",
        "tools/python-typecheck/package.json",
        "tools/python-typecheck/package-lock.json",
        "Cargo.lock",
        "rust-toolchain.toml",
    ]
    return digest(
        {name: hashlib.sha256(read_regular(root / name)).hexdigest() for name in names}
    )


def package_pair(name: str, version: str, *, observed: bool = False) -> dict[str, str]:
    validator = OBSERVED_PACKAGE if observed else PACKAGE
    if validator.fullmatch(name) is None or VERSION.fullmatch(version) is None:
        raise PreparationError("invalid_package_metadata")
    return {
        "name": name.removesuffix(":amd64").removesuffix(":all"),
        "version": version,
    }


def apt_candidates(data: bytes, names: list[str]) -> list[dict[str, str]]:
    candidates: dict[str, str] = {}
    current: str | None = None
    for line in data.decode("utf-8", errors="strict").splitlines():
        if line and not line[0].isspace():
            current = line.removesuffix(":")
        elif line.strip().startswith("Candidate:"):
            if current is None or current in candidates:
                raise PreparationError("invalid_package_metadata")
            candidates[current] = line.strip().removeprefix("Candidate:").strip()
    if set(candidates) != set(names) or any(
        value == "(none)" for value in candidates.values()
    ):
        raise PreparationError("package_metadata_missing_refresh_required")
    return [package_pair(name, candidates[name]) for name in sorted(candidates)]


def apt_transaction(data: bytes) -> list[dict[str, str]]:
    packages: dict[str, dict[str, str]] = {}
    for line in data.decode("utf-8", errors="strict").splitlines():
        if line.startswith("Remv "):
            raise PreparationError("package_removal_refused")
        if line.startswith("Inst "):
            match = re.fullmatch(
                r"Inst ([^ ]+) (?:\[[^\]]+\] )?\(([^ ]+) .+\)(?: \[[^\]]*\])?", line
            )
            if match is None:
                raise PreparationError("invalid_package_transaction")
            package = package_pair(match[1], match[2])
            if package["name"] in packages:
                raise PreparationError("invalid_package_transaction")
            packages[package["name"]] = package
    if len(packages) > MAX_PACKAGES:
        raise PreparationError("package_inventory_limit")
    return [packages[name] for name in sorted(packages)]


def apt_base() -> list[str]:
    return [
        "/usr/bin/apt-get",
        "-o",
        "APT::Get::AllowUnauthenticated=false",
        "-o",
        "Acquire::AllowInsecureRepositories=false",
        "-o",
        "APT::Get::allow-Downgrades=false",
        "-o",
        "DPkg::Lock::Timeout=30",
        "--no-remove",
        "--no-install-recommends",
    ]


def package_inventory(commands: Commands, distribution: str) -> bytes:
    if distribution == "ubuntu":
        if commands.query(["/usr/bin/dpkg", "--audit"]):
            raise PreparationError("package_database_recovery_required")
        return commands.query(
            [
                "/usr/bin/dpkg-query",
                "-W",
                "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
            ]
        )
    return commands.query(["/usr/bin/pacman", "-Q"])


def installed_versions(data: bytes, distribution: str) -> dict[str, str]:
    result: dict[str, str] = {}
    lines = data.decode("ascii").splitlines()
    if len(lines) > MAX_PACKAGES:
        raise PreparationError("package_inventory_limit")
    for line in lines:
        fields = line.split("\t") if distribution == "ubuntu" else line.split()
        if len(fields) != (3 if distribution == "ubuntu" else 2):
            raise PreparationError("invalid_package_inventory")
        package = package_pair(fields[0], fields[1], observed=distribution == "ubuntu")
        if distribution == "ubuntu":
            if not re.fullmatch(r"[uihrp][ncHUFWti][ R]", fields[2]):
                raise PreparationError("invalid_package_inventory")
            # Held packages are installed too; the first character describes
            # the requested dpkg action, not current installation status.
            if fields[2][1:] != "i ":
                continue
        if package["name"] in result:
            raise PreparationError("invalid_package_inventory")
        result[package["name"]] = package["version"]
    return result


def repository_state(commands: Commands, distribution: str) -> str:
    if distribution == "ubuntu":
        return hashlib.sha256(
            commands.query(["/usr/bin/apt-cache", "policy"])
        ).hexdigest()
    files = sorted(Path("/var/lib/pacman/sync").glob("*.db"))
    if not files:
        raise PreparationError("arch_synchronized_host_required")
    values = {}
    for path in files:
        if time.time() - path.stat().st_mtime > 24 * 3600:
            raise PreparationError("arch_synchronized_host_required")
        values[path.name] = hashlib.sha256(read_regular(path)).hexdigest()
    return digest(values)


def manual_packages(commands: Commands, distribution: str) -> list[str]:
    data = commands.query(
        ["/usr/bin/apt-mark", "showmanual"]
        if distribution == "ubuntu"
        else ["/usr/bin/pacman", "-Qqe"]
    )
    names = data.decode("ascii").splitlines()
    if (
        len(names) > MAX_PACKAGES
        or len(set(names)) != len(names)
        or any(
            (OBSERVED_PACKAGE if distribution == "ubuntu" else PACKAGE).fullmatch(name)
            is None
            for name in names
        )
    ):
        raise PreparationError("invalid_package_ownership_inventory")
    return sorted({name.removesuffix(":amd64").removesuffix(":all") for name in names})


def system_plan(
    commands: Commands, distribution: str, names: list[str], repair: bool
) -> dict[str, Any]:
    installed = package_inventory(commands, distribution)
    versions = installed_versions(installed, distribution)
    manual = manual_packages(commands, distribution)
    repository = repository_state(commands, distribution)
    if distribution == "ubuntu":
        targets = apt_candidates(
            commands.query(["/usr/bin/apt-cache", "policy", *names]), names
        )
        # Use the already validated, architecture-separated installed snapshot.
        # An unqualified dpkg-query -W <name> can concatenate amd64 and i386
        # versions, creating an invalid candidate on multilib workstations.
        # Foreign-only installations must not count as native target versions.
        # Native dpkg comparison preserves epochs, Debian revisions and ~.
        for target in targets:
            version = versions.get(target["name"])
            if version is None:
                continue
            newer = commands.run(
                [
                    "/usr/bin/dpkg",
                    "--compare-versions",
                    version,
                    "gt",
                    target["version"],
                ]
            )
            if newer.code == 0:
                target["version"] = package_pair(target["name"], version)["version"]
            elif newer.code != 1:
                raise PreparationError("version_comparison_failed")
        args = [
            *apt_base(),
            "--simulate",
            *(["--reinstall"] if repair else []),
            "install",
            *[f"{p['name']}={p['version']}" for p in targets],
        ]
        transaction = apt_transaction(commands.query(args, timeout=120))
        # Reject dependency downgrades as well as direct-target downgrades.
        for package in transaction:
            if package["name"] in versions:
                comparison = commands.run(
                    [
                        "/usr/bin/dpkg",
                        "--compare-versions",
                        versions[package["name"]],
                        "gt",
                        package["version"],
                    ]
                ).code
                if comparison == 0:
                    raise PreparationError("package_downgrade_refused")
                if comparison != 1:
                    raise PreparationError("version_comparison_failed")
    else:
        pending = commands.run(["/usr/bin/pacman", "-Qu"])
        if pending.code not in (0, 1) or pending.output:
            raise PreparationError("arch_full_system_upgrade_required")
        args = [
            "/usr/bin/pacman",
            "-Sp",
            *([] if repair else ["--needed"]),
            "--print-format",
            "%n\t%v\t%h",
            *names,
        ]
        data = commands.query(args, timeout=120)
        transaction = []
        for line in data.decode("ascii").splitlines():
            fields = line.split("\t")
            if len(fields) != 3 or SHA256.fullmatch(fields[2]) is None:
                raise PreparationError("invalid_package_transaction")
            transaction.append(
                {**package_pair(fields[0], fields[1]), "sha256": fields[2]}
            )
        if len(transaction) > MAX_PACKAGES or len(
            {p["name"] for p in transaction}
        ) != len(transaction):
            raise PreparationError("package_inventory_limit")
        transaction.sort(key=lambda package: package["name"])
        targets = []
        for name in names:
            info = commands.query(["/usr/bin/pacman", "-Si", name]).decode("ascii")
            matches = re.findall(r"^Version\s*:\s*(\S+)\s*$", info, re.MULTILINE)
            if len(matches) != 1:
                raise PreparationError("invalid_package_metadata")
            targets.append(package_pair(name, matches[0]))
        for package in [*targets, *transaction]:
            if package["name"] in versions:
                compared = commands.query(
                    ["/usr/bin/vercmp", versions[package["name"]], package["version"]]
                ).strip()
                if not re.fullmatch(rb"-?[0-9]+", compared):
                    raise PreparationError("version_comparison_failed")
                if int(compared) > 0:
                    raise PreparationError("package_downgrade_refused")
    # Queries must observe the same installed/repository state throughout.
    if (
        installed != package_inventory(commands, distribution)
        or manual != manual_packages(commands, distribution)
        or repository != repository_state(commands, distribution)
    ):
        raise PreparationError("package_state_changed_during_planning")
    return {
        "requested": targets,
        "transaction": transaction,
        "installed_digest": hashlib.sha256(installed).hexdigest(),
        "repository_digest": repository,
        "manual_packages": manual,
    }


def plan(
    selected: list[str],
    *,
    repair: bool = False,
    root: Path = ROOT,
    commands: Commands | None = None,
) -> dict[str, Any]:
    commands = commands or Commands(root)
    if (
        not isinstance(selected, list)
        or any(not isinstance(name, str) for name in selected)
        or type(repair) is not bool
    ):
        raise PreparationError("invalid_profile_selection")
    spec = load_spec(root)
    pins = tool_pins(root / "tools/codex/versions.env")
    if not pins["NATIVE_PYTHON_RELEASE"].startswith(pins["PYTHON_MAJOR_MINOR"] + "."):
        raise PreparationError("native_python_pin_mismatch")
    selected = profiles(selected, spec)
    distribution = host(spec)
    for name in selected:
        if distribution["id"] not in spec["profile"][name].get(
            "supported", ["ubuntu", "arch"]
        ):
            raise PreparationError("profile_requires_native_arch_builder")
    source = source_state(commands)
    inputs = input_identity(root)
    names = sorted(
        {
            package
            for name in selected
            for package in spec["profile"][name][distribution["id"]]
        }
    )
    system = system_plan(commands, distribution["id"], names, repair)
    if source_state(commands) != source or input_identity(root) != inputs:
        raise PreparationError("source_changed_during_planning")
    payload = {
        "schema_version": 1,
        "kind": "native-development-preparation",
        "qualification_evidence": False,
        "uid": os.geteuid(),
        "home": str(commands.home),
        "profiles": selected,
        "repair": repair,
        "host": distribution,
        "source_digest": source,
        "input_digest": inputs,
        "system": system,
        "user_tools": {key: pins[key] for key in sorted(pins)},
        "typecheck_lock_digest": hashlib.sha256(
            read_regular(root / "tools/python-typecheck/package-lock.json")
        ).hexdigest(),
        "external_prerequisites": [
            "native package-manager authorization",
            "sufficient disk/memory",
            "existing authenticated package repositories",
            "hardware/session/storage requirements remain independently verified",
        ],
    }
    return {
        "read_only": True,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "plan_digest": digest(payload),
        "payload": payload,
    }


def validate_saved_plan(saved: dict[str, Any], current: dict[str, Any]) -> None:
    if (
        set(saved) != {"read_only", "created_utc", "plan_digest", "payload"}
        or saved["read_only"] is not True
        or digest(saved["payload"]) != saved["plan_digest"]
    ):
        raise PreparationError("invalid_preparation_plan")
    try:
        created = dt.datetime.fromisoformat(saved["created_utc"])
        age = (dt.datetime.now(dt.timezone.utc) - created).total_seconds()
    except (TypeError, ValueError) as exc:
        raise PreparationError("invalid_preparation_plan") from exc
    if not 0 <= age <= 900:
        raise PreparationError("preparation_plan_expired")
    if (
        saved["payload"] != current["payload"]
        or saved["plan_digest"] != current["plan_digest"]
    ):
        raise PreparationError("preparation_plan_stale_replan_required")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "prepare", "maintain"):
        command = sub.add_parser(name)
        command.add_argument("--profile", choices=doctor.PROFILES, action="append")
        command.add_argument(
            "--all", action="store_true", help="all profiles; image requires Arch"
        )
        if name == "plan":
            command.add_argument(
                "--maintenance",
                action="store_true",
                help="review an explicit reinstall plan",
            )
        if name != "plan":
            command.add_argument(
                "--accept-current-packages",
                action="store_true",
                help="after native operator recovery/review, archive an interrupted package receipt and accept the newly observed package state",
            )
            command.add_argument(
                "--plan-file",
                type=Path,
                help="apply only if this private saved plan still matches",
            )
            command.add_argument(
                "--refresh",
                action="store_true",
                help="explicitly refresh Ubuntu metadata before making a new plan; Arch requires separate full system maintenance",
            )
    args = parser.parse_args()
    try:
        commands = Commands()
        selected: list[str] = (
            list(doctor.PROFILES) if args.all else (args.profile or ["core"])
        )
        repair = args.command == "maintain" or (
            args.command == "plan" and args.maintenance
        )
        if args.command != "plan":
            from tools.codex import native_install

            if args.refresh:
                if args.plan_file:
                    raise PreparationError("refresh_requires_new_plan")
                native_install.refresh_metadata(selected, commands)
        saved = None
        if args.command != "plan" and args.plan_file:
            saved = json.loads(read_regular(args.plan_file).decode("utf-8"))
            if not isinstance(saved, dict) or not isinstance(
                saved.get("payload"), dict
            ):
                raise PreparationError("invalid_preparation_plan")
            # Explicit CLI selectors must agree; a file cannot choose commands.
            if args.profile or args.all:
                if profiles(selected, load_spec()) != saved["payload"].get("profiles"):
                    raise PreparationError("plan_profile_mismatch")
            selected = saved["payload"].get("profiles", [])
            if saved["payload"].get("repair") is not repair:
                raise PreparationError("plan_mode_mismatch")
        current = plan(selected, repair=repair, commands=commands)
        if saved is not None:
            validate_saved_plan(saved, current)
        if args.command == "plan":
            result = current
        else:
            from tools.codex import native_install

            result = native_install.prepare(
                current, commands, accept_current_packages=args.accept_current_packages
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        code = (
            str(exc)
            if isinstance(exc, PreparationError)
            else "invalid_or_unavailable_preparation_input"
        )
        print(
            json.dumps(
                {"ok": False, "error": code, "qualification_evidence": False},
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
