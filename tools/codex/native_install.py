"""Explicit operator preparation; no runtime, provider or executor interface."""

from __future__ import annotations

from dataclasses import asdict
import datetime as dt
import fcntl
import hashlib
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
import stat
import tarfile
import uuid
from typing import Any

from tools.codex import doctor, native


def safe_directory(path: Path, *, create: bool = False, private: bool = False) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise native.PreparationError("unsafe_preparation_path")
    missing: list[Path] = []
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            missing.append(part)
            continue
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022
        ):
            # /tmp is accepted only as an existing root-owned sticky ancestor,
            # never as the installation root. This also supports private tests.
            if not (
                part != path
                and stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and info.st_mode & stat.S_ISVTX
            ):
                raise native.PreparationError("unsafe_preparation_directory")
    if missing and not create:
        return path
    for part in reversed(missing):
        part.mkdir(mode=0o700)
    if path.exists():
        info = path.lstat()
        if info.st_uid != os.geteuid() or (
            private and stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise native.PreparationError("preparation_directory_not_private")
    return path


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    safe_directory(path.parent, private=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise native.PreparationError("unsafe_preparation_record")
    temporary = path.parent / (".record-" + uuid.uuid4().hex)
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def root_program(path: str) -> None:
    resolved = Path(path).resolve(strict=True)
    for part in (resolved, *resolved.parents):
        info = part.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise native.PreparationError("native_authority_host_required")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise native.PreparationError("native_authority_host_required")


def privileged(commands: native.Commands, args: list[str]) -> None:
    # Only the native package-manager entrypoints below call this helper. No
    # command/arguments are accepted from a saved plan, model or runtime client.
    if args[0] not in {"/usr/bin/apt-get", "/usr/bin/apt-mark", "/usr/bin/pacman"}:
        raise native.PreparationError("unsupported_preparation_effect")
    root_program("/usr/bin/sudo")
    root_program(args[0])
    commands.effect(["/usr/bin/sudo", "-n", "--", *args])


def require_developer() -> None:
    """Native preparation and metadata changes require a non-root caller."""
    if os.geteuid() == 0:
        raise native.PreparationError("run_preparation_as_developer")


def refresh_metadata(selected: list[str], commands: native.Commands) -> None:
    require_developer()
    spec = native.load_spec(commands.root)
    native.tool_pins(commands.root / "tools/codex/versions.env")
    native.input_identity(commands.root)
    selected = native.profiles(selected, spec)
    distribution = native.host(spec)
    if distribution["id"] != "ubuntu":
        raise native.PreparationError("arch_refresh_requires_full_system_maintenance")
    if any(
        distribution["id"]
        not in spec["profile"][name].get("supported", ["ubuntu", "arch"])
        for name in selected
    ):
        raise native.PreparationError("profile_requires_native_arch_builder")
    before = native.source_state(commands)
    try:
        privileged(
            commands,
            [*native.apt_base(), "-o", "APT::Update::Error-Mode=any", "update"],
        )
    finally:
        if native.source_state(commands) != before:
            raise native.PreparationError("preparation_changed_source")


def install_packages(payload: dict[str, Any], commands: native.Commands) -> None:
    if not payload["system"]["transaction"]:
        return
    # Both direct requests and the simulated dependency closure are exact
    # version constraints. Removals, downgrades and recovery shortcuts are not
    # admitted by planning. The package manager retains signature/hooks/locks.
    versions = {
        p["name"]: p["version"]
        for p in [*payload["system"]["requested"], *payload["system"]["transaction"]]
    }
    targets = [f"{name}={versions[name]}" for name in sorted(versions)]
    if payload["host"]["id"] == "ubuntu":
        privileged(
            commands,
            [
                *native.apt_base(),
                "--yes",
                *(["--reinstall"] if payload["repair"] else []),
                "install",
                *targets,
            ],
        )
    else:
        # Never -Sy, partial host upgrades, key imports, hook suppression,
        # --overwrite, dependency bypass or the Linura ALPM break-glass flag.
        privileged(
            commands,
            [
                "/usr/bin/pacman",
                "-S",
                "--noconfirm",
                *([] if payload["repair"] else ["--needed"]),
                *targets,
            ],
        )


def verify_packages(
    payload: dict[str, Any], commands: native.Commands, before: dict[str, str]
) -> None:
    distribution = payload["host"]["id"]
    inventory = native.package_inventory(commands, distribution)
    versions = native.installed_versions(inventory, distribution)
    expected = dict(before)
    for package in [*payload["system"]["requested"], *payload["system"]["transaction"]]:
        if versions.get(package["name"]) != package["version"]:
            raise native.PreparationError("package_postcondition_failed")
        expected[package["name"]] = package["version"]
    if versions != expected:
        raise native.PreparationError("unexpected_package_changes_reobserve_required")


def restore_dependency_reasons(
    payload: dict[str, Any], commands: native.Commands
) -> None:
    # Exact dependency constraints are dispatched as explicit arguments. Restore
    # native automatic-dependency reasons instead of turning the whole closure
    # into manually owned packages. Never remove shared/native packages.
    manual = set(payload["system"]["manual_packages"])
    direct = {p["name"] for p in payload["system"]["requested"]}
    dependencies = sorted(
        {p["name"] for p in payload["system"]["transaction"]} - manual - direct
    )
    if dependencies:
        if payload["host"]["id"] == "ubuntu":
            privileged(commands, ["/usr/bin/apt-mark", "auto", *dependencies])
        else:
            privileged(commands, ["/usr/bin/pacman", "-D", "--asdeps", *dependencies])
    after = set(native.manual_packages(commands, payload["host"]["id"]))
    if not manual <= after or after & set(dependencies):
        raise native.PreparationError("package_ownership_verification_failed")


def extract_archive(archive: Path, destination: Path, top: str) -> Path:
    """Extract digest-pinned sources without trusting tar link/filter semantics."""
    safe_directory(destination, private=True)
    if (destination / top).exists() or (destination / top).is_symlink():
        raise native.PreparationError("archive_destination_already_exists")
    with tarfile.open(archive, "r:xz") as source:
        members = []
        total = 0
        for member in source:
            total += member.size
            if len(members) >= 100000 or member.size < 0 or total > 1024**3:
                raise native.PreparationError("archive_resource_limit")
            members.append(member)
        seen: set[str] = set()
        for member in members:
            name = PurePosixPath(member.name)
            if (
                name.is_absolute()
                or ".." in name.parts
                or not name.parts
                or name.parts[0] != top
                or member.name in seen
                or not (member.isdir() or member.isfile() or member.issym())
            ):
                raise native.PreparationError("unsafe_preparation_archive")
            seen.add(member.name)
            if member.issym():
                target = posixpath.normpath(
                    posixpath.join(str(name.parent), member.linkname)
                )
                if member.linkname.startswith("/") or not target.startswith(top + "/"):
                    raise native.PreparationError("unsafe_preparation_archive_link")
        # Symlinks are created only after all regular files; no filesystem write
        # can traverse an archive-created symlink, including linked parents.
        for member in members:
            if member.issym():
                continue
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
            else:
                stream = source.extractfile(member)
                if stream is None:
                    raise native.PreparationError("invalid_preparation_archive")
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o755 if member.mode & 0o111 else 0o644,
                )
                with stream, os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
        for member in members:
            if member.issym():
                target = destination / member.name
                root = (destination / top).resolve()
                if not target.parent.resolve().is_relative_to(root) or not (
                    target.parent / member.linkname
                ).resolve().is_relative_to(root):
                    raise native.PreparationError("unsafe_preparation_archive_link")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(member.linkname)
    return destination / top


def download(commands: native.Commands, url: str, expected: str, target: Path) -> None:
    if (
        not re.fullmatch(
            r"https://(?:www\.python\.org|nodejs\.org)/[A-Za-z0-9_./-]+", url
        )
        or native.SHA256.fullmatch(expected) is None
    ):
        raise native.PreparationError("invalid_download_contract")
    commands.effect(
        [
            "/usr/bin/curl",
            "--disable",
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "20",
            "--max-time",
            "180",
            "--max-filesize",
            str(128 * 1024 * 1024),
            "--output",
            str(target),
            url,
        ],
        timeout=200,
    )
    if (
        hashlib.sha256(native.read_regular(target, 128 * 1024 * 1024)).hexdigest()
        != expected
    ):
        raise native.PreparationError("download_digest_mismatch")


def python_works(commands: native.Commands, binary: Path, release: str) -> bool:
    if not binary.is_file():
        return False
    code = (
        "import sys,ssl,hashlib,zlib,bz2,lzma,sqlite3,ctypes,readline,venv,ensurepip; assert '.'.join(map(str,sys.version_info[:3])) == "
        + repr(release)
    )
    return commands.run([str(binary), "-I", "-S", "-c", code]).code == 0


def tree_manifest(generation: Path) -> dict[str, Any]:
    safe_directory(generation, private=True)
    result: dict[str, Any] = {}
    total_bytes = 0
    for subtree in (
        "python",
        "typing",
        "bin",
        *[path.name for path in generation.glob("node-v*-linux-x64")],
    ):
        root = generation / subtree
        if not root.is_dir() or root.is_symlink():
            raise native.PreparationError("invalid_managed_tool_tree")
        paths = list(itertools.islice(root.rglob("*"), 100001))
        if len(paths) + len(result) > 100000:
            raise native.PreparationError("managed_tool_inventory_limit")
        for path in (root, *sorted(paths)):
            relative = str(path.relative_to(generation))
            info = path.lstat()
            if info.st_uid != os.geteuid() or (
                not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022
            ):
                raise native.PreparationError("unsafe_managed_tool_tree")
            if stat.S_ISLNK(info.st_mode):
                if not path.resolve().is_relative_to(generation):
                    raise native.PreparationError("unsafe_managed_tool_link")
                result[relative] = {"link": os.readlink(path)}
            elif stat.S_ISDIR(info.st_mode):
                result[relative] = {"mode": stat.S_IMODE(info.st_mode)}
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                total_bytes += info.st_size
                if info.st_size > 512 * 1024 * 1024 or total_bytes > 4 * 1024**3:
                    raise native.PreparationError("managed_tool_file_limit")
                hasher = hashlib.sha256()
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    while block := stream.read(1024 * 1024):
                        hasher.update(block)
                result[relative] = {
                    "sha256": hasher.hexdigest(),
                    "mode": stat.S_IMODE(info.st_mode),
                }
            else:
                raise native.PreparationError("unsupported_managed_tool_file")
    return result


def build_python(
    commands: native.Commands, generation: Path, pins: dict[str, str]
) -> Path:
    release = pins["NATIVE_PYTHON_RELEASE"]
    archive = generation / "python.tar.xz"
    download(
        commands,
        f"https://www.python.org/ftp/python/{release}/Python-{release}.tar.xz",
        pins["NATIVE_PYTHON_SHA256"],
        archive,
    )
    source = extract_archive(archive, generation, "Python-" + release)
    prefix = generation / "python"
    commands.effect(
        [
            str(source / "configure"),
            "--prefix=" + str(prefix),
            "--with-ensurepip=install",
            "--disable-test-modules",
        ],
        timeout=300,
        cwd=source,
    )
    commands.effect(["/usr/bin/make", "-j2"], timeout=3600, cwd=source)
    if not python_works(commands, source / "python", release):
        raise native.PreparationError("private_python_build_modules_missing")
    commands.effect(["/usr/bin/make", "altinstall"], timeout=1800, cwd=source)
    binary = prefix / "bin/python3.12"
    if not python_works(commands, binary, release):
        raise native.PreparationError("private_python_verification_failed")
    return binary


def install_typing(
    commands: native.Commands, generation: Path, pins: dict[str, str]
) -> tuple[Path, Path]:
    release = pins["NATIVE_NODE_VERSION"]
    top = f"node-v{release}-linux-x64"
    archive = generation / "node.tar.xz"
    download(
        commands,
        f"https://nodejs.org/dist/v{release}/{top}.tar.xz",
        pins["NATIVE_NODE_SHA256"],
        archive,
    )
    node = extract_archive(archive, generation, top)
    binary = node / "bin/node"
    if commands.query([str(binary), "--version"]).strip() != ("v" + release).encode():
        raise native.PreparationError("private_node_verification_failed")
    typing = generation / "typing"
    typing.mkdir(mode=0o700)
    for name in ("package.json", "package-lock.json"):
        (typing / name).write_bytes(
            native.read_regular(commands.root / "tools/python-typecheck" / name)
        )
    commands.env["PATH"] = f"{node / 'bin'}:{commands.env['PATH']}"
    # npm refuses to load one path as both user and global configuration.
    # Distinct private empty files exclude ambient registry credentials/config.
    user_config = generation / "npm-user.conf"
    global_config = generation / "npm-global.conf"
    user_config.write_text("", encoding="utf-8")
    global_config.write_text("", encoding="utf-8")
    commands.effect(
        [
            str(binary),
            str(node / "lib/node_modules/npm/bin/npm-cli.js"),
            "ci",
            "--prefix",
            str(typing),
            "--ignore-scripts",
            "--omit=optional",
            "--no-audit",
            "--no-fund",
            "--userconfig",
            str(user_config),
            "--globalconfig",
            str(global_config),
            "--cache",
            str(generation / "npm-cache"),
        ],
        timeout=600,
    )
    expected = json.loads(native.read_regular(typing / "package.json"))[
        "devDependencies"
    ]["pyright"]
    program = typing / "node_modules/pyright/index.js"
    if (
        commands.query([str(binary), str(program), "--version"]).strip()
        != ("pyright " + expected).encode()
    ):
        raise native.PreparationError("private_typechecker_verification_failed")
    metadata = json.loads(
        native.read_regular(typing / "node_modules/pyright/package.json")
    )
    if metadata["version"] != expected or sorted(
        path.name
        for path in (typing / "node_modules").iterdir()
        if not path.name.startswith(".")
    ) != ["pyright"]:
        raise native.PreparationError("private_typechecker_inventory_failed")
    if native.read_regular(typing / "package-lock.json") != native.read_regular(
        commands.root / "tools/python-typecheck/package-lock.json"
    ):
        raise native.PreparationError("private_typechecker_lock_changed")
    return binary, program


def check_link(
    link: Path, target: Path, managed: Path, *, python: bool = False
) -> None:
    safe_directory(link.parent, create=True, private=python)
    if link.exists() or link.is_symlink():
        if not link.is_symlink() or link.lstat().st_uid != os.geteuid():
            raise native.PreparationError("unmanaged_tool_path_conflict")
        if not link.resolve().is_relative_to(managed):
            raise native.PreparationError("unmanaged_tool_path_conflict")


def publish_link(
    link: Path, target: Path, managed: Path, *, python: bool = False
) -> None:
    check_link(link, target, managed, python=python)
    temporary = link.parent / (".link-" + uuid.uuid4().hex)
    try:
        temporary.symlink_to(target)
        os.replace(temporary, link)
    finally:
        temporary.unlink(missing_ok=True)


def user_tools(
    commands: native.Commands, base: Path, payload: dict[str, Any]
) -> dict[str, str]:
    pins = payload["user_tools"]
    current = base / "user-tools.json"
    if current.exists() and not payload["repair"]:
        try:
            record = json.loads(native.read_regular(current))
        except (ValueError, OSError):
            record = {}
        if not isinstance(record, dict):
            record = {}
        if record.get("input_digest") == payload["input_digest"]:
            python = Path(record.get("python", ""))
            node = Path(record.get("node", ""))
            pyright = Path(record.get("pyright", ""))
            generation = Path(record.get("generation", ""))
            if (
                generation.is_absolute()
                and generation.is_relative_to(base / "generations")
                and generation.parent == base / "generations"
                and re.fullmatch(r"[0-9a-f]{32}", generation.name)
                and all(
                    path.is_absolute() and path.is_relative_to(generation)
                    for path in (python, node, pyright)
                )
                and python == generation / "python/bin/python3.12"
                and node
                == generation
                / f"node-v{pins['NATIVE_NODE_VERSION']}-linux-x64/bin/node"
                and pyright == generation / "typing/node_modules/pyright/index.js"
            ):
                try:
                    manifest = json.loads(
                        native.read_regular(generation / "files.json")
                    )
                    if (
                        native.digest(manifest) != record.get("files_digest")
                        or tree_manifest(generation) != manifest
                    ):
                        raise native.PreparationError("managed_tool_cache_drift")
                    expected = json.loads(
                        native.read_regular(
                            commands.root / "tools/python-typecheck/package.json"
                        )
                    )["devDependencies"]["pyright"]
                    if (
                        python_works(commands, python, pins["NATIVE_PYTHON_RELEASE"])
                        and commands.query([str(node), "--version"]).strip()
                        == ("v" + pins["NATIVE_NODE_VERSION"]).encode()
                        and commands.query(
                            [str(node), str(pyright), "--version"]
                        ).strip()
                        == ("pyright " + expected).encode()
                    ):
                        for name in ("pyright", "pyright-langserver"):
                            publish_link(
                                commands.home / ".local/bin" / name,
                                generation / "bin" / name,
                                base,
                            )
                        publish_link(
                            commands.home / ".local/linura-tools/python312/bin/python3",
                            python,
                            base,
                            python=True,
                        )
                        return {
                            "python": str(python),
                            "node": str(node),
                            "pyright": str(pyright),
                            "generation": record["generation"],
                        }
                except (native.PreparationError, OSError, ValueError):
                    pass
    generations = safe_directory(base / "generations", create=True, private=True)
    generation = generations / uuid.uuid4().hex
    generation.mkdir(mode=0o700)
    # Retain incomplete generations for explicit diagnosis, never adopt one
    # merely because an executable or a stale success marker is present.
    atomic_json(
        generation / "generation.json",
        {
            "schema_version": 1,
            "kind": "native-development-tools",
            "uid": os.geteuid(),
            "input_digest": payload["input_digest"],
            "state": "building",
        },
    )
    python = build_python(commands, generation, pins)
    node, pyright = install_typing(commands, generation, pins)
    launchers = generation / "bin"
    launchers.mkdir(mode=0o700)
    for name, program in (
        ("pyright", pyright),
        ("pyright-langserver", pyright.with_name("langserver.index.js")),
    ):
        path = launchers / name
        path.write_text(
            "#!/bin/sh\nexec "
            + shlex.quote(str(node))
            + " "
            + shlex.quote(str(program))
            + ' "$@"\n',
            encoding="utf-8",
        )
        path.chmod(0o700)
        publish_link(commands.home / ".local/bin" / name, path, base)
    publish_link(
        commands.home / ".local/linura-tools/python312/bin/python3",
        python,
        base,
        python=True,
    )
    tools = {
        "python": str(python),
        "node": str(node),
        "pyright": str(pyright),
        "generation": str(generation),
    }
    manifest = tree_manifest(generation)
    atomic_json(generation / "files.json", manifest)
    atomic_json(
        generation / "generation.json",
        {
            "schema_version": 1,
            "kind": "native-development-tools",
            "uid": os.geteuid(),
            "input_digest": payload["input_digest"],
            "state": "verified",
            **tools,
        },
    )
    atomic_json(
        current,
        {
            "schema_version": 1,
            "input_digest": payload["input_digest"],
            "files_digest": native.digest(manifest),
            **tools,
        },
    )
    return tools


def prepare(
    current: dict[str, Any],
    commands: native.Commands,
    *,
    accept_current_packages: bool = False,
) -> dict[str, Any]:
    previous = os.umask(0o077)
    try:
        return _prepare(
            current, commands, accept_current_packages=accept_current_packages
        )
    finally:
        os.umask(previous)


def _prepare(
    current: dict[str, Any], commands: native.Commands, *, accept_current_packages: bool
) -> dict[str, Any]:
    require_developer()
    payload = current["payload"]
    # Re-derive the complete native plan. A serialized developer plan is data,
    # not an executable command list, reusable credential or product authority.
    fresh = native.plan(
        payload["profiles"],
        repair=payload["repair"],
        root=commands.root,
        commands=commands,
    )
    native.validate_saved_plan(current, fresh)
    before = native.source_state(commands)
    base = safe_directory(
        commands.home / ".local/linura-tools/native", create=True, private=True
    )
    safe_directory(commands.home / ".local/bin", create=True)
    safe_directory(
        commands.home / ".local/linura-tools/python312/bin", create=True, private=True
    )
    for name in ("pyright", "pyright-langserver"):
        check_link(commands.home / ".local/bin" / name, base, base)
    check_link(
        commands.home / ".local/linura-tools/python312/bin/python3",
        base,
        base,
        python=True,
    )
    # No broad repair, chmod/chown, root-owned home or implicit cleanup.
    if (
        shutil.disk_usage(base).free < 2 * 1024**3
        or shutil.disk_usage(Path("/")).free < 1024**3
    ):
        raise native.PreparationError("insufficient_preparation_disk_space")
    descriptor = os.open(
        base / "preparation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": "native-development-preparation",
        "qualification_evidence": False,
        "plan_digest": current["plan_digest"],
        "profiles": payload["profiles"],
        "source_digest": before,
        "status": "in_progress",
        "phase": "system_packages",
        "system": payload["system"],
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    acquired = False
    receipt_started = False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise native.PreparationError("unsafe_preparation_lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError as exc:
            raise native.PreparationError("preparation_already_running") from exc
        # Revalidate after obtaining the preparation lock as another process
        # may have completed between the first plan and lock acquisition.
        native.validate_saved_plan(
            current,
            native.plan(
                payload["profiles"],
                repair=payload["repair"],
                root=commands.root,
                commands=commands,
            ),
        )
        previous = base / "last-run.json"
        if previous.exists() or previous.is_symlink():
            record = json.loads(native.read_regular(previous))
            if not isinstance(record, dict) or record.get("kind") != receipt["kind"]:
                raise native.PreparationError("invalid_prior_preparation_record")
            prior_system = record.get("system", {})
            if not isinstance(prior_system, dict):
                raise native.PreparationError("invalid_prior_preparation_record")
            changed = any(
                prior_system.get(key) != payload["system"][key]
                for key in ("installed_digest", "manual_packages")
            )
            if (
                record.get("phase") == "system_packages"
                and record.get("status") != "ready"
                and changed
                and not accept_current_packages
            ):
                # Do not guess whether an interrupted native transaction or
                # another administrator now owns a dependency's manual reason.
                raise native.PreparationError(
                    "prior_package_transaction_requires_operator_review"
                )
            history = safe_directory(base / "history", create=True, private=True)
            atomic_json(history / (uuid.uuid4().hex + ".json"), record)
        receipt["accepted_current_packages"] = accept_current_packages
        atomic_json(base / "last-run.json", receipt)
        receipt_started = True
        inventory = native.package_inventory(commands, payload["host"]["id"])
        if (
            hashlib.sha256(inventory).hexdigest()
            != payload["system"]["installed_digest"]
        ):
            raise native.PreparationError("package_state_changed_before_dispatch")
        install_packages(payload, commands)
        verify_packages(
            payload,
            commands,
            native.installed_versions(inventory, payload["host"]["id"]),
        )
        restore_dependency_reasons(payload, commands)
        if native.source_state(commands) != before:
            raise native.PreparationError("preparation_changed_source")
        receipt["phase"] = "user_tools"
        atomic_json(base / "last-run.json", receipt)
        tools = user_tools(commands, base, payload)
        commands.env["PATH"] = (
            str(Path(tools["python"]).parent)
            + ":"
            + str(commands.home / ".local/linura-tools/python312/bin")
            + ":"
            + commands.env["PATH"]
        )
        receipt["phase"] = "canonical_bootstrap"
        atomic_json(base / "last-run.json", receipt)
        commands.effect(
            [
                "/usr/bin/bash",
                "scripts/setup_codex_environment.sh",
                *(["--bindings"] if "bindings" in payload["profiles"] else []),
            ],
            timeout=3600,
        )
        receipt["phase"] = "readiness_verification"
        atomic_json(base / "last-run.json", receipt)
        checks = doctor.inventory(set(payload["profiles"]))
        receipt["checks"] = [asdict(check) for check in checks]
        receipt["tools"] = tools
        if not checks or not all(check.ready for check in checks):
            raise native.PreparationError("selected_profile_verification_failed")
        if (
            native.source_state(commands) != before
            or native.input_identity(commands.root) != payload["input_digest"]
        ):
            raise native.PreparationError("preparation_changed_source")
        receipt.update(
            status="ready",
            phase="complete",
            completed_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        )
        atomic_json(base / "last-run.json", receipt)
        return receipt
    except BaseException as exc:
        receipt.update(
            status="failed_reobserve_required",
            error=str(exc)
            if isinstance(exc, native.PreparationError)
            else "preparation_interrupted_or_failed",
        )
        if acquired and receipt_started:
            atomic_json(base / "last-run.json", receipt)
        raise
    finally:
        os.close(descriptor)
        if native.source_state(commands) != before:
            raise native.PreparationError("preparation_changed_source")
