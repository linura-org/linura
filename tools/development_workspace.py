#!/usr/bin/env python3
"""Inspect checkout/storage/SDK isolation without installation, workloads or cleanup.

This produces a development layout snapshot, never qualification evidence or an
authorization to execute, delete, provision or publish anything.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tomllib
from typing import Mapping, NotRequired, TypedDict

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    # Standalone inspection must not create repository bytecode directories.
    sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from tools.codex.doctor import probe  # noqa: E402

MAX_INPUT_BYTES = 1024 * 1024
GIB = 1024**3
INHERITED_OUTPUT_KEYS = (
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
)
GIT_REDIRECTION_KEYS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_NAMESPACE",
)
PERSISTENT_FILESYSTEMS = frozenset({"ext4", "xfs", "btrfs"})
CONVENTIONAL_STORAGE_MOUNT = Path("/mnt/linura-data")
STORAGE_CLASSES = ("dedicated", "github-hosted-ephemeral")
UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


class WorkspaceError(ValueError):
    pass


@dataclass(frozen=True)
class Check:
    name: str
    ready: bool
    remedy: str


@dataclass(frozen=True)
class Mount:
    device: str
    target: Path
    filesystem: str
    source: str
    root: Path = Path("/")
    options: frozenset[str] = frozenset({"rw"})


class CheckReport(TypedDict):
    name: str
    ready: bool
    remedy: str


class WorkspaceReport(TypedDict):
    schema_version: int
    qualification_evidence: bool
    execution_performed: bool
    scope: str
    layout_ready: bool
    checks: list[CheckReport]
    development_mode: NotRequired[str]
    heavy_storage_required: NotRequired[bool]
    worktree: NotRequired[str]
    common_git_dir: NotRequired[str]
    source_sha: NotRequired[str]
    worktree_id: NotRequired[str]
    storage_root: NotRequired[str]
    filesystem: NotRequired[str]
    available_bytes: NotRequired[int]
    available_inodes: NotRequired[int]
    layout: NotRequired[dict[str, dict[str, str]]]
    storage_uuid: NotRequired[str]
    storage_selection: NotRequired[str]
    storage_class: NotRequired[str]
    editor_settings: NotRequired[dict[str, str | bool | list[str]]]


class StorageReport(WorkspaceReport):
    max_parallel_builds: int
    required_free_bytes: int


def read_bounded(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise WorkspaceError("diagnostic input is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_INPUT_BYTES:
        raise WorkspaceError("input exceeds the diagnostic bound")
    return data.decode("utf-8")


def directory(path: Path) -> Path:
    """Reject symlinks instead of normalizing an unsafe selected storage path."""
    try:
        expanded = path.expanduser()
    except RuntimeError as exc:
        raise WorkspaceError("cannot resolve the selected home directory") from exc
    if ".." in expanded.parts:
        raise WorkspaceError("parent traversal in a selected path")
    absolute = Path(os.path.abspath(expanded))
    if any(ord(char) < 32 or ord(char) == 127 for char in str(absolute)):
        raise WorkspaceError("control characters in a selected path")
    for part in (absolute, *absolute.parents):
        if not stat.S_ISDIR(part.lstat().st_mode):
            raise WorkspaceError("selected directory or ancestor is not a directory")
    return absolute


def token(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise argparse.ArgumentTypeError("use 1-64 lowercase letters/digits, - or _")
    return value


def positive(value: str) -> int:
    result = int(value)
    if not 1 <= result <= 1024:
        raise argparse.ArgumentTypeError("use an integer between 1 and 1024")
    return result


def select_storage_root(
    explicit: Path | None,
    environment: Mapping[str, str] | None = None,
    mountinfo: str | None = None,
) -> tuple[Path | None, str]:
    """Select existing heavy storage without provisioning or guessing a disk."""
    if explicit is not None:
        return explicit, "argument"
    values = os.environ if environment is None else environment
    declared = values.get("LINURA_STORAGE_ROOT")
    if declared is not None:
        candidate = Path(declared)
        if not declared or not candidate.is_absolute() or ".." in candidate.parts:
            return None, "invalid-environment"
        return candidate, "environment"
    try:
        inventory = mounts(
            read_bounded(Path("/proc/self/mountinfo"))
            if mountinfo is None
            else mountinfo
        )
    except (OSError, ValueError):
        return None, "unavailable"
    if any(item.target == CONVENTIONAL_STORAGE_MOUNT for item in inventory):
        return CONVENTIONAL_STORAGE_MOUNT, "conventional-mount"
    return None, "unavailable"


def add_storage_options(parser: argparse.ArgumentParser) -> None:
    """Shared execution prerequisites; these options never provision storage."""
    parser.add_argument(
        "--storage-root",
        type=Path,
        help="existing heavy-storage mount; otherwise use LINURA_STORAGE_ROOT or an already-mounted /mnt/linura-data",
    )
    parser.add_argument("--storage-id", default=os.environ.get("LINURA_STORAGE_ID"))
    parser.add_argument(
        "--storage-class",
        choices=STORAGE_CLASSES,
        default=os.environ.get("LINURA_STORAGE_CLASS", "dedicated"),
    )
    parser.add_argument("--run", type=token, default=os.environ.get("LINURA_RUN_ID"))


def github_hosted_ephemeral_root(
    worktree: Path, environment: Mapping[str, str] | None = None
) -> Path:
    """Check an existing trusted hosted-job context, without provider attestation.

    A local caller controlling its environment can reproduce these declarations.
    Reviewed workflow runner selection establishes the execution context; this
    unprivileged helper only checks its consistency and storage layout.
    """
    values = os.environ if environment is None else environment
    if (
        values.get("GITHUB_ACTIONS") != "true"
        or values.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or values.get("RUNNER_OS") != "Linux"
    ):
        raise WorkspaceError(
            "provider-ephemeral storage requires a GitHub-hosted Linux runner"
        )
    workspace = values.get("GITHUB_WORKSPACE")
    runner_temp = values.get("RUNNER_TEMP")
    if not workspace or not runner_temp:
        raise WorkspaceError("GitHub runner workspace and temporary root are required")
    if directory(Path(workspace)) != directory(worktree):
        raise WorkspaceError("provider workspace does not match the exact checkout")
    temporary = directory(Path(runner_temp))
    info = temporary.stat()
    if info.st_uid != os.geteuid() or not os.access(
        temporary, os.W_OK | os.X_OK, effective_ids=True
    ):
        raise WorkspaceError(
            "GitHub runner temporary root is not caller-owned and writable"
        )
    return temporary / "linura-data"


def execution_layout(
    worktree: Path,
    args: argparse.Namespace,
    environment: str,
    vm_image: Path | None = None,
) -> dict[str, dict[str, str]]:
    """Require the same storage boundary for local and CI heavy entry points."""
    if not isinstance(args.run, str):
        raise WorkspaceError("heavy execution requires --run or LINURA_RUN_ID")
    try:
        token(args.run)
    except argparse.ArgumentTypeError as error:
        raise WorkspaceError("invalid storage run identity") from error
    storage_root, storage_selection = select_storage_root(args.storage_root)
    storage_class = getattr(args, "storage_class", "dedicated")
    report = inspect(
        worktree,
        storage_root,
        environment,
        args.run,
        12,
        1,
        args.storage_id,
        vm_image=vm_image,
        storage_selection=storage_selection,
        storage_class=storage_class,
    )
    if not report["layout_ready"] or "layout" not in report:
        failed = ", ".join(
            check["name"] for check in report["checks"] if not check["ready"]
        )
        raise WorkspaceError(f"{storage_class} storage preflight failed: " + failed)
    # Downstream bounded helpers need the exact root chosen from an argument,
    # provider declaration or the already-mounted conventional path. Preserve
    # that resolved value on the invocation namespace; never leave them to
    # reinterpret a missing argument as a local directory.
    assert storage_root is not None
    args.storage_root = storage_root
    return report["layout"]


def regular_storage_input(path: Path, root: Path) -> Path:
    """Check a regular, non-aliased input without reading a potentially huge image."""
    selected = directory(path.parent) / path.name
    if not selected.is_relative_to(root) or any(
        char == "," or ord(char) < 32 or ord(char) == 127 for char in str(selected)
    ):
        raise WorkspaceError(
            "input is outside its storage namespace or has unsafe syntax"
        )
    descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & stat.S_IWOTH
            or info.st_dev != root.stat().st_dev
        ):
            raise WorkspaceError(
                "input must be a regular, single-link dedicated-storage file"
            )
    finally:
        os.close(descriptor)
    return selected


def mounts(text: str) -> list[Mount]:
    result: list[Mount] = []
    for line in text.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            if separator < 6 or len(fields) != separator + 4:
                raise WorkspaceError("invalid mount inventory")
            device, target = fields[2], fields[4]
            if not re.fullmatch(r"[0-9]+:[0-9]+", device):
                raise WorkspaceError("invalid mount device")
            target = re.sub(
                r"\\(040|011|012|134)",
                lambda match: chr(int(match[1], 8)),
                target,
            )
            if not Path(target).is_absolute():
                raise WorkspaceError("invalid mount target")
            result.append(
                Mount(
                    device,
                    Path(target),
                    fields[separator + 1],
                    fields[separator + 2],
                    Path(fields[3]),
                    frozenset(fields[5].split(",")),
                )
            )
        except ValueError as exc:
            raise WorkspaceError("invalid mount inventory") from exc
    if not result:
        raise WorkspaceError("empty mount inventory")
    return result


def containing_mount(path: Path, inventory: list[Mount]) -> Mount:
    candidates = [item for item in inventory if path.is_relative_to(item.target)]
    if not candidates:
        raise WorkspaceError("selected path has no known mount")
    # The last equally specific entry represents a later overmount.
    return max(
        enumerate(candidates), key=lambda item: (len(item[1].target.parts), item[0])
    )[1]


def independent_mount(source: Mount, storage: Mount) -> bool:
    return (
        source.filesystem in PERSISTENT_FILESYSTEMS
        and storage.filesystem in PERSISTENT_FILESYSTEMS
        and source.source.startswith("/dev/")
        and storage.source.startswith("/dev/")
        and source.device != storage.device
        and Path(source.source).resolve() != Path(storage.source).resolve()
    )


def mount_device_matches(path: Path, mount: Mount) -> bool:
    device = path.stat().st_dev
    return mount.device == f"{os.major(device)}:{os.minor(device)}"


def backing_disks(inventory: str) -> dict[str, str]:
    """Bounded block topology; unsupported/virtual backing never proves separation.

    Support physical/virtual block disks and their ordinary partitions. Loop,
    device-mapper, RAID and network storage need a separately reviewed topology
    contract rather than an assumption that a different filesystem adds capacity.
    """
    value = json.loads(inventory)
    if not isinstance(value, dict) or not isinstance(value.get("blockdevices"), list):
        raise WorkspaceError("unknown block inventory")
    result: dict[str, str] = {}
    visited = 0

    def visit(node: object, disk: str | None, depth: int) -> None:
        nonlocal visited
        visited += 1
        if visited > 256 or depth > 16 or not isinstance(node, dict):
            raise WorkspaceError("invalid or oversized block topology")
        device = node.get("maj:min")
        if not isinstance(device, str) or not re.fullmatch(r"[0-9]+:[0-9]+", device):
            raise WorkspaceError("unknown block device identity")
        kind = node.get("type")
        if kind == "disk" and disk is None and depth == 0:
            disk = device
        elif kind != "part":
            disk = None
        if disk is not None:
            if device in result:
                raise WorkspaceError("ambiguous block device topology")
            result[device] = disk
        children = node.get("children", [])
        if not isinstance(children, list):
            raise WorkspaceError("unknown block device children")
        for child in children:
            visit(child, disk, depth + 1)

    for node in value["blockdevices"]:
        visit(node, None, 0)
    return result


def protected_paths_private(storage: Path, paths: dict[str, str]) -> bool:
    for value in paths.values():
        path = Path(value)
        for part in (path, *path.parents):
            if part == storage:
                break
            try:
                info = part.lstat()
            except FileNotFoundError:
                continue
            # The shared qualification parent may contain public prerequisites;
            # the recording subtree itself must remain private.
            if part == storage / "qualification":
                continue
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                return False
    return True


def run_paths_private(storage: Path, identity: str, paths: list[Path]) -> bool:
    if not planned_directories_safe(paths):
        return False
    for path in paths:
        for part in (path, *path.parents):
            if part == storage:
                break
            try:
                info = part.lstat()
            except FileNotFoundError:
                continue
            if info.st_mode & stat.S_IWOTH:
                return False
            if identity in part.parts and (
                info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077
            ):
                return False
    return True


def git(worktree: Path, *args: str) -> str:
    if any(key in os.environ for key in GIT_REDIRECTION_KEYS):
        raise WorkspaceError("inherited Git redirection prevents reliable inspection")
    env = os.environ.copy()
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_NO_REPLACE_OBJECTS="1",
    )
    output = probe(
        [
            "git",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(worktree),
            *args,
        ],
        env,
    )
    if output is None:
        raise WorkspaceError("Git inspection failed")
    return output


def checkout(worktree: Path) -> tuple[Path, str, str, list[Path]]:
    if git(worktree, "rev-parse", "--show-toplevel") != str(worktree):
        raise WorkspaceError("select the active worktree root, not a nested directory")
    head = git(worktree, "rev-parse", "--verify", "HEAD^{commit}")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise WorkspaceError("unsupported or invalid source identity")
    common = directory(
        Path(git(worktree, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    )
    registered = []
    for item in git(worktree, "worktree", "list", "--porcelain", "-z").split("\0"):
        if item.startswith("worktree "):
            path = Path(item.removeprefix("worktree "))
            if not path.is_absolute():
                raise WorkspaceError("invalid registered worktree path")
            try:
                registered.append(path.resolve())
            except (OSError, RuntimeError) as exc:
                raise WorkspaceError(
                    "cannot resolve registered worktree boundary"
                ) from exc
    if worktree not in registered or len(registered) > 128:
        raise WorkspaceError("invalid or oversized worktree inventory")
    identity = hashlib.sha256(f"{common}\0{worktree}".encode()).hexdigest()
    return common, head, identity, registered


def no_global_cargo_output(worktree: Path) -> bool:
    if any(key in os.environ for key in INHERITED_OUTPUT_KEYS):
        return False
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    if not cargo_home.is_absolute():
        cargo_home = worktree / cargo_home
    if ".." in cargo_home.parts:
        return False
    directories = [
        cargo_home,
        *(part / ".cargo" for part in (worktree, *worktree.parents)),
    ]
    for parent in directories:
        if not planned_directories_safe([parent]):
            return False
        for name in ("config", "config.toml"):
            path = parent / name
            if path.is_symlink():
                return False
            if not path.exists():
                continue
            config = tomllib.loads(read_bounded(path))
            build = config.get("build", {})
            if not isinstance(build, dict):
                return False
            if "target-dir" in build or "build-dir" in build:
                return False
    return True


def overlaps(first: Path, second: Path) -> bool:
    return first.is_relative_to(second) or second.is_relative_to(first)


def planned_directories_safe(paths: list[Path]) -> bool:
    for path in paths:
        for part in (path, *path.parents):
            try:
                mode = part.lstat().st_mode
            except FileNotFoundError:
                continue
            except OSError:
                return False
            if not stat.S_ISDIR(mode):
                return False
    return True


def inspect_outputs(worktree: Path) -> WorkspaceReport:
    report: WorkspaceReport = {
        "schema_version": 1,
        "qualification_evidence": False,
        "execution_performed": False,
        "scope": "read-only default output layout, not tool or runner qualification",
        "layout_ready": False,
        "checks": [],
        "development_mode": "workspace-local",
        "heavy_storage_required": False,
    }
    try:
        worktree = directory(worktree)
        common, head, identity, _ = checkout(worktree)
        report.update(
            worktree=str(worktree),
            common_git_dir=str(common),
            source_sha=head,
            worktree_id=identity,
        )
        report["checks"].append(
            CheckReport(
                name="checkout.identity",
                ready=True,
                remedy="Select a registered checkout root.",
            )
        )
        isolated = no_global_cargo_output(worktree)
        report["checks"].append(
            CheckReport(
                name="cargo.output_isolation",
                ready=isolated,
                remedy="Review output overrides; default and nested workspaces must not share targets.",
            )
        )
        safe = planned_directories_safe(
            [
                worktree / "target",
                worktree / ".artifacts/cmake/ui",
                worktree / ".artifacts/cmake/bridge",
            ]
        )
        safe = safe and all(
            cmake_owner_matches(
                worktree / f".artifacts/cmake/{component}",
                worktree / f"apps/linura-shell/{component}",
            )
            for component in ("ui", "bridge")
        )
        report["checks"].append(
            CheckReport(
                name="outputs.default_paths",
                ready=safe,
                remedy="Inspect paths and CMake ownership; reject files, symlinks and another checkout's cache.",
            )
        )
        report["layout_ready"] = isolated and safe
    except (OSError, ValueError):
        report["checks"].append(
            CheckReport(
                name="outputs.observation",
                ready=False,
                remedy="Inspect checkout metadata and Cargo configuration; unknown state is not ready.",
            )
        )
    return report


def cmake_owner_matches(build: Path, source: Path) -> bool:
    """Do not reuse a cache bound to another source or build directory."""
    cache = build / "CMakeCache.txt"
    if not cache.exists() and not cache.is_symlink():
        return True
    values: dict[str, str] = {}
    for line in read_bounded(cache).splitlines():
        for key in ("CMAKE_HOME_DIRECTORY", "CMAKE_CACHEFILE_DIR"):
            prefix = f"{key}:INTERNAL="
            if line.startswith(prefix):
                if key in values:
                    return False
                values[key] = line.removeprefix(prefix)
    return values == {
        "CMAKE_HOME_DIRECTORY": str(source),
        "CMAKE_CACHEFILE_DIR": str(build),
    }


def trusted_authority_test_directory(path: Path, expected_uid: int) -> bool:
    """Mirror the durable-test parent requirements without creating state."""
    if not path.is_absolute() or ".." in path.parts:
        return False
    current = Path("/")
    try:
        chain = [current]
        for component in path.parts[1:]:
            current /= component
            chain.append(current)
        for current in chain:
            metadata = current.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                return False
            trusted_owner = metadata.st_uid in (0, expected_uid)
            root_sticky_shared = metadata.st_uid == 0 and mode & stat.S_ISVTX != 0
            if not trusted_owner or (mode & 0o022 != 0 and not root_sticky_shared):
                return False
    except OSError:
        return False
    return True


def trusted_native_recovery_program(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == 0
        and stat.S_IMODE(metadata.st_mode) & 0o111 != 0
    )


def inspect_authority_host(*, recovery_profile: str | None = None) -> WorkspaceReport:
    """Inspect generic ownership and explicitly selected recovery prerequisites."""
    if recovery_profile not in (None, "ubuntu-v09"):
        raise ValueError("unsupported authority-host recovery profile")
    expected_uid = os.geteuid()
    temporary_root = Path(os.environ.get("TMPDIR", "/tmp"))
    checks = [
        Check(
            "authority_host.native_recovery_program",
            trusted_native_recovery_program(Path("/usr/bin/bash")),
            "Run authority-sensitive tests in a prepared host namespace where /usr/bin/bash is a root-owned regular executable; UID-remapped roots are unsupported. Use the documented prepared environment; never change host binary ownership.",
        ),
        Check(
            "authority_host.temporary_root",
            trusted_authority_test_directory(temporary_root, expected_uid),
            "Use a prepared namespace with native root-owned sticky /tmp, or select an absolute trusted TMPDIR whose directory chain is root/process-owned and not writable by other users except for a root-owned sticky shared root; do not replace /tmp with a user-owned shared mount.",
        ),
    ]
    if recovery_profile == "ubuntu-v09":
        checks.append(
            Check(
                "authority_host.native_recovery_package_manager",
                trusted_native_recovery_program(Path("/usr/bin/apt")),
                "The Ubuntu v0.9 recovery profile requires /usr/bin/apt as a root-owned regular executable; generic authority-host readiness does not require this Ubuntu package manager. Use the documented prepared environment; never change host binary ownership.",
            )
        )
    return WorkspaceReport(
        schema_version=1,
        qualification_evidence=False,
        execution_performed=False,
        scope=(
            "authority-test host ownership readiness"
            + (" with Ubuntu v0.9 recovery prerequisites" if recovery_profile else "")
            + ", not product or qualification evidence"
        ),
        layout_ready=all(check.ready for check in checks),
        checks=[
            CheckReport(name=check.name, ready=check.ready, remedy=check.remedy)
            for check in checks
        ],
    )


def inspect_editor(worktree: Path, qtpaths: str | None = None) -> WorkspaceReport:
    """Inspect the selected namespace's existing SDK and generated modules."""
    report = inspect_outputs(worktree)
    report["scope"] = (
        "Qt/editor prerequisites, not IDE activation or native qualification"
    )
    try:
        worktree = directory(worktree)
        executable = qtpaths or shutil.which("qtpaths6") or "/usr/lib/qt6/bin/qtpaths"
        output = probe([executable, "--query"], os.environ.copy())
        if output is None:
            raise WorkspaceError("Qt SDK query failed")
        sdk: dict[str, str] = {}
        for line in output.splitlines():
            key, separator, value = line.partition(":")
            if not separator or key in sdk:
                raise WorkspaceError("unknown Qt SDK output")
            sdk[key] = value
        version = sdk.get("QT_VERSION", "")
        if not re.fullmatch(r"6\.[0-9]+\.[0-9]+", version):
            raise WorkspaceError("unsupported Qt SDK")
        minor = int(version.split(".")[1])
        if minor < 4:
            raise WorkspaceError("unsupported Qt SDK")
        bins = directory(Path(sdk["QT_INSTALL_BINS"]))
        directory(Path(sdk["QT_INSTALL_HEADERS"]))
        qml_root = directory(Path(sdk["QT_INSTALL_QML"]))
        for module in ("QtQuick", "QtQuick.Controls", "QtQuick.Layouts"):
            imported = directory(qml_root.joinpath(*module.split(".")))
            if f"module {module}" not in read_bounded(imported / "qmldir").splitlines():
                raise WorkspaceError("Qt QML runtime/import metadata unavailable")
        server = bins / "qmlls"
        if not server.is_file() or not os.access(server, os.X_OK):
            raise WorkspaceError("Qt language server unavailable")
        help_text = probe([str(server), "--help"], os.environ.copy())
        if help_text is None or any(
            option not in help_text for option in ("--build-dir", "--ignore-settings")
        ):
            raise WorkspaceError("Qt language server unsupported")
        arguments = ["--ignore-settings"]
        databases = []
        for component, module in (("ui", "UI"), ("bridge", "ShellBridge")):
            build = worktree / f".artifacts/cmake/{component}"
            database = build / "compile_commands.json"
            entries = json.loads(read_bounded(database))
            if not isinstance(entries, list) or not entries:
                raise WorkspaceError("missing compilation database")
            if not all(
                isinstance(entry, dict)
                and entry.get("directory") == str(build)
                and isinstance(entry.get("file"), str)
                and Path(entry["file"]).is_relative_to(worktree)
                for entry in entries
            ):
                raise WorkspaceError("compilation database is from another checkout")
            source = worktree / f"apps/linura-shell/{component}"
            if not cmake_owner_matches(build, source):
                raise WorkspaceError("CMake source identity mismatch")
            generated = build / f"qml/org/linura/{module}"
            directory(generated)
            if (
                f"module org.linura.{module}"
                not in read_bounded(generated / "qmldir").splitlines()
            ):
                raise WorkspaceError("generated QML module mismatch")
            arguments.extend(["--build-dir", str(build)])
            databases.append(str(database))
        # Older pinned qmlls uses build-dir, not modern -I/-E switches. Custom
        # arguments override extension defaults; no download or host path shim.
        report["editor_settings"] = {
            "qt-core.additionalQtPaths": [str(bins / "qtpaths")],
            "qt-qml.qmlls.enabled": True,
            "qt-qml.qmlls.customExePath": str(server),
            "qt-qml.qmlls.customArgs": arguments,
            "qt-qml.doNotAskForQmllsDownload": True,
            "C_Cpp.default.compileCommands": databases,
        }
        report["checks"].append(
            CheckReport(
                name="editor.qt_sdk_and_generated_modules",
                ready=True,
                remedy="Use these settings only in this SDK/extension-host namespace.",
            )
        )
    except (OSError, ValueError, KeyError):
        report["checks"].append(
            CheckReport(
                name="editor.qt_sdk_and_generated_modules",
                ready=False,
                remedy="Build both modules and provide the matching prepared Qt SDK/qmlls; do not download substitutes.",
            )
        )
    report["layout_ready"] = all(check["ready"] for check in report["checks"])
    return report


def layout(
    storage: Path, identity: str, head: str, environment: str, run: str
) -> dict[str, dict[str, str]]:
    token(environment)
    token(run)
    if not re.fullmatch(r"[0-9a-f]{64}", identity) or not re.fullmatch(
        r"[0-9a-f]{40}", head
    ):
        raise WorkspaceError("invalid layout source identity")
    namespace = Path(identity) / environment / run / head
    return {
        "generated": {
            "cargo-target": str(storage / "builds" / namespace / "cargo"),
            "cmake-build": str(storage / "builds" / namespace / "cmake"),
            "temporary": str(storage / "qualification/runs" / namespace / "temporary"),
            "vm-disposable": str(
                storage / "qualification/vm-images/disposable" / namespace
            ),
        },
        "protected": {
            "recovery": str(storage / "recovery" / namespace),
            "qualification-artifacts": str(storage / "evidence" / namespace),
            "recordings": str(storage / "qualification/recordings" / namespace),
        },
        "prerequisite": {
            "vm-base": str(storage / "qualification/vm-images/base" / environment),
            "dependency-inputs": str(storage / "caches" / environment),
        },
    }


def inspect(
    worktree: Path,
    storage: Path | None,
    environment: str,
    run: str,
    min_free_gib: int,
    parallel: int,
    storage_id: str | None = None,
    vm_image: Path | None = None,
    evidence_dir: Path | None = None,
    fresh_run: bool = False,
    storage_selection: str | None = None,
    storage_class: str = "dedicated",
) -> StorageReport:
    if storage_class not in STORAGE_CLASSES:
        raise WorkspaceError("unsupported storage class")
    checks: list[Check] = []
    report: StorageReport = {
        "schema_version": 1,
        "qualification_evidence": False,
        "execution_performed": False,
        "scope": "read-only checkout/storage layout snapshot, not tool or runner qualification",
        "max_parallel_builds": parallel,
        "required_free_bytes": min_free_gib * parallel * GIB,
        "layout_ready": False,
        "checks": [],
        "development_mode": (
            "dedicated-storage" if storage_class == "dedicated" else storage_class
        ),
        "heavy_storage_required": True,
        "storage_class": storage_class,
    }
    if storage_selection is not None:
        report["storage_selection"] = storage_selection

    def add(name: str, ready: bool, remedy: str) -> None:
        checks.append(Check(name, ready, remedy))

    try:
        worktree = directory(worktree)
        common, head, identity, registered = checkout(worktree)
        report.update(
            worktree=str(worktree),
            common_git_dir=str(common),
            source_sha=head,
            worktree_id=identity,
        )
        add(
            "checkout.identity",
            True,
            "Select a registered checkout with valid Git metadata.",
        )
    except (OSError, ValueError):
        add(
            "checkout.identity",
            False,
            "Select the worktree root; remove inherited Git redirection and inspect metadata.",
        )
    else:
        try:
            isolated = no_global_cargo_output(worktree)
        except (OSError, ValueError):
            isolated = False
        add(
            "cargo.output_isolation",
            isolated,
            "Review inherited output variables and Cargo configuration; keep nested targets independent.",
        )
        if storage is None:
            add(
                "storage.unavailable",
                False,
                "Lightweight work remains available in the worktree. For heavy work, supply an existing mounted volume with --storage-root or LINURA_STORAGE_ROOT; this tool never creates or resizes storage.",
            )
        else:
            try:
                storage = directory(storage)
                if (
                    storage == Path(storage.anchor)
                    or storage == Path.home()
                    or any(overlaps(storage, path) for path in [common, *registered])
                ):
                    raise WorkspaceError("storage overlaps source or broad roots")
                add(
                    "storage.boundary",
                    True,
                    "Choose a separate non-symlink storage directory outside all registered source/Git roots.",
                )
                inventory = mounts(read_bounded(Path("/proc/self/mountinfo")))
                storage_mount = containing_mount(storage, inventory)
                provider_ready = False
                separate = False
                backing = False
                identified = False
                if storage_class == "github-hosted-ephemeral":
                    expected = github_hosted_ephemeral_root(worktree)
                    provider_ready = storage == expected and mount_device_matches(
                        storage, storage_mount
                    )
                    add(
                        "storage.github_hosted_ephemeral",
                        provider_ready,
                        "Use the protected GitHub-hosted Linux runner's exact RUNNER_TEMP/linura-data root; self-hosted and local execution require dedicated storage.",
                    )
                else:
                    source_mount = containing_mount(worktree, inventory)
                    system_mount = containing_mount(Path("/"), inventory)
                    separate = independent_mount(
                        source_mount, storage_mount
                    ) and independent_mount(system_mount, storage_mount)
                    # A subdirectory, subvolume/bind alias or read-only mount is not
                    # the independently provisioned writable storage contract.
                    separate = (
                        separate
                        and storage_mount.target == storage
                        and storage_mount.root == Path("/")
                    )
                    separate = separate and "rw" in storage_mount.options
                    separate = (
                        separate
                        and sum(
                            item.device == storage_mount.device for item in inventory
                        )
                        == 1
                    )
                    separate = separate and mount_device_matches(storage, storage_mount)
                    add(
                        "storage.independent_filesystem",
                        separate,
                        "Provision a writable dedicated filesystem at this exact root; reject root-disk, bind/subvolume aliases, overlayfs and tmpfs.",
                    )
                    block_inventory = probe(
                        ["lsblk", "--json", "--tree", "--output", "MAJ:MIN,TYPE"],
                        os.environ.copy(),
                    )
                    disks = (
                        backing_disks(block_inventory)
                        if block_inventory is not None
                        else {}
                    )
                    backing = (
                        all(
                            mount.device in disks
                            for mount in (source_mount, system_mount, storage_mount)
                        )
                        and disks[storage_mount.device] != disks[source_mount.device]
                        and disks[storage_mount.device] != disks[system_mount.device]
                    )
                    add(
                        "storage.independent_backing",
                        backing,
                        "Provide a separate block disk with known partition topology; loop, shared-system-disk and unsupported backing fail closed.",
                    )
                    actual_id = probe(
                        [
                            "findmnt",
                            "--noheadings",
                            "--output",
                            "UUID",
                            "--target",
                            str(storage),
                        ],
                        os.environ.copy(),
                    )
                    identified = (
                        storage_id is not None
                        and UUID_PATTERN.fullmatch(storage_id) is not None
                        and actual_id == storage_id
                    )
                    if identified:
                        assert storage_id is not None
                        report["storage_uuid"] = storage_id
                    add(
                        "storage.identity",
                        identified,
                        "Declare the independently verified filesystem UUID; unknown or changed storage fails closed.",
                    )
                info = storage.stat()
                accessible = (
                    info.st_uid == os.geteuid()
                    and not stat.S_IMODE(info.st_mode) & 0o077
                    and os.access(storage, os.W_OK | os.X_OK, effective_ids=True)
                )
                add(
                    "storage.permissions",
                    accessible,
                    "Provision a private caller-owned writable/searchable storage root; do not repair permissions during a task.",
                )
                usage = os.statvfs(storage)
                available = usage.f_bavail * usage.f_frsize
                report.update(
                    storage_root=str(storage),
                    filesystem=storage_mount.filesystem,
                    available_bytes=available,
                    available_inodes=usage.f_favail,
                )
                add(
                    "storage.free_bytes",
                    available >= min_free_gib * parallel * GIB,
                    "Budget measured cold-build/VM/recording peaks for every concurrent run; reclaim only verified disposable output.",
                )
                add(
                    "storage.free_inodes",
                    usage.f_files > 0 and usage.f_favail >= 65536 * parallel,
                    "Provide enough inode headroom for build inputs and generated output.",
                )
                paths = layout(storage, identity, head, environment, run)
                if fresh_run:
                    evidence = Path(paths["protected"]["qualification-artifacts"])
                    unused = planned_directories_safe([evidence]) and (
                        not evidence.exists() or next(evidence.iterdir(), None) is None
                    )
                    add(
                        "storage.fresh_run",
                        unused,
                        "Choose a fresh run ID; retained evidence and failure diagnostics must not be purged by relaunch.",
                    )
                if evidence_dir is not None:
                    if evidence_dir != Path(
                        paths["protected"]["qualification-artifacts"]
                    ):
                        raise WorkspaceError(
                            "evidence destination is outside this run's protected namespace"
                        )
                if vm_image is not None:
                    selected_image = directory(vm_image.parent) / vm_image.name
                    if any(
                        ord(char) < 32 or ord(char) == 127
                        for char in str(selected_image)
                    ):
                        raise WorkspaceError("unsafe VM image path")
                    if not selected_image.is_relative_to(
                        storage / "qualification/vm-images"
                    ):
                        raise WorkspaceError("VM image is outside dedicated VM storage")
                    image_info = selected_image.lstat()
                    if (
                        not stat.S_ISREG(image_info.st_mode)
                        or image_info.st_nlink != 1
                        or image_info.st_mode & stat.S_IWOTH
                    ):
                        raise WorkspaceError("VM image is not a regular file")
                    if not mount_device_matches(selected_image, storage_mount):
                        raise WorkspaceError("VM image is on another filesystem")
                safe = run_paths_private(
                    storage,
                    identity,
                    [
                        Path(value)
                        for group in paths.values()
                        for value in group.values()
                    ],
                )
                add(
                    "storage.layout_paths",
                    safe,
                    "Inspect existing paths; do not follow layout symlinks into protected or unrelated state.",
                )
                private = protected_paths_private(storage, paths["protected"])
                add(
                    "storage.protected_permissions",
                    private,
                    "Existing evidence, recovery and recording directories must be private and owned by this user; create missing run directories with umask 077.",
                )
                boundary_ready = (
                    provider_ready
                    if storage_class == "github-hosted-ephemeral"
                    else separate and backing and identified
                )
                if boundary_ready and safe and accessible and private:
                    report["layout"] = paths
            except (OSError, ValueError):
                name = (
                    "storage.observation"
                    if any(check.name == "storage.boundary" for check in checks)
                    else "storage.boundary"
                )
                add(
                    name,
                    False,
                    "Supply an existing persistent storage directory and inspect its mount/capacity; this tool never creates or mounts it.",
                )
    report["layout_ready"] = bool(checks) and all(check.ready for check in checks)
    report["checks"] = [
        CheckReport(name=check.name, ready=check.ready, remedy=check.remedy)
        for check in checks
    ]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "outputs", help="check safe worktree-local default Cargo/CMake outputs"
    )
    authority_host = sub.add_parser(
        "authority-host",
        help="check generic authority-test ownership semantics",
    )
    authority_host.add_argument(
        "--recovery-profile",
        choices=("ubuntu-v09",),
        help="also check prerequisites for the selected qualified recovery profile",
    )
    storage = sub.add_parser(
        "storage", help="inspect an operator-provisioned persistent volume"
    )
    editor = sub.add_parser(
        "editor", help="inspect the existing Qt SDK and generated editor metadata"
    )
    editor.add_argument("--qtpaths")
    storage.add_argument(
        "--storage-root",
        type=Path,
        help="existing heavy-storage mount; otherwise use LINURA_STORAGE_ROOT or an already-mounted /mnt/linura-data",
    )
    storage.add_argument("--storage-id", default=os.environ.get("LINURA_STORAGE_ID"))
    storage.add_argument(
        "--storage-class",
        choices=STORAGE_CLASSES,
        default=os.environ.get("LINURA_STORAGE_CLASS", "dedicated"),
    )
    storage.add_argument("--environment", type=token, required=True)
    storage.add_argument("--run", type=token, required=True)
    storage.add_argument("--min-free-gib", type=positive, default=8)
    storage.add_argument("--max-parallel-builds", type=positive, default=1)
    storage.add_argument("--vm-image", type=Path)
    storage.add_argument("--evidence-dir", type=Path)
    storage.add_argument("--fresh-run", action="store_true")
    storage.add_argument("--field", choices=("temporary", "evidence", "vm-disposable"))
    args = parser.parse_args()
    selected_storage: Path | None = None
    storage_selection: str | None = None
    if args.command == "storage":
        selected_storage, storage_selection = select_storage_root(args.storage_root)
    report = (
        inspect_outputs(args.worktree)
        if args.command == "outputs"
        else inspect_authority_host(recovery_profile=args.recovery_profile)
        if args.command == "authority-host"
        else inspect_editor(args.worktree, args.qtpaths)
        if args.command == "editor"
        else inspect(
            args.worktree,
            selected_storage,
            args.environment,
            args.run,
            args.min_free_gib,
            args.max_parallel_builds,
            args.storage_id,
            args.vm_image,
            args.evidence_dir,
            args.fresh_run,
            storage_selection,
            args.storage_class,
        )
    )
    if args.command == "storage" and args.field:
        if not report["layout_ready"] or "layout" not in report:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1
        group, key = (
            ("protected", "qualification-artifacts")
            if args.field == "evidence"
            else ("generated", args.field)
        )
        print(report["layout"][group][key])
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["layout_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
