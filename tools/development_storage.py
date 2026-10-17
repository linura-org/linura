#!/usr/bin/env python3
"""Guard and prepare unprivileged heavy-workload paths; never provision a disk.

This is developer infrastructure, not qualification evidence or product authority.
All paths come from the existing read-only workspace/storage inspector. Preparation
creates only new private run directories; no cleanup, permission repair or fallback.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from tools import development_workspace as workspace  # noqa: E402

ROLES = {
    "temporary": ("generated", "temporary"),
    "vm": ("generated", "vm-disposable"),
    "cargo": ("generated", "cargo-target"),
    "cmake": ("generated", "cmake-build"),
    "evidence": ("protected", "qualification-artifacts"),
    "recordings": ("protected", "recordings"),
}


def arguments(run: str | None) -> argparse.Namespace:
    storage_root, _ = workspace.select_storage_root(None)
    if storage_root is None:
        raise workspace.WorkspaceError(
            "heavy storage is unavailable; declare an existing mount with LINURA_STORAGE_ROOT"
        )
    return argparse.Namespace(
        storage_root=storage_root,
        storage_id=os.environ.get("LINURA_STORAGE_ID"),
        storage_class=os.environ.get("LINURA_STORAGE_CLASS", "dedicated"),
        run=run,
    )


def create_github_hosted_ephemeral_root(source: Path) -> None:
    """Reserve the private job-local root; never emulate a persistent volume."""
    expected = workspace.github_hosted_ephemeral_root(source)
    selected, _ = workspace.select_storage_root(None)
    if selected is None or Path(os.path.abspath(selected)) != expected:
        raise workspace.WorkspaceError(
            "provider-ephemeral storage root is not canonical"
        )
    parent = expected.parent
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(expected.name, mode=0o700, dir_fd=descriptor)
        child = os.open(
            expected.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        try:
            info = os.fstat(child)
            if (
                info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_dev != os.fstat(descriptor).st_dev
            ):
                raise workspace.WorkspaceError(
                    "provider-ephemeral storage root is not private and job-local"
                )
        finally:
            os.close(child)
    finally:
        os.close(descriptor)


def run_layout(
    source: Path, environment: str, run: str | None
) -> dict[str, dict[str, str]]:
    return workspace.execution_layout(source, arguments(run), environment)


def role_path(paths: dict[str, dict[str, str]], role: str) -> Path:
    group, name = ROLES[role]
    return Path(paths[group][name])


def require_destination(
    source: Path,
    environment: str,
    destination: Path,
    role: str,
    *,
    run: str | None = None,
    fresh: bool = False,
) -> Path:
    """Validate the exact source/run namespace before copying or publishing data.

    Run identity may be supplied explicitly or derived from the role's canonical
    path. Derivation is not authority: the inspector independently binds current
    Git/worktree identity, volume identity and every selected boundary.
    """
    selected_root = workspace.directory(arguments(run).storage_root)
    selected = Path(os.path.abspath(destination.expanduser()))
    if ".." in destination.parts or not workspace.planned_directories_safe([selected]):
        raise workspace.WorkspaceError("unsafe heavy-workload destination")
    if run is None:
        family = {
            "evidence": "evidence",
            "recordings": "qualification/recordings",
            "temporary": "qualification/runs",
            "vm": "qualification/vm-images/disposable",
            "cargo": "builds",
            "cmake": "builds",
        }[role]
        relative = selected.relative_to(selected_root / family)
        if len(relative.parts) < 4 or relative.parts[1] != environment:
            raise workspace.WorkspaceError("destination has no canonical run identity")
        run = relative.parts[2]
    paths = run_layout(source, environment, run)
    permitted = role_path(paths, role)
    if not selected.is_relative_to(permitted):
        raise workspace.WorkspaceError(
            "destination is outside the current storage namespace"
        )
    for part in (selected, *selected.parents):
        if not part.is_relative_to(permitted):
            continue
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise workspace.WorkspaceError(
                "run destinations must be private caller-owned directories"
            )
        if info.st_dev != selected_root.stat().st_dev:
            raise workspace.WorkspaceError(
                "run destination moved to another filesystem"
            )
    if fresh and selected.exists() and next(selected.iterdir(), None) is not None:
        raise workspace.WorkspaceError(
            "retained run data exists; choose a fresh destination"
        )
    return selected


def private_tree(root: Path, destination: Path, *, exclusive: bool = False) -> None:
    """Directory-relative creation, without following links or repairing modes."""
    root = workspace.directory(root)
    relative = destination.relative_to(root)
    if not relative.parts or ".." in relative.parts:
        raise workspace.WorkspaceError("cannot create broad or escaping storage paths")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    device = os.fstat(descriptor).st_dev
    try:
        for index, part in enumerate(relative.parts):
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                if exclusive and index == len(relative.parts) - 1:
                    raise workspace.WorkspaceError(
                        "run already reserved; existing data is retained"
                    )
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if (
                info.st_dev != device
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise workspace.WorkspaceError(
                    "storage directories must be private, owned and on the checked volume"
                )
    finally:
        os.close(descriptor)


def prepare(
    source: Path, environment: str, run: str, source_sha: str
) -> dict[str, str]:
    source = workspace.directory(source)
    observed = workspace.checkout(source)[1]
    if source_sha != observed or workspace.git(
        source, "status", "--porcelain=v1", "--untracked-files=all"
    ):
        raise workspace.WorkspaceError(
            "qualification preparation requires a clean exact-source checkout"
        )
    storage_class = os.environ.get("LINURA_STORAGE_CLASS", "dedicated")
    if storage_class == "github-hosted-ephemeral":
        create_github_hosted_ephemeral_root(source)
    elif storage_class != "dedicated":
        raise workspace.WorkspaceError("unsupported storage class")
    paths = run_layout(source, environment, run)
    if role_path(paths, "temporary").parent.name != source_sha:
        raise workspace.WorkspaceError(
            "qualification preparation requires an exact-source storage namespace"
        )
    root = workspace.directory(arguments(run).storage_root)
    for role in ROLES:
        selected = role_path(paths, role)
        if selected.exists() and next(selected.iterdir(), None) is not None:
            raise workspace.WorkspaceError(
                "retained run data exists; choose a fresh run"
            )
    # Atomic final mkdir reserves the run before any output/evidence is touched.
    # Partial failures remain for inspection; there is no automatic rollback purge.
    private_tree(root, role_path(paths, "temporary"), exclusive=True)
    for role in ("vm", "cargo", "cmake", "evidence", "recordings"):
        private_tree(root, role_path(paths, role))
    private_tree(root, Path(paths["prerequisite"]["vm-base"]))
    return {
        "LINURA_WORK_DIR": str(role_path(paths, "temporary")),
        "LINURA_VM_DIR": str(role_path(paths, "vm")),
        "LINURA_VM_BASE_DIR": paths["prerequisite"]["vm-base"],
        "LINURA_CARGO_TARGET": str(role_path(paths, "cargo")),
        "LINURA_CMAKE_BUILD": str(role_path(paths, "cmake")),
        "ARTIFACT_DIR": str(role_path(paths, "evidence")),
        "LINURA_RECORDINGS_DIR": str(role_path(paths, "recordings")),
        "LINURA_RUN_ID": run,
        "CARGO_BUILD_JOBS": "1",
        "TMPDIR": str(role_path(paths, "temporary")),
    }


def check_vm(
    source: Path, environment: str, run: str, image: Path, seed: Path, persistent: bool
) -> Path:
    paths = run_layout(source, environment, run)
    root = workspace.directory(arguments(run).storage_root)
    image_root = (
        role_path(paths, "vm") if persistent else root / "qualification/vm-images"
    )
    workspace.regular_storage_input(image, image_root)
    workspace.regular_storage_input(seed, root / "qualification/vm-images")
    scratch = require_destination(
        source, environment, role_path(paths, "temporary"), "temporary", run=run
    )
    return workspace.directory(scratch)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--environment", type=workspace.token, required=True)
    parser.add_argument(
        "--run", type=workspace.token, default=os.environ.get("LINURA_RUN_ID")
    )
    sub = parser.add_subparsers(dest="command", required=True)
    provision = sub.add_parser("prepare")
    provision.add_argument("--source-sha", required=True)
    provision.add_argument("--format", choices=("json", "env"), default="json")
    check = sub.add_parser("check")
    check.add_argument("--role", choices=ROLES, required=True)
    check.add_argument("--path", type=Path, required=True)
    check.add_argument("--fresh", action="store_true")
    vm = sub.add_parser("vm")
    vm.add_argument("--image", type=Path, required=True)
    vm.add_argument("--seed", type=Path, required=True)
    vm.add_argument("--persistent", action="store_true")
    sub.add_parser("scratch")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            if args.run is None:
                raise workspace.WorkspaceError("preparation requires a run identity")
            result = prepare(
                args.source_root, args.environment, args.run, args.source_sha
            )
            if args.format == "env":
                for name, value in result.items():
                    if any(ord(char) < 32 or ord(char) == 127 for char in value):
                        raise workspace.WorkspaceError("unsafe environment path")
                    print(f"{name}={value}")
            else:
                print(
                    json.dumps(
                        {"qualification_evidence": False, "paths": result},
                        sort_keys=True,
                    )
                )
        elif args.command == "check":
            print(
                require_destination(
                    args.source_root,
                    args.environment,
                    args.path,
                    args.role,
                    run=args.run,
                    fresh=args.fresh,
                )
            )
        elif args.command == "scratch":
            if args.run is None:
                raise workspace.WorkspaceError(
                    "scratch selection requires a run identity"
                )
            paths = run_layout(args.source_root, args.environment, args.run)
            scratch = require_destination(
                args.source_root,
                args.environment,
                role_path(paths, "temporary"),
                "temporary",
                run=args.run,
            )
            print(workspace.directory(scratch))
        else:
            if args.run is None:
                raise workspace.WorkspaceError("VM execution requires a run identity")
            print(
                check_vm(
                    args.source_root,
                    args.environment,
                    args.run,
                    args.image,
                    args.seed,
                    args.persistent,
                )
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"storage denied: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
