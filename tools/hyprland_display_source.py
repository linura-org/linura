#!/usr/bin/env python3
"""Stage the exact reviewed Hyprland source integration; never install host tools.

This consumes an explicitly supplied, published-digest-pinned release archive.
It neither downloads mutable sources nor compiles/installs/qualifies a compositor.
Native build and qualification remain separate mandatory steps.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import runpy
from types import SimpleNamespace
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PIN = "contracts/hyprland-display-integration.toml"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_UNPACKED = 512 * 1024 * 1024
MAX_MEMBERS = 100_000


RECIPE = ROOT / "apps/linura-hyprland-display/source_integration.py"
if (
    RECIPE.is_symlink()
    or not RECIPE.is_file()
    or RECIPE.stat().st_size > 2 * 1024 * 1024
):
    raise ValueError("native integration recipe is absent, substituted or oversized")
RECIPE_SHA256 = hashlib.sha256(RECIPE.read_bytes()).hexdigest()
integration = SimpleNamespace(**runpy.run_path(str(RECIPE)))
if hashlib.sha256(RECIPE.read_bytes()).hexdigest() != RECIPE_SHA256:
    raise ValueError("native integration recipe changed while loading")
SourceError = integration.SourceError


def require_loaded_recipe() -> None:
    if (
        RECIPE.is_symlink()
        or not RECIPE.is_file()
        or RECIPE.stat().st_size > 2 * 1024 * 1024
        or hashlib.sha256(RECIPE.read_bytes()).hexdigest() != RECIPE_SHA256
    ):
        raise SourceError("native integration recipe changed after loading")


def extract_verified_archive(
    archive: Path, destination: Path, digest: str, top: str
) -> Path:
    """Extract verified immutable bytes, with no archive-created links.

    Keeping the original descriptor alone would not prevent in-place writes
    after verification. The bounded immutable copy is the extraction input.
    """
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= MAX_ARCHIVE
        ):
            raise SourceError("pinned source archive is not a bounded regular file")
        content = stream.read(MAX_ARCHIVE + 1)
        if len(content) != metadata.st_size or len(content) > MAX_ARCHIVE:
            raise SourceError("pinned source archive changed while reading")
        if hashlib.sha256(content).hexdigest() != digest:
            raise SourceError("pinned source archive checksum mismatch")
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as source:
            members: list[tarfile.TarInfo] = []
            seen: set[str] = set()
            total = 0
            for member in source:
                path = PurePosixPath(member.name)
                total += member.size
                if (
                    len(members) >= MAX_MEMBERS
                    or member.size < 0
                    or total > MAX_UNPACKED
                    or not (member.isdir() or member.isfile())
                    or path.is_absolute()
                    or not path.parts
                    or path.parts[0] != top
                    or ".." in path.parts
                    or path.as_posix() in seen
                    or member.name.rstrip("/") != path.as_posix()
                    or any(ord(c) < 32 or c == "\\" for c in member.name)
                ):
                    raise SourceError("unsafe or over-budget pinned source archive")
                seen.add(path.as_posix())
                members.append(member)
            if not members:
                raise SourceError("pinned source archive is empty")
            # Reject an archive declaring a regular file as another member's
            # parent before creating anything, including reversed entry order.
            regular = {PurePosixPath(m.name) for m in members if m.isfile()}
            if any(
                any(p in regular for p in PurePosixPath(m.name).parents)
                for m in members
            ):
                raise SourceError("pinned source archive has conflicting parents")
            destination.mkdir(mode=0o700, parents=False, exist_ok=False)
            for member in members:
                target = destination / member.name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if member.isdir():
                    target.mkdir(mode=0o700, exist_ok=True)
                    continue
                data = source.extractfile(member)
                if data is None:
                    raise SourceError("pinned source member is unreadable")
                output = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o755 if member.mode & 0o111 else 0o644,
                )
                with data, os.fdopen(output, "wb") as installed:
                    shutil.copyfileobj(data, installed, 1024 * 1024)
    return destination / top


def stage(archive: Path, destination: Path, root: Path = ROOT) -> dict[str, object]:
    require_loaded_recipe()
    pin = tomllib.loads((root / PIN).read_text(encoding="utf-8"))
    if (
        pin.get("schema_version") != 1
        or pin.get("integration_id") != "linura-hyprland-display-v1"
    ):
        raise SourceError("unsupported native integration source contract")
    source = extract_verified_archive(
        archive, destination, pin["source_sha256"], pin["source_top"]
    )
    inputs: dict[str, str] = {}
    for item in pin["upstream_file"]:
        path = PurePosixPath(item["path"])
        if path.is_absolute() or ".." in path.parts or path.as_posix() in inputs:
            raise SourceError("invalid native integration input path")
        data = (source / path).read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise SourceError("reviewed upstream source checksum mismatch")
        inputs[path.as_posix()] = data.decode("utf-8")
    outputs = integration.patch_sources(inputs, pin["upstream_commit"])
    require_loaded_recipe()
    digests = {}
    for name, text in outputs.items():
        (source / name).write_text(text, encoding="utf-8")
        digests[name] = hashlib.sha256(text.encode()).hexdigest()
    manifest = {
        "schema_version": 1,
        "integration_id": pin["integration_id"],
        "upstream_commit": pin["upstream_commit"],
        "source_sha256": pin["source_sha256"],
        "patched_files": digests,
        "integration_recipe_sha256": RECIPE_SHA256,
        "qualification_evidence": False,
    }
    (destination / "linura-display-source.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument(
        "--destination",
        type=Path,
        required=True,
        help="new staging directory; existing destinations are rejected",
    )
    args = parser.parse_args()
    try:
        print(json.dumps(stage(args.archive, args.destination), indent=2))
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, f"native source staging failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
