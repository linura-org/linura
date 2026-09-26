#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tomllib


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink():
        fail(f"missing or untrusted file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


if len(sys.argv) != 5:
    fail("usage: verify-substrate.py CONTRACT BUILDER IMAGE MANIFEST")

contract_path = pathlib.Path(sys.argv[1])
builder_path = pathlib.Path(sys.argv[2])
image_path = pathlib.Path(sys.argv[3])
manifest_path = pathlib.Path(sys.argv[4])

contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

if manifest.get("schema_version") != 1:
    fail("prepared substrate manifest schema_version must be 1")
if manifest.get("id") != contract.get("id"):
    fail("prepared substrate id does not match contract")
if manifest.get("claim") != "non-authoritative-prepared-substrate":
    fail("prepared substrate claim drifted")
if manifest.get("contract_sha256") != digest(contract_path):
    fail("prepared substrate contract digest mismatch")
if manifest.get("builder_sha256") != digest(builder_path):
    fail("prepared substrate builder digest mismatch")
image_sha256 = digest(image_path)
if manifest.get("prepared_image_sha256") != image_sha256:
    fail("prepared substrate image digest mismatch")

base_image = manifest.get("base_image")
if not isinstance(base_image, dict) or base_image.get("url") != contract.get("base_image_url"):
    fail("prepared substrate base-image identity mismatch")
base_image_sha256 = base_image.get("sha256")
if not isinstance(base_image_sha256, str) or len(base_image_sha256) != 64:
    fail("prepared substrate base-image digest is missing or malformed")
archive = manifest.get("arch_archive")
if not isinstance(archive, dict):
    fail("prepared substrate archive identity is missing")
if archive.get("snapshot") != contract.get("arch_archive_snapshot"):
    fail("prepared substrate archive snapshot mismatch")
if archive.get("url") != contract.get("arch_archive_url"):
    fail("prepared substrate archive URL mismatch")
if manifest.get("runtime_packages") != contract.get("runtime_packages"):
    fail("prepared substrate runtime package set mismatch")

package_versions = manifest.get("package_versions")
if not isinstance(package_versions, list) or not package_versions:
    fail("prepared substrate package-version evidence is incomplete")
names = set()
for record in package_versions:
    if not isinstance(record, str) or " " not in record:
        fail(f"invalid prepared substrate package-version record: {record!r}")
    name, version = record.split(" ", 1)
    if not name or not version or name in names:
        fail(f"invalid or duplicate prepared substrate package-version record: {record!r}")
    names.add(name)

for key, expected in (
    ("sanitized", True),
    ("contains_linura_source", False),
    ("contains_linura_build_outputs", False),
    ("qualification_evidence", False),
    ("release_support_promotion", False),
):
    if manifest.get(key) is not expected:
        fail(f"prepared substrate manifest {key} must remain {expected!r}")

print(image_sha256)
