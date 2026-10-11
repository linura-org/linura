#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def spdx_id(prefix: str, value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-") or "item"
    return f"SPDXRef-{prefix}-{clean}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate SPDX 2.3 SBOM for Linura candidate artifacts and Cargo.lock packages"
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("artifacts", nargs="+", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()

    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    packages = []
    package_ids: dict[tuple[str, str], str] = {}
    for package in lock.get("package", []):
        name = package["name"]
        version = package["version"]
        identifier = spdx_id("Package", f"{name}-{version}")
        package_ids[(name, version)] = identifier
        packages.append(
            {
                "SPDXID": identifier,
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )

    files = []
    relationships = []
    for index, path in enumerate(args.artifacts, 1):
        file_id = f"SPDXRef-File-{index}"
        files.append(
            {
                "SPDXID": file_id,
                "fileName": path.name,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest(path)}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": file_id,
            }
        )

    for package in packages:
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": package["SPDXID"],
            }
        )

    # Cargo.lock dependency strings may include only names for path packages. Link unambiguous names.
    ids_by_name: dict[str, list[str]] = {}
    for (name, _version), identifier in package_ids.items():
        ids_by_name.setdefault(name, []).append(identifier)
    for package in lock.get("package", []):
        source_id = package_ids[(package["name"], package["version"])]
        for dependency in package.get("dependencies", []):
            dep_name = dependency.split(" ", 1)[0]
            candidates = ids_by_name.get(dep_name, [])
            if len(candidates) == 1:
                relationships.append(
                    {
                        "spdxElementId": source_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": candidates[0],
                    }
                )

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"Linura-{args.version}",
        "documentNamespace": f"https://linura.org/spdx/{args.version}/{args.source_sha}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: linura-generate-sbom-0.0.0"],
        },
        "documentComment": f"Built from source commit {args.source_sha}",
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
