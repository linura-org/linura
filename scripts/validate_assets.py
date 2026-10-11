#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


class ValidationError(Exception):
    pass


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise ValidationError(
            f"{path.relative_to(ROOT)}: invalid JSON: {error}"
        ) from error


def validate(value, schema, where: str) -> None:
    expected = schema.get("type")
    if isinstance(expected, list):
        valid = False
        for item in expected:
            try:
                validate(value, {**schema, "type": item}, where)
            except ValidationError:
                continue
            valid = True
            break
        if not valid:
            raise ValidationError(
                f"{where}: value does not match any allowed type {expected}"
            )
        return
    if expected == "object":
        if not isinstance(value, dict):
            raise ValidationError(f"{where}: expected object")
        for key in schema.get("required", []):
            if key not in value:
                raise ValidationError(f"{where}: missing required key {key!r}")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                validate(item, properties[key], f"{where}.{key}")
            elif schema.get("additionalProperties") is False:
                raise ValidationError(f"{where}: unexpected key {key!r}")
    elif expected == "array":
        if not isinstance(value, list):
            raise ValidationError(f"{where}: expected array")
        if len(value) < schema.get("minItems", 0):
            raise ValidationError(f"{where}: too few items")
        if schema.get("uniqueItems") and len(
            {json.dumps(item, sort_keys=True) for item in value}
        ) != len(value):
            raise ValidationError(f"{where}: expected unique items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                validate(item, item_schema, f"{where}[{index}]")
    elif expected == "string":
        if not isinstance(value, str):
            raise ValidationError(f"{where}: expected string")
        if len(value) < schema.get("minLength", 0):
            raise ValidationError(f"{where}: string too short")
    elif expected == "boolean":
        if not isinstance(value, bool):
            raise ValidationError(f"{where}: expected boolean")
    elif expected == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(f"{where}: expected integer")
    elif expected == "null":
        if value is not None:
            raise ValidationError(f"{where}: expected null")

    if "const" in schema and value != schema["const"]:
        raise ValidationError(f"{where}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError(f"{where}: expected one of {schema['enum']!r}")


def validate_against(asset: str, schema: str) -> None:
    asset_path = ROOT / asset
    schema_path = ROOT / schema
    validate(load_json(asset_path), load_json(schema_path), asset)


def main() -> int:
    failures: list[str] = []
    mappings: list[tuple[str, str]] = []
    mappings.extend(
        (str(path.relative_to(ROOT)), "schemas/hardware-fixture.v1.schema.json")
        for path in sorted((ROOT / "hardware/fixtures").glob("*.json"))
    )
    mappings.extend(
        (str(path.relative_to(ROOT)), "schemas/acceptance-scenario.v1.schema.json")
        for path in sorted((ROOT / "tests/acceptance").glob("*.json"))
    )
    mappings.extend(
        (str(path.relative_to(ROOT)), "schemas/migration.v1.schema.json")
        for path in sorted((ROOT / "migrations").glob("*/*.json"))
    )
    mappings.append(
        ("visual/baselines/manifest.json", "schemas/visual-baseline.v1.schema.json")
    )
    mappings.append(
        ("supervision/default-desktop.json", "schemas/app-supervision.v1.schema.json")
    )
    mappings.extend(
        (str(path.relative_to(ROOT)), "schemas/lifecycle-workflow.v1.schema.json")
        for path in sorted((ROOT / "lifecycle/examples").glob("*.json"))
    )

    seen_schema_ids: set[str] = set()
    for schema_path in sorted((ROOT / "schemas").glob("*.schema.json")):
        try:
            schema = load_json(schema_path)
            schema_id = schema.get("$id")
            if not isinstance(schema_id, str) or not schema_id:
                raise ValidationError(
                    f"{schema_path.relative_to(ROOT)}: schema must define non-empty $id"
                )
            if schema_id in seen_schema_ids:
                raise ValidationError(
                    f"{schema_path.relative_to(ROOT)}: duplicate schema $id {schema_id}"
                )
            seen_schema_ids.add(schema_id)
        except ValidationError as error:
            failures.append(str(error))

    for asset, schema in mappings:
        try:
            validate_against(asset, schema)
        except ValidationError as error:
            failures.append(str(error))

    support = load_json(ROOT / "hardware/support-matrix.json")
    allowed_tiers = set(support.get("evidence_tiers", []))
    for domain, tier in support.get("domains", {}).items():
        if tier not in allowed_tiers:
            failures.append(
                f"hardware/support-matrix.json: {domain} uses unknown evidence tier {tier!r}"
            )

    install_policy = load_json(
        ROOT / "packaging/arch/archiso/airootfs/etc/linura/install-policy.json"
    )
    if install_policy.get("disk_encryption") != "required_for_supported_install":
        failures.append(
            "install policy must require disk encryption for supported installs"
        )
    if install_policy.get("firewall_inbound") != "deny_by_default":
        failures.append("install policy must use deny-by-default inbound firewall")
    if install_policy.get("ssh_initial_state") != "disabled":
        failures.append("install policy must start with SSH disabled")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(
        f"asset checks passed ({len(mappings)} schema-validated assets, {len(seen_schema_ids)} schemas)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
