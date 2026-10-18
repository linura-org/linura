#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
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


def _valid_type(value, kind: str) -> bool:
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "null":
        return value is None
    raise ValueError(f"unsupported schema type {kind!r}")


def validate(value, schema, where: str, *, root_schema=None) -> None:
    if root_schema is None:
        root_schema = schema
    if not isinstance(schema, dict):
        raise ValueError(f"{where}: invalid JSON schema")

    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise ValueError(f"{where}: unsupported schema reference {reference!r}")
        target = root_schema
        for component in reference[2:].split("/"):
            key = component.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or key not in target:
                raise ValueError(f"{where}: unresolved schema reference {reference!r}")
            target = target[key]
        validate(value, target, where, root_schema=root_schema)

    expected = schema.get("type")
    if expected is not None:
        alternatives = expected if isinstance(expected, list) else [expected]
        if not alternatives or not all(isinstance(x, str) for x in alternatives):
            raise ValueError(f"{where}: malformed schema type {expected!r}")
        if not any(_valid_type(value, kind) for kind in alternatives):
            raise ValidationError(f"{where}: expected type {expected!r}")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise ValidationError(f"{where}: missing required key {key!r}")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                validate(
                    item, properties[key], f"{where}.{key}", root_schema=root_schema
                )
            elif schema.get("additionalProperties") is False:
                raise ValidationError(f"{where}: unexpected key {key!r}")
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ValidationError(f"{where}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ValidationError(f"{where}: too many items")
        if schema.get("uniqueItems") and len(
            {json.dumps(item, sort_keys=True) for item in value}
        ) != len(value):
            raise ValidationError(f"{where}: expected unique items")
        if "items" in schema:
            for index, item in enumerate(value):
                validate(
                    item, schema["items"], f"{where}[{index}]", root_schema=root_schema
                )
        if "contains" in schema:
            matches = 0
            for index, item in enumerate(value):
                try:
                    validate(
                        item,
                        schema["contains"],
                        f"{where}[{index}]",
                        root_schema=root_schema,
                    )
                except ValidationError:
                    continue
                matches += 1
            if matches < schema.get("minContains", 1):
                raise ValidationError(f"{where}: too few matching items")
            if "maxContains" in schema and matches > schema["maxContains"]:
                raise ValidationError(f"{where}: too many matching items")
    elif isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValidationError(f"{where}: string too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ValidationError(f"{where}: string too long")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValidationError(f"{where}: string does not match required pattern")

    if "const" in schema and value != schema["const"]:
        raise ValidationError(f"{where}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError(f"{where}: expected one of {schema['enum']!r}")

    for part in schema.get("allOf", []):
        validate(value, part, where, root_schema=root_schema)
    for keyword in ("anyOf", "oneOf"):
        if keyword not in schema:
            continue
        matches = 0
        for part in schema[keyword]:
            try:
                validate(value, part, where, root_schema=root_schema)
            except ValidationError:
                continue
            matches += 1
        if keyword == "anyOf" and matches == 0:
            raise ValidationError(f"{where}: no matching schema alternative")
        if keyword == "oneOf" and matches != 1:
            raise ValidationError(f"{where}: expected exactly one schema alternative")
    if "if" in schema:
        try:
            validate(value, schema["if"], where, root_schema=root_schema)
        except ValidationError:
            branch = schema.get("else")
        else:
            branch = schema.get("then")
        if branch is not None:
            validate(value, branch, where, root_schema=root_schema)
    if "not" in schema:
        try:
            validate(value, schema["not"], where, root_schema=root_schema)
        except ValidationError:
            pass
        else:
            raise ValidationError(f"{where}: matched prohibited schema")


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
