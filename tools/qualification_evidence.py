#!/usr/bin/env python3
"""Independently admit qualification artifacts against an exact execution envelope."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import qualification_envelope as envelope_lib  # noqa: E402
from tools import qualification_evidence_verifiers as semantic_verifier  # noqa: E402

CONTRACT_PATH = Path("contracts/qualification-evidence-binding.toml")
IMPLEMENTATION_PATH = Path("tools/qualification_evidence.py")
VERIFIER_PATH = Path("tools/qualification_evidence_verifiers.py")
ACTION_PATH = Path(".github/actions/qualification-evidence/action.yml")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
ALLOWED_ARTIFACT_KINDS = {"json-result", "file"}
CONTROL_FILES = frozenset({
    "qualification-execution-envelope.json",
    "qualification-execution-envelope.json.sha256",
    "verifier-result.json",
    "verifier-result.json.sha256",
    "evidence-binding.json",
    "evidence-binding.json.sha256",
})
TRIGGER_FILES = (
    ".github/actions/qualification-evidence/**",
    "contracts/qualification-evidence-binding.toml",
    "tools/qualification_evidence.py",
    "tools/qualification_evidence_verifiers.py",
    "tests/tooling/test_qualification_evidence.py",
)


class EvidenceError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_stable_regular(path: Path) -> tuple[int, os.stat_result]:
    _require(hasattr(os, "O_NOFOLLOW"), "no-follow file opens are unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"cannot open evidence file safely: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), f"evidence path is not a regular file: {path}")
        _require(before.st_nlink == 1, f"evidence file must have a single link: {path}")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, before


def _finish_stable_regular(
    path: Path, descriptor: int, before: os.stat_result
) -> None:
    after = os.fstat(descriptor)
    _require(
        _stat_identity(after) == _stat_identity(before),
        f"evidence file changed while being read: {path}",
    )
    try:
        named = os.lstat(path)
    except OSError as exc:
        raise EvidenceError(f"evidence file path changed while being read: {path}: {exc}") from exc
    _require(
        stat.S_ISREG(named.st_mode)
        and named.st_nlink == 1
        and named.st_dev == after.st_dev
        and named.st_ino == after.st_ino,
        f"evidence file path changed while being read: {path}",
    )


def _read_bytes_file(path: Path) -> bytes:
    descriptor, before = _open_stable_regular(path)
    chunks: list[bytes] = []
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        _finish_stable_regular(path, descriptor, before)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(_read_bytes_file(path)).hexdigest()


def _read_text_file(path: Path) -> str:
    descriptor, before = _open_stable_regular(path)
    chunks: list[bytes] = []
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        _finish_stable_regular(path, descriptor, before)
    finally:
        os.close(descriptor)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"evidence text file is not UTF-8: {path}") from exc

def _safe_repo_file(root: Path, relative: str) -> Path:
    _require(isinstance(relative, str) and relative and not relative.startswith("/"),
             "repository path must be non-empty and relative")
    _require(".." not in Path(relative).parts, "repository path may not traverse parents")
    path = root / relative
    _require(path.is_file() and not path.is_symlink(), f"missing or unsafe repository file: {relative}")
    _require(path.resolve().is_relative_to(root.resolve()), f"repository file escapes root: {relative}")
    return path


def _bundle_file(bundle: Path, filename: object, label: str) -> Path:
    _require(isinstance(filename, str) and filename and Path(filename).name == filename,
             f"{label} filename is invalid")
    path = bundle / filename
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    _require(path.stat(follow_symlinks=False).st_nlink == 1, f"{label} must have a single link")
    _require(path.resolve().parent == bundle.resolve(), f"{label} escapes evidence bundle")
    return path


def _atomic_write(path: Path, content: str) -> None:
    _require(not path.exists() or not path.is_symlink(), f"unsafe output path: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_json_with_checksum(path: Path, payload: dict, digest_field: str) -> None:
    digest = payload[digest_field]
    _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    _atomic_write(path.with_name(path.name + ".sha256"), f"{digest}  {path.name}\n")


def _verify_checksum(path: Path, digest: str) -> None:
    checksum = path.with_name(path.name + ".sha256")
    _require(checksum.is_file() and not checksum.is_symlink(), f"{path.name} checksum is missing or unsafe")
    _require(_read_text_file(checksum).strip() == f"{digest}  {path.name}",
             f"{path.name} checksum mismatch")


def _string_list(value: object, label: str, *, allow_empty: bool = False) -> list[str]:
    _require(isinstance(value, list), f"{label} must be a list")
    _require(allow_empty or bool(value), f"{label} must not be empty")
    _require(all(isinstance(item, str) and item and item.strip() == item for item in value),
             f"{label} contains invalid strings")
    _require(len(value) == len(set(value)), f"{label} contains duplicates")
    return list(value)


def load_contract(root: Path = ROOT) -> dict:
    path = _safe_repo_file(root, CONTRACT_PATH.as_posix())
    try:
        contract = tomllib.loads(_read_text_file(path))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError(f"cannot load evidence-binding contract: {exc}") from exc

    expected_top = {
        "schema_version", "id", "repository", "digest_algorithm", "canonicalization",
        "execution_envelope_contract", "execution_envelope_schema_version",
        "publication_policy", "binding_model", "non_evidence_lanes",
        "authority_boundary", "acceptance", "artifact_policy", "privacy",
        "profile",
    }
    _require(set(contract) == expected_top, "evidence-binding contract fields changed without schema review")
    _require(contract["schema_version"] == 3, "unsupported evidence-binding schema")
    _require(contract["id"] == "qualification/evidence-binding", "unexpected contract id")
    _require(contract["repository"] == "linura-org/linura", "unexpected repository identity")
    _require(contract["digest_algorithm"] == "sha256", "evidence digest must be sha256")
    _require(contract["canonicalization"] == "json-sort-keys-compact-utf8-v1", "unexpected evidence canonicalization")
    _require(contract["binding_model"] == "semantic-adapter-plus-envelope-plus-sealed-artifact-set-v3",
             "unexpected evidence binding model")
    _safe_repo_file(root, contract["execution_envelope_contract"])
    _safe_repo_file(root, contract["publication_policy"])
    _safe_repo_file(root, IMPLEMENTATION_PATH.as_posix())
    _safe_repo_file(root, VERIFIER_PATH.as_posix())
    _safe_repo_file(root, ACTION_PATH.as_posix())

    _require(contract["authority_boundary"] == {
        "role": "evidence-acceptance-only",
        "consumes_execution_envelopes": True,
        "mutates_execution_envelopes": False,
        "grants_publication_authority": False,
        "grants_release_authority": False,
    }, "evidence authority boundary changed without schema review")
    _require(contract["acceptance"] == {
        "self_declared_pass_allowed": False,
        "stale_source_allowed": False,
        "cross_envelope_substitution_allowed": False,
        "cross_lane_substitution_allowed": False,
        "missing_artifact_allowed": False,
        "extra_artifact_claims_allowed": False,
        "symlink_artifact_allowed": False,
        "artifact_sha256_required": True,
        "artifact_set_sha256_required": True,
        "verifier_result_sha256_required": True,
        "verifier_implementation_identity_required": True,
        "semantic_verification_required": True,
        "sealed_upload_required": True,
    }, "evidence acceptance policy changed without schema review")
    artifact_policy = contract["artifact_policy"]
    _require(
        isinstance(artifact_policy, dict)
        and set(artifact_policy)
        == {
            "inventory",
            "control_files",
            "required_artifacts_are_contract_owned",
            "auxiliary_files_are_bound_not_claims",
            "admission_must_immediately_precede_upload",
            "reserved_control_basenames_forbidden_in_auxiliary",
            "stable_no_follow_hashing_required",
            "single_link_regular_files_required",
            "accepted_upload_uses_sealed_copy",
            "workflow_direct_accepted_upload_forbidden",
            "post_upload_readback_required",
        }
        and artifact_policy["inventory"]
        == "recursive-bind-all-retained-files-v1"
        and isinstance(artifact_policy["control_files"], list)
        and len(artifact_policy["control_files"]) == len(CONTROL_FILES)
        and set(artifact_policy["control_files"]) == CONTROL_FILES
        and artifact_policy["required_artifacts_are_contract_owned"] is True
        and artifact_policy["auxiliary_files_are_bound_not_claims"] is True
        and artifact_policy["admission_must_immediately_precede_upload"] is True
        and artifact_policy["reserved_control_basenames_forbidden_in_auxiliary"] is True
        and artifact_policy["stable_no_follow_hashing_required"] is True
        and artifact_policy["single_link_regular_files_required"] is True
        and artifact_policy["accepted_upload_uses_sealed_copy"] is True
        and artifact_policy["workflow_direct_accepted_upload_forbidden"] is True
        and artifact_policy["post_upload_readback_required"] is True,
        "evidence artifact policy changed without schema review",
    )
    _require(contract["privacy"] == {
        "physical_recording_publication": "explicit-approval-and-redaction-required",
        "private_evidence_default": True,
    }, "evidence privacy policy changed without schema review")

    envelope_contract = envelope_lib.load_contract(root)
    _require(envelope_contract["schema_version"] == contract["execution_envelope_schema_version"],
             "evidence binding is not aligned with execution-envelope schema")
    envelope_lanes = {lane["id"]: lane for lane in envelope_contract["lane"]}
    non_evidence = _string_list(contract["non_evidence_lanes"], "non_evidence_lanes")
    _require(all(lane in envelope_lanes for lane in non_evidence),
             "non-evidence lane references unknown execution lane")

    profiles = contract["profile"]
    _require(isinstance(profiles, list) and profiles, "evidence profile inventory is empty")
    seen_ids: set[str] = set()
    seen_lanes: set[str] = set()
    for profile in profiles:
        _require(isinstance(profile, dict), "evidence profile must be a table")
        required = {
            "id", "lane_id", "test_ids", "contract_ids", "verification_class",
            "verifier_id", "verifier_adapter", "primary_artifact", "accepted_results",
            "accepted_schema_versions", "required_json_values",
            "require_observation_identity", "publication_default", "artifact",
        }
        allowed = required | {"observation_policy", "observation_identity_fields"}
        _require(required.issubset(profile) and set(profile).issubset(allowed),
                 "evidence profile fields changed without schema review")
        profile_id = profile["id"]
        lane_id = profile["lane_id"]
        _require(isinstance(profile_id, str) and NAME.fullmatch(profile_id),
                 f"invalid evidence profile id: {profile_id!r}")
        _require(profile_id not in seen_ids, f"duplicate evidence profile: {profile_id}")
        _require(isinstance(lane_id, str) and lane_id in envelope_lanes,
                 f"evidence profile references unknown lane: {lane_id!r}")
        _require(lane_id not in seen_lanes, f"duplicate evidence lane: {lane_id}")
        seen_ids.add(profile_id)
        seen_lanes.add(lane_id)
        _require(isinstance(profile["verifier_id"], str) and NAME.fullmatch(profile["verifier_id"]),
                 f"invalid verifier id for {profile_id}")
        _require(
            profile["verifier_adapter"] == semantic_verifier.ADAPTER_IDS.get(lane_id),
            f"{profile_id} semantic verifier adapter is not reviewed for its lane",
        )
        _string_list(profile["test_ids"], f"{profile_id}.test_ids")
        _string_list(profile["contract_ids"], f"{profile_id}.contract_ids")
        _string_list(profile["accepted_results"], f"{profile_id}.accepted_results")
        schemas = profile["accepted_schema_versions"]
        _require(isinstance(schemas, list) and schemas
                 and all(isinstance(item, int) and not isinstance(item, bool) and item >= 1 for item in schemas)
                 and len(schemas) == len(set(schemas)),
                 f"{profile_id} has invalid accepted schema versions")
        _string_list(profile["required_json_values"], f"{profile_id}.required_json_values", allow_empty=True)
        _require(profile["publication_default"] == "private", f"{profile_id} has unsafe publication default")
        _require(isinstance(profile["require_observation_identity"], bool),
                 f"{profile_id} observation identity flag is invalid")
        if profile["require_observation_identity"]:
            policy = profile.get("observation_policy")
            _require(isinstance(policy, str), f"{profile_id} lacks observation policy")
            _safe_repo_file(root, policy)
            observation_fields = _string_list(
                profile.get("observation_identity_fields"),
                f"{profile_id}.observation_identity_fields",
            )
            _require(
                all(
                    re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", field)
                    is not None
                    for field in observation_fields
                ),
                f"{profile_id} has invalid observation identity fields",
            )
        else:
            _require(
                "observation_policy" not in profile
                and "observation_identity_fields" not in profile,
                f"{profile_id} declares unused observation identity configuration",
            )

        artifacts = profile["artifact"]
        _require(isinstance(artifacts, list) and artifacts, f"{profile_id} artifact inventory is empty")
        roles: set[str] = set()
        filenames: set[str] = set()
        for spec in artifacts:
            _require(isinstance(spec, dict) and set(spec) == {"role", "filename", "kind"},
                     f"{profile_id} artifact fields changed without schema review")
            role, filename, kind = spec["role"], spec["filename"], spec["kind"]
            _require(isinstance(role, str) and NAME.fullmatch(role), f"{profile_id} has invalid artifact role")
            _require(role not in roles, f"{profile_id} has duplicate artifact role: {role}")
            _require(isinstance(filename, str) and Path(filename).name == filename and filename,
                     f"{profile_id} has unsafe artifact filename")
            _require(filename not in filenames, f"{profile_id} has duplicate artifact filename")
            _require(kind in ALLOWED_ARTIFACT_KINDS, f"{profile_id} has unsupported artifact kind")
            roles.add(role)
            filenames.add(filename)
        _require(profile["primary_artifact"] in roles, f"{profile_id} primary artifact is not declared")
        primary = next(item for item in artifacts if item["role"] == profile["primary_artifact"])
        _require(primary["kind"] == "json-result", f"{profile_id} primary artifact must be a JSON result")

    non_evidence_set = set(non_evidence)
    _require(non_evidence_set.isdisjoint(seen_lanes), "a lane cannot be both evidence-bearing and non-evidence")
    _require(non_evidence_set | seen_lanes == set(envelope_lanes),
             "every execution-envelope lane must be explicitly classified")
    return contract


def profile_for_lane(contract: dict, lane_id: str) -> dict:
    for profile in contract["profile"]:
        if profile["lane_id"] == lane_id:
            return profile
    raise EvidenceError(f"lane is not evidence-bearing: {lane_id}")


def _artifact_inventory(profile: dict, bundle: Path) -> list[dict]:
    _require(
        bundle.is_dir() and not bundle.is_symlink(),
        "evidence bundle is missing or unsafe",
    )
    required = {spec["filename"]: spec for spec in profile["artifact"]}
    for filename, spec in required.items():
        _bundle_file(bundle, filename, f"artifact {spec['role']}")

    inventory: list[dict] = []
    seen_required: set[str] = set()
    entries = sorted(
        bundle.rglob("*"),
        key=lambda path: path.relative_to(bundle).as_posix(),
    )
    for path in entries:
        relative = path.relative_to(bundle).as_posix()
        _require(not path.is_symlink(), f"retained path is a symlink: {relative}")
        if path.is_dir():
            continue
        _require(path.is_file(), f"retained path is not a regular file: {relative}")
        _require(
            path.stat(follow_symlinks=False).st_nlink == 1,
            f"retained evidence file must have a single link: {relative}",
        )
        if relative in CONTROL_FILES:
            continue
        _require(
            path.name not in CONTROL_FILES,
            f"reserved control filename outside bundle root: {relative}",
        )

        spec = required.get(relative) if "/" not in relative else None
        if spec is not None:
            role = spec["role"]
            kind = spec["kind"]
            required_artifact = True
            seen_required.add(relative)
        else:
            role = "retained-auxiliary"
            kind = "file"
            required_artifact = False
        inventory.append({
            "role": role,
            "path": relative,
            "kind": kind,
            "required": required_artifact,
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
        })

    _require(
        seen_required == set(required),
        "required artifact inventory changed during evidence admission",
    )
    _require(inventory, "retained artifact inventory is empty")
    return inventory


def _artifact_set_sha256(inventory: list[dict]) -> str:
    return hashlib.sha256(_canonical(inventory)).hexdigest()


def _lookup_json(payload: object, dotted: str) -> object:
    current = payload
    for part in dotted.split("."):
        _require(isinstance(current, dict) and part in current, f"required JSON value is missing: {dotted}")
        current = current[part]
    return current


def _parse_claim_value(text: str) -> object:
    if text == "true":
        return True
    if text == "false":
        return False
    if re.fullmatch(r"-?[0-9]+", text):
        return int(text)
    return text


def _verify_primary_result(contract: dict, profile: dict, bundle: Path, envelope: dict) -> dict:
    primary_spec = next(item for item in profile["artifact"] if item["role"] == profile["primary_artifact"])
    path = _bundle_file(bundle, primary_spec["filename"], "primary result")
    try:
        payload = json.loads(_read_text_file(path))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid primary result: {exc}") from exc
    _require(isinstance(payload, dict), "primary result must be an object")
    _require(payload.get("schema_version") in profile["accepted_schema_versions"], "primary result schema is not approved")
    _require(payload.get("source_sha") == envelope["source"]["commit_sha"], "primary result source SHA mismatch")
    _require(payload.get("result") in profile["accepted_results"], "primary result is not an accepted pass")
    if "repository" in payload:
        _require(payload["repository"] == contract["repository"], "primary result repository mismatch")
    for claim in profile["required_json_values"]:
        key, separator, expected = claim.partition("=")
        _require(separator == "=" and key and expected, f"invalid reviewed JSON claim: {claim!r}")
        _require(_lookup_json(payload, key) == _parse_claim_value(expected),
                 f"primary result reviewed claim mismatch: {key}")
    return payload


def _observation_identity(root: Path, profile: dict, primary: dict) -> dict:
    policy_path = profile["observation_policy"]
    policy = _safe_repo_file(root, policy_path)
    return {
        "policy": {"path": policy_path, "sha256": _sha256_file(policy)},
        "fields": {
            field: _lookup_json(primary, field)
            for field in profile["observation_identity_fields"]
        },
    }



def _semantic_outcome(
    root: Path,
    profile: dict,
    bundle: Path,
    primary: dict,
    envelope: dict,
) -> dict:
    try:
        outcome = semantic_verifier.verify_retained_evidence(
            root=root,
            lane_id=profile["lane_id"],
            bundle=bundle,
            primary=primary,
            envelope=envelope,
        )
    except semantic_verifier.VerificationError as exc:
        raise EvidenceError(f"semantic evidence verification failed: {exc}") from exc
    expected = {
        "adapter", "result", "independent", "environment_verified",
        "verified_claims", "test_ids", "contract_ids", "details",
    }
    _require(
        isinstance(outcome, dict) and set(outcome) == expected,
        "semantic verifier outcome fields do not match schema",
    )
    _require(
        outcome["adapter"] == profile["verifier_adapter"],
        "semantic verifier adapter identity mismatch",
    )
    _require(
        outcome["result"] == "passed"
        and outcome["independent"] is True
        and outcome["environment_verified"] is True,
        "semantic verifier did not independently establish a pass",
    )
    _require(
        outcome["test_ids"] == sorted(profile["test_ids"]),
        "semantic verifier test-id conclusion mismatch",
    )
    _require(
        outcome["contract_ids"] == sorted(profile["contract_ids"]),
        "semantic verifier contract-id conclusion mismatch",
    )
    _require(
        isinstance(outcome["verified_claims"], list)
        and outcome["verified_claims"]
        and outcome["verified_claims"] == sorted(set(outcome["verified_claims"]))
        and all(isinstance(item, str) and item for item in outcome["verified_claims"]),
        "semantic verifier claim inventory is invalid",
    )
    _require(isinstance(outcome["details"], dict), "semantic verifier details are invalid")
    return outcome


def _verification_record(
    root: Path,
    profile: dict,
    primary: dict,
    primary_sha256: str,
    outcome: dict,
) -> dict:
    result = {
        "class": profile["verification_class"],
        "adapter": outcome["adapter"],
        "primary_artifact": profile["primary_artifact"],
        "primary_artifact_sha256": primary_sha256,
        "primary_schema_version": primary["schema_version"],
        "environment_verified": outcome["environment_verified"],
        "independent": outcome["independent"],
        "verified_claims": outcome["verified_claims"],
        "details": outcome["details"],
    }
    if profile["require_observation_identity"]:
        result["observation_identity"] = _observation_identity(root, profile, primary)
    return result


def _verifier_provenance(root: Path, contract: dict, profile: dict) -> dict:
    implementation = _safe_repo_file(root, IMPLEMENTATION_PATH.as_posix())
    verifier = _safe_repo_file(root, VERIFIER_PATH.as_posix())
    contract_path = _safe_repo_file(root, CONTRACT_PATH.as_posix())
    result = {
        "id": profile["verifier_id"],
        "adapter": profile["verifier_adapter"],
        "semantic_verifier": {
            "path": VERIFIER_PATH.as_posix(),
            "sha256": _sha256_file(verifier),
        },
        "binder": {
            "path": IMPLEMENTATION_PATH.as_posix(),
            "sha256": _sha256_file(implementation),
        },
        "contract_sha256": _sha256_file(contract_path),
        "admission_action": ACTION_PATH.as_posix(),
        "admission_action_sha256": _sha256_file(
            _safe_repo_file(root, ACTION_PATH.as_posix())
        ),
    }
    if profile["require_observation_identity"]:
        policy = _safe_repo_file(root, profile["observation_policy"])
        result["observation_policy"] = {
            "path": profile["observation_policy"],
            "sha256": _sha256_file(policy),
        }
    return result


def attest(*, root: Path, lane_id: str, bundle: Path, output: Path) -> dict:
    contract = load_contract(root)
    profile = profile_for_lane(contract, lane_id)
    envelope_path = _bundle_file(
        bundle, "qualification-execution-envelope.json", "execution envelope"
    )
    envelope = envelope_lib.verify_envelope(root, envelope_path)
    _require(envelope["lane"]["id"] == lane_id, "cross-lane execution envelope substitution")
    inventory = _artifact_inventory(profile, bundle)
    primary = _verify_primary_result(contract, profile, bundle, envelope)
    outcome = _semantic_outcome(root, profile, bundle, primary, envelope)
    artifact_set = _artifact_set_sha256(inventory)
    primary_sha256 = next(
        item["sha256"] for item in inventory
        if item["role"] == profile["primary_artifact"] and item["required"] is True
    )
    body = {
        "schema_version": 3,
        "result": outcome["result"],
        "independent": outcome["independent"],
        "source_sha": envelope["source"]["commit_sha"],
        "source_tree_sha": envelope["source"]["tree_sha"],
        "lane_id": lane_id,
        "execution_envelope_sha256": envelope["envelope_sha256"],
        "artifact_set_sha256": artifact_set,
        "test_ids": outcome["test_ids"],
        "contract_ids": outcome["contract_ids"],
        "verifier": _verifier_provenance(root, contract, profile),
        "verification": _verification_record(
            root, profile, primary, primary_sha256, outcome
        ),
    }
    body["verifier_result_sha256"] = hashlib.sha256(_canonical(body)).hexdigest()
    _write_json_with_checksum(output, body, "verifier_result_sha256")
    return body


def _load_verifier_result(
    root: Path,
    path: Path,
    *,
    contract: dict,
    profile: dict,
    envelope: dict,
    artifact_set: str,
    semantic: bool,
) -> tuple[dict, str]:
    _require(path.is_file() and not path.is_symlink(), "verifier result is missing or unsafe")
    try:
        result = json.loads(_read_text_file(path))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid verifier result: {exc}") from exc
    expected = {
        "schema_version", "result", "independent", "source_sha", "source_tree_sha",
        "lane_id", "execution_envelope_sha256", "artifact_set_sha256",
        "test_ids", "contract_ids", "verifier", "verification",
        "verifier_result_sha256",
    }
    _require(isinstance(result, dict) and set(result) == expected, "verifier result fields do not match schema")
    digest = result.get("verifier_result_sha256")
    _require(isinstance(digest, str) and HEX64.fullmatch(digest), "verifier result digest is invalid")
    body = dict(result)
    body.pop("verifier_result_sha256")
    _require(hashlib.sha256(_canonical(body)).hexdigest() == digest, "verifier result canonical digest mismatch")
    _verify_checksum(path, digest)
    _require(
        result["schema_version"] == 3
        and result["result"] == "passed"
        and result["independent"] is True,
        "verifier did not independently pass",
    )
    _require(
        result["source_sha"] == envelope["source"]["commit_sha"]
        and result["source_tree_sha"] == envelope["source"]["tree_sha"],
        "verifier source/tree mismatch",
    )
    _require(result["lane_id"] == envelope["lane"]["id"], "verifier lane mismatch")
    _require(result["execution_envelope_sha256"] == envelope["envelope_sha256"], "verifier execution-envelope mismatch")
    _require(result["artifact_set_sha256"] == artifact_set, "verifier artifact-set mismatch")
    _require(result["test_ids"] == sorted(profile["test_ids"]), "verifier test-id binding mismatch")
    _require(result["contract_ids"] == sorted(profile["contract_ids"]), "verifier contract-id binding mismatch")
    _require(result["verifier"] == _verifier_provenance(root, contract, profile), "verifier implementation provenance mismatch")

    current_inventory = _artifact_inventory(profile, path.parent)
    primary_entry = next(
        item for item in current_inventory
        if item["role"] == profile["primary_artifact"] and item["required"] is True
    )
    primary_payload = _verify_primary_result(contract, profile, path.parent, envelope)
    verification = result["verification"]
    if semantic:
        outcome = _semantic_outcome(
            root, profile, path.parent, primary_payload, envelope
        )
        _require(
            result["result"] == outcome["result"]
            and result["independent"] == outcome["independent"]
            and result["test_ids"] == outcome["test_ids"]
            and result["contract_ids"] == outcome["contract_ids"],
            "serialized verifier conclusion disagrees with semantic re-verification",
        )
        expected_verification = _verification_record(
            root, profile, primary_payload, primary_entry["sha256"], outcome
        )
        _require(
            verification == expected_verification,
            "verifier verification metadata mismatch",
        )
    else:
        _require(
            isinstance(verification, dict)
            and verification.get("adapter") == profile["verifier_adapter"]
            and verification.get("environment_verified") is True
            and verification.get("independent") is True
            and isinstance(verification.get("verified_claims"), list)
            and bool(verification["verified_claims"]),
            "serialized semantic verifier conclusion is malformed",
        )
    return result, digest

def bind(*, root: Path, lane_id: str, bundle: Path, verifier_path: Path, output: Path) -> dict:
    contract = load_contract(root)
    profile = profile_for_lane(contract, lane_id)
    envelope_path = _bundle_file(bundle, "qualification-execution-envelope.json", "execution envelope")
    envelope = envelope_lib.verify_envelope(root, envelope_path)
    _require(envelope["lane"]["id"] == lane_id, "cross-lane execution envelope substitution")
    inventory = _artifact_inventory(profile, bundle)
    _verify_primary_result(contract, profile, bundle, envelope)
    artifact_set = _artifact_set_sha256(inventory)
    verifier, verifier_digest = _load_verifier_result(
        root,
        verifier_path,
        contract=contract,
        profile=profile,
        envelope=envelope,
        artifact_set=artifact_set,
        semantic=True,
    )
    body = {
        "schema_version": 3,
        "binding_contract": {"id": contract["id"], "sha256": _sha256_file(_safe_repo_file(root, CONTRACT_PATH.as_posix()))},
        "profile": {
            "id": profile["id"], "lane_id": lane_id,
            "verification_class": profile["verification_class"],
            "publication_default": profile["publication_default"],
        },
        "source": dict(envelope["source"]),
        "execution_envelope": {
            "filename": envelope_path.name, "sha256": envelope["envelope_sha256"],
            "profile_version": envelope["lane"]["profile_version"],
        },
        "artifact_set_sha256": artifact_set,
        "test_ids": sorted(profile["test_ids"]),
        "contract_ids": sorted(profile["contract_ids"]),
        "artifacts": inventory,
        "verifier_result": {
            "filename": verifier_path.name, "sha256": verifier_digest,
            "verifier_id": verifier["verifier"]["id"],
            "semantic_verifier_sha256": verifier["verifier"]["semantic_verifier"]["sha256"],
            "binder_sha256": verifier["verifier"]["binder"]["sha256"],
            "independent": verifier["independent"],
        },
        "privacy": {
            "publication_default": profile["publication_default"],
            "physical_recording_publication": contract["privacy"]["physical_recording_publication"],
        },
    }
    body["binding_sha256"] = hashlib.sha256(_canonical(body)).hexdigest()
    _write_json_with_checksum(output, body, "binding_sha256")
    return body


def verify_binding(root: Path, path: Path, *, semantic: bool = True) -> dict:
    _require(path.is_file() and not path.is_symlink(), "evidence binding is missing or unsafe")
    try:
        binding = json.loads(_read_text_file(path))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid evidence binding: {exc}") from exc
    expected = {
        "schema_version", "binding_contract", "profile", "source",
        "execution_envelope", "artifact_set_sha256", "test_ids",
        "contract_ids", "artifacts", "verifier_result", "privacy",
        "binding_sha256",
    }
    _require(isinstance(binding, dict) and set(binding) == expected, "evidence binding fields do not match schema")
    digest = binding.get("binding_sha256")
    _require(binding["schema_version"] == 3 and isinstance(digest, str) and HEX64.fullmatch(digest),
             "evidence binding schema or digest is invalid")
    body = dict(binding)
    body.pop("binding_sha256")
    _require(hashlib.sha256(_canonical(body)).hexdigest() == digest, "evidence binding canonical digest mismatch")
    _verify_checksum(path, digest)

    contract = load_contract(root)
    _require(binding["binding_contract"] == {
        "id": contract["id"], "sha256": _sha256_file(_safe_repo_file(root, CONTRACT_PATH.as_posix()))
    }, "evidence binding contract mismatch")
    profile_info = binding["profile"]
    _require(isinstance(profile_info, dict) and set(profile_info)
             == {"id", "lane_id", "verification_class", "publication_default"},
             "evidence profile binding is malformed")
    profile = profile_for_lane(contract, profile_info["lane_id"])
    _require(profile_info == {
        "id": profile["id"], "lane_id": profile["lane_id"],
        "verification_class": profile["verification_class"],
        "publication_default": profile["publication_default"],
    }, "evidence profile mismatch")
    bundle = path.parent
    envelope_info = binding["execution_envelope"]
    _require(isinstance(envelope_info, dict) and set(envelope_info) == {"filename", "sha256", "profile_version"},
             "execution envelope binding is malformed")
    envelope_path = _bundle_file(bundle, envelope_info["filename"], "execution envelope")
    envelope = envelope_lib.verify_envelope(root, envelope_path, source_sha=binding["source"].get("commit_sha"))
    _require(envelope["lane"]["id"] == profile["lane_id"], "cross-lane envelope substitution")
    _require(binding["source"] == envelope["source"], "evidence source/tree mismatch")
    _require(envelope_info["sha256"] == envelope["envelope_sha256"]
             and envelope_info["profile_version"] == envelope["lane"]["profile_version"],
             "execution envelope identity mismatch")
    inventory = _artifact_inventory(profile, bundle)
    _verify_primary_result(contract, profile, bundle, envelope)
    artifact_set = _artifact_set_sha256(inventory)
    _require(binding["artifacts"] == inventory, "bound artifact inventory mismatch")
    _require(binding["artifact_set_sha256"] == artifact_set, "bound artifact-set digest mismatch")
    _require(binding["test_ids"] == sorted(profile["test_ids"]),
             "bound test-id inventory mismatch")
    _require(binding["contract_ids"] == sorted(profile["contract_ids"]),
             "bound contract-id inventory mismatch")
    verifier_info = binding["verifier_result"]
    _require(isinstance(verifier_info, dict) and set(verifier_info)
             == {"filename", "sha256", "verifier_id", "semantic_verifier_sha256", "binder_sha256", "independent"},
             "verifier binding is malformed")
    verifier_path = _bundle_file(bundle, verifier_info["filename"], "verifier result")
    verifier, verifier_digest = _load_verifier_result(
        root,
        verifier_path,
        contract=contract,
        profile=profile,
        envelope=envelope,
        artifact_set=artifact_set,
        semantic=semantic,
    )
    _require(verifier_info == {
        "filename": verifier_path.name,
        "sha256": verifier_digest,
        "verifier_id": verifier["verifier"]["id"],
        "semantic_verifier_sha256": verifier["verifier"]["semantic_verifier"]["sha256"],
        "binder_sha256": verifier["verifier"]["binder"]["sha256"],
        "independent": verifier["independent"],
    }, "verifier result binding mismatch")
    _require(binding["privacy"] == {
        "publication_default": profile["publication_default"],
        "physical_recording_publication": contract["privacy"]["physical_recording_publication"],
    }, "evidence privacy binding mismatch")
    return binding



def _sealed_member_bytes(bundle: Path) -> list[tuple[str, bytes]]:
    _require(bundle.is_dir() and not bundle.is_symlink(), "evidence bundle is missing or unsafe")
    members: list[tuple[str, bytes]] = []
    for path in sorted(bundle.rglob("*"), key=lambda item: item.relative_to(bundle).as_posix()):
        relative = path.relative_to(bundle).as_posix()
        _require(not path.is_symlink(), f"sealed evidence path is a symlink: {relative}")
        if path.is_dir():
            continue
        _require(path.is_file(), f"sealed evidence path is not regular: {relative}")
        _require(path.stat(follow_symlinks=False).st_nlink == 1, f"sealed evidence file must have one link: {relative}")
        members.append((relative, _read_bytes_file(path)))
    _require(members, "sealed evidence bundle is empty")
    return members


def verify_sealed_archive(
    root: Path,
    archive_path: Path,
    *,
    semantic: bool = False,
) -> tuple[str, str]:
    archive_bytes = _read_bytes_file(archive_path)
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    with tempfile.TemporaryDirectory(prefix="linura-evidence-unseal-") as temporary:
        destination = Path(temporary)
        seen: set[str] = set()
        try:
            archive = tarfile.open(
                fileobj=io.BytesIO(archive_bytes), mode="r:", format=tarfile.PAX_FORMAT
            )
        except tarfile.TarError as exc:
            raise EvidenceError(f"sealed evidence archive is invalid: {exc}") from exc
        with archive:
            for member in archive.getmembers():
                name = member.name
                _require(
                    name
                    and not name.startswith("/")
                    and ".." not in Path(name).parts
                    and name not in seen,
                    f"unsafe or duplicate sealed evidence member: {name!r}",
                )
                _require(member.isfile(), f"sealed evidence member is not a regular file: {name}")
                _require(
                    member.uid == 0
                    and member.gid == 0
                    and member.uname == ""
                    and member.gname == ""
                    and member.mtime == 0
                    and member.mode == 0o444,
                    f"sealed evidence member metadata is not canonical: {name}",
                )
                seen.add(name)
                extracted = destination / name
                extracted.parent.mkdir(parents=True, exist_ok=True)
                _require(extracted.resolve().is_relative_to(destination.resolve()), "sealed member escapes destination")
                stream = archive.extractfile(member)
                _require(stream is not None, f"cannot read sealed evidence member: {name}")
                data = stream.read()
                _require(len(data) == member.size, f"sealed evidence member size mismatch: {name}")
                descriptor = os.open(
                    extracted,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o400,
                )
                try:
                    offset = 0
                    while offset < len(data):
                        offset += os.write(descriptor, data[offset:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.chmod(extracted, 0o444)
        binding_path = destination / "evidence-binding.json"
        _require(binding_path.is_file(), "sealed evidence lacks evidence-binding.json")
        binding = verify_binding(root, binding_path, semantic=semantic)
        return archive_sha256, binding["binding_sha256"]


def seal_bundle(
    root: Path,
    bundle: Path,
    binding_path: Path,
    destination: Path,
) -> tuple[str, str]:
    _require(
        binding_path.resolve().parent == bundle.resolve(),
        "binding must be inside the bundle being sealed",
    )
    verified = verify_binding(root, binding_path, semantic=True)
    _require(not destination.exists() and not destination.is_symlink(), "sealed archive destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _require(
        not destination.resolve().is_relative_to(bundle.resolve()),
        "sealed archive must be outside the mutable evidence bundle",
    )

    members = _sealed_member_bytes(bundle)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for relative, data in members:
                info = tarfile.TarInfo(relative)
                info.size = len(data)
                info.mode = 0o444
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
        os.chmod(temporary, 0o444)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    archive_sha256, binding_sha256 = verify_sealed_archive(
        root, destination, semantic=False
    )
    _require(
        binding_sha256 == verified["binding_sha256"],
        "sealed archive changed evidence-binding identity",
    )
    return archive_sha256, binding_sha256


def unseal_archive(
    root: Path,
    archive_path: Path,
    destination: Path,
    *,
    semantic: bool = False,
) -> tuple[str, str]:
    _require(not destination.exists() and not destination.is_symlink(), "unseal destination already exists")
    archive_bytes = _read_bytes_file(archive_path)
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    destination.mkdir(parents=True, mode=0o700)
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            for member in archive.getmembers():
                name = member.name
                _require(
                    name
                    and not name.startswith("/")
                    and ".." not in Path(name).parts
                    and name not in seen
                    and member.isfile(),
                    f"unsafe sealed evidence member: {name!r}",
                )
                _require(
                    member.uid == 0
                    and member.gid == 0
                    and member.uname == ""
                    and member.gname == ""
                    and member.mtime == 0
                    and member.mode == 0o444,
                    f"sealed evidence member metadata is not canonical: {name}",
                )
                seen.add(name)
                output = destination / name
                output.parent.mkdir(parents=True, exist_ok=True)
                _require(output.resolve().is_relative_to(destination.resolve()), "sealed member escapes destination")
                stream = archive.extractfile(member)
                _require(stream is not None, f"cannot read sealed evidence member: {name}")
                data = stream.read()
                _require(len(data) == member.size, f"sealed evidence member size mismatch: {name}")
                descriptor = os.open(
                    output,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o400,
                )
                try:
                    offset = 0
                    while offset < len(data):
                        offset += os.write(descriptor, data[offset:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.chmod(output, 0o444)
        binding = verify_binding(
            root, destination / "evidence-binding.json", semantic=semantic
        )
        return archive_sha256, binding["binding_sha256"]
    except Exception:
        for path in sorted(destination.rglob("*"), reverse=True):
            try:
                if path.is_file():
                    os.chmod(path, 0o600)
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            except OSError:
                pass
        try:
            destination.rmdir()
        except OSError:
            pass
        raise


def _composite_action_step_blocks(source: str) -> list[tuple[int, str]]:
    """Return only concrete steps from a repository-owned composite action."""
    lines = source.splitlines()
    try:
        runs_index = next(
            index for index, line in enumerate(lines) if line == "runs:"
        )
    except StopIteration:
        return []
    steps_index: int | None = None
    for index in range(runs_index + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            break
        if line == "  steps:":
            steps_index = index
            break
    if steps_index is None:
        return []

    blocks: list[tuple[int, str]] = []
    index = steps_index + 1
    while index < len(lines):
        line = lines[index]
        if line.strip() and not line.startswith(" "):
            break
        if line.strip() and len(line) - len(line.lstrip()) <= 2:
            break
        if re.match(r"^    -\s+\S", line) is None:
            index += 1
            continue
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.strip() and not candidate.startswith(" "):
                break
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= 2:
                break
            if re.match(r"^    -\s+\S", candidate) is not None:
                break
            end += 1
        blocks.append((index + 1, "\n".join(lines[index:end])))
        index = end
    return blocks


def _admission_action_has_sealed_upload(source: str) -> bool:
    steps = _composite_action_step_blocks(source)
    if not steps:
        return False

    by_id: dict[str, tuple[int, str]] = {}
    uploads: list[tuple[int, str]] = []
    downloads: list[tuple[int, str]] = []
    for start, block in steps:
        step_id = envelope_lib.workflow_step_direct_value(block, "id")
        if step_id:
            if step_id in by_id:
                return False
            by_id[step_id] = (start, block)
        if envelope_lib.workflow_step_uses_prefix(block, "actions/upload-artifact@"):
            uploads.append((start, block))
        if envelope_lib.workflow_step_uses_prefix(block, "actions/download-artifact@"):
            downloads.append((start, block))

    required = (
        "attest",
        "bind",
        "verify",
        "seal",
        "upload",
        "readback-1",
        "readback-retry-1",
        "readback-2",
        "readback-retry-2",
        "readback-3",
        "verify-upload",
    )
    if (
        any(step_id not in by_id for step_id in required)
        or len(uploads) != 1
        or len(downloads) != 3
    ):
        return False

    step_index = {start: index for index, (start, _) in enumerate(steps)}
    sealed_chain = [
        by_id["seal"][0],
        by_id["upload"][0],
        by_id["readback-1"][0],
        by_id["readback-retry-1"][0],
        by_id["readback-2"][0],
        by_id["readback-retry-2"][0],
        by_id["readback-3"][0],
        by_id["verify-upload"][0],
    ]
    try:
        sealed_chain_indexes = [step_index[start] for start in sealed_chain]
    except KeyError:
        return False
    if sealed_chain_indexes != list(
        range(
            sealed_chain_indexes[0],
            sealed_chain_indexes[0] + len(sealed_chain_indexes),
        )
    ):
        return False

    ordered = [
        by_id["attest"][0],
        by_id["bind"][0],
        by_id["verify"][0],
        *sealed_chain,
    ]
    if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
        return False

    attest = by_id["attest"][1]
    bind = by_id["bind"][1]
    verify = by_id["verify"][1]
    seal = by_id["seal"][1]
    upload = by_id["upload"][1]
    if uploads[0][0] != by_id["upload"][0]:
        return False
    readback_1 = by_id["readback-1"][1]
    retry_1 = by_id["readback-retry-1"][1]
    readback_2 = by_id["readback-2"][1]
    retry_2 = by_id["readback-retry-2"][1]
    readback_3 = by_id["readback-3"][1]
    verify_upload = by_id["verify-upload"][1]

    # Authority-bearing steps keep normal success semantics. The bounded
    # readback retries are storage-observation retries only; they can never
    # mutate the sealed upload or turn a failed digest comparison into a pass.
    for block in (attest, bind, verify, seal, upload, verify_upload):
        if (
            envelope_lib.workflow_step_direct_value(block, "if") is not None
            or envelope_lib.workflow_step_direct_value(
                block, "continue-on-error"
            )
            is not None
        ):
            return False

    if "qualification_evidence.py attest" not in attest:
        return False
    if "qualification_evidence.py bind" not in bind:
        return False
    if "qualification_evidence.py verify" not in verify:
        return False
    if "qualification_evidence.py seal" not in seal:
        return False
    for block in (attest, bind, verify, seal):
        if 'LINURA_EVIDENCE_ROOT: ${{ inputs.artifact-root }}' not in block:
            return False
    if '--bundle "$LINURA_EVIDENCE_ROOT"' not in seal:
        return False
    if '--binding "$LINURA_EVIDENCE_ROOT/evidence-binding.json"' not in seal:
        return False
    if (
        envelope_lib.workflow_step_input_value(upload, "path")
        != "${{ steps.seal.outputs.archive }}"
        or envelope_lib.workflow_step_input_value(upload, "name")
        != "${{ inputs.artifact-name }}"
        or envelope_lib.workflow_step_input_value(upload, "if-no-files-found")
        != "error"
    ):
        return False

    readbacks = (readback_1, readback_2, readback_3)
    if any(
        envelope_lib.workflow_step_input_value(block, "artifact-ids")
        != "${{ steps.upload.outputs.artifact-id }}"
        or envelope_lib.workflow_step_input_value(block, "name") is not None
        or envelope_lib.workflow_step_input_value(block, "repository") is not None
        or envelope_lib.workflow_step_input_value(block, "run-id") is not None
        or envelope_lib.workflow_step_input_value(block, "github-token") is not None
        or envelope_lib.workflow_step_input_value(block, "path")
        != "${{ runner.temp }}/qualification-evidence-readback"
        for block in readbacks
    ):
        return False

    first_condition = envelope_lib.workflow_step_direct_value(
        readback_1, "if"
    )
    second_condition = envelope_lib.workflow_step_direct_value(
        readback_2, "if"
    )
    third_condition = envelope_lib.workflow_step_direct_value(
        readback_3, "if"
    )
    retry_1_condition = envelope_lib.workflow_step_direct_value(retry_1, "if")
    retry_2_condition = envelope_lib.workflow_step_direct_value(retry_2, "if")
    expected_retry_1 = "${{ steps.readback-1.outcome != 'success' }}"
    expected_retry_2 = (
        "${{ steps.readback-1.outcome != 'success' && "
        "steps.readback-2.outcome != 'success' }}"
    )
    if (
        first_condition is not None
        or envelope_lib.workflow_step_direct_value(
            readback_1, "continue-on-error"
        )
        != "true"
        or second_condition != expected_retry_1
        or envelope_lib.workflow_step_direct_value(
            readback_2, "continue-on-error"
        )
        != "true"
        or third_condition != expected_retry_2
        or envelope_lib.workflow_step_direct_value(
            readback_3, "continue-on-error"
        )
        is not None
        or retry_1_condition != expected_retry_1
        or retry_2_condition != expected_retry_2
    ):
        return False

    if not (
        'rm -rf "$RUNNER_TEMP/qualification-evidence-readback"' in retry_1
        and "sleep 2" in retry_1
        and 'rm -rf "$RUNNER_TEMP/qualification-evidence-readback"' in retry_2
        and "sleep 4" in retry_2
    ):
        return False

    return (
        'sealed="$RUNNER_TEMP/qualification-evidence.tar"' in seal
        and 'test "$archive_sha" = "$actual_archive_sha"' in seal
        and "printf 'archive=%s\\n' \"$sealed\" >> \"$GITHUB_OUTPUT\""
        in seal
        and "LINURA_EXPECTED_ARCHIVE_SHA256: "
        "${{ steps.seal.outputs.archive-sha256 }}" in verify_upload
        and 'readback="$RUNNER_TEMP/qualification-evidence-readback/'
        'qualification-evidence.tar"' in verify_upload
        and 'test "$actual" = "$LINURA_EXPECTED_ARCHIVE_SHA256"'
        in verify_upload
        and "printf 'archive-sha256=%s\\n' \"$actual\" >> "
        '\"$GITHUB_OUTPUT\"' in verify_upload
    )


def _workflow_job_at(source: str, start_line: int) -> str | None:
    lines = source.splitlines()
    for line in reversed(lines[: max(0, start_line - 1)]):
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if match is not None:
            return match.group(1)
    return None



def _ordered_evidence_admission(source: str, expected_lane: str) -> bool:
    evidence_steps = [
        (start, block)
        for start, block in envelope_lib.workflow_action_steps(
            source, "./.github/actions/qualification-evidence"
        )
        if envelope_lib.workflow_step_has_value(block, "lane", expected_lane)
    ]
    if len(evidence_steps) != 1:
        return False
    evidence_start, evidence_block = evidence_steps[0]
    evidence_job = _workflow_job_at(source, evidence_start)
    if evidence_job is None:
        return False

    if envelope_lib.workflow_step_direct_value(evidence_block, "if") is not None:
        return False

    artifact_root = envelope_lib.workflow_step_input_value(
        evidence_block, "artifact-root"
    )
    artifact_name = envelope_lib.workflow_step_input_value(
        evidence_block, "artifact-name"
    )
    if not artifact_root or not artifact_name:
        return False

    envelope_steps = [
        (start, block)
        for start, block in envelope_lib.workflow_action_steps(
            source, "./.github/actions/qualification-envelope"
        )
        if start < evidence_start
        and envelope_lib.workflow_step_has_value(block, "lane", expected_lane)
        and _workflow_job_at(source, start) == evidence_job
    ]
    if not envelope_steps:
        return False
    if any(
        envelope_lib.workflow_step_direct_value(block, "if") is not None
        for _, block in envelope_steps
    ):
        return False

    # The caller job may never upload accepted evidence directly, before or
    # after admission. Any workflow-level upload in this job is diagnostics
    # only: it must be failure-gated and explicitly unqualified in both the
    # step label and artifact name. Accepted bytes are uploaded solely by the
    # composite action from its sealed archive in this same job.
    for start, block in envelope_lib.workflow_step_blocks(source):
        if _workflow_job_at(source, start) != evidence_job:
            continue
        if not envelope_lib.workflow_step_uses_prefix(
            block, "actions/upload-artifact@"
        ):
            continue
        condition = envelope_lib.workflow_step_direct_value(block, "if") or ""
        step_name = envelope_lib.workflow_step_direct_value(block, "name") or ""
        artifact_name_value = (
            envelope_lib.workflow_step_input_value(block, "name") or ""
        )
        if (
            "failure()" not in condition
            or "unqualified" not in step_name.lower()
            or "unqualified" not in artifact_name_value.lower()
        ):
            return False
    return True

def _trusted_release_has_split_v010_source_roots(source: str) -> bool:
    """Require distinct exact-source roots for pre-seal and prepared v0.10 evidence."""
    required = (
        "V010_QUALIFICATION_SOURCE_ROOT: /tmp/linura-v010-qualification-source",
        "V010_PREPARED_SOURCE_ROOT: /tmp/linura-v010-prepared-source",
        'test "$QUALIFICATION_SOURCE_SHA" != "$SOURCE_SHA"',
        'worktree add --detach \\\n            "$V010_QUALIFICATION_SOURCE_ROOT" "$QUALIFICATION_SOURCE_SHA"',
        'worktree add --detach \\\n            "$V010_PREPARED_SOURCE_ROOT" "$SOURCE_SHA"',
        'git -C "$V010_QUALIFICATION_SOURCE_ROOT" rev-parse HEAD',
        'git -C "$V010_QUALIFICATION_SOURCE_ROOT" rev-parse \'HEAD^{tree}\'',
        '"$QUALIFICATION_TREE_SHA"',
        'git -C "$V010_PREPARED_SOURCE_ROOT" rev-parse HEAD',
        '"$V010_QUALIFICATION_SOURCE_ROOT/tools/qualification_evidence.py"',
        '--root "$V010_QUALIFICATION_SOURCE_ROOT" unseal',
        '--root "$V010_QUALIFICATION_SOURCE_ROOT" verify --structural-only',
        '"$V010_PREPARED_SOURCE_ROOT/tools/qualification_evidence.py"',
        '--root "$V010_PREPARED_SOURCE_ROOT" unseal',
        '--root "$V010_PREPARED_SOURCE_ROOT" verify --structural-only',
        'cd "$V010_PREPARED_SOURCE_ROOT"',
    )
    return (
        "V010_SOURCE_ROOT:" not in source
        and all(fragment in source for fragment in required)
    )


def validate_integrations(root: Path, contract: dict | None = None) -> None:
    contract = contract or load_contract(root)
    envelope_contract = envelope_lib.load_contract(root)
    lanes = {lane["id"]: lane for lane in envelope_contract["lane"]}
    action = _read_text_file(_safe_repo_file(root, ACTION_PATH.as_posix()))
    _require(
        _admission_action_has_sealed_upload(action),
        "evidence action must structurally attest -> bind -> reverify -> seal -> upload the exact sealed object",
    )
    _require(
        "value: ${{ steps.verify.outputs.sha256 }}" in action,
        "evidence action digest output is not reverify-bound",
    )
    _require(
        "artifact-root:" in action
        and "artifact-name:" in action,
        "evidence action public inputs are incomplete",
    )
    trusted_release = _read_text_file(_safe_repo_file(
        root, ".github/workflows/trusted-release-proof.yml"
    ))
    _require(
        _trusted_release_has_split_v010_source_roots(trusted_release),
        "trusted release must verify pre-seal and prepared v0.10 evidence against distinct exact-source roots",
    )
    for profile in contract["profile"]:
        lane_id = profile["lane_id"]
        lane = lanes[lane_id]
        target = lane.get("workflow")
        _require(isinstance(target, str), f"evidence-bearing lane lacks hosted workflow: {lane_id}")
        integration_target = target
        expected_lane = lane_id
        if lane_id == "control1-plan-preview-vm":
            integration_target = ".github/workflows/vm-acceptance.yml"
            expected_lane = "${{ inputs.envelope_lane || 'vm-acceptance' }}"
            wrapper = _read_text_file(_safe_repo_file(root, target))
            for trigger in TRIGGER_FILES:
                _require(trigger in wrapper, f"control1 evidence trigger missing: {trigger}")
        elif lane_id == "vm-acceptance":
            expected_lane = "${{ inputs.envelope_lane || 'vm-acceptance' }}"
        source = _read_text_file(_safe_repo_file(root, integration_target))
        _require(
            _ordered_evidence_admission(source, expected_lane),
            f"evidence admission ordering or lane binding drift: {lane_id}",
        )
        trigger_source = source
        if lane_id == "v010-shell-runtime":
            trigger_source = _read_text_file(_safe_repo_file(
                root, ".github/workflows/v010-qualification.yml"
            ))
        for trigger in TRIGGER_FILES:
            _require(
                trigger in trigger_source,
                f"evidence workflow trigger missing for {lane_id}: {trigger}",
            )


def _command_validate(args: argparse.Namespace) -> int:
    contract = load_contract(args.root)
    validate_integrations(args.root, contract)
    print(json.dumps({
        "ready": True, "schema_version": contract["schema_version"],
        "contract_id": contract["id"],
        "profiles": [profile["id"] for profile in contract["profile"]],
        "non_evidence_lanes": contract["non_evidence_lanes"],
    }, indent=2, sort_keys=True))
    return 0


def _command_attest(args: argparse.Namespace) -> int:
    result = attest(root=args.root, lane_id=args.lane, bundle=args.bundle, output=args.output)
    print(result["verifier_result_sha256"])
    return 0


def _command_bind(args: argparse.Namespace) -> int:
    result = bind(root=args.root, lane_id=args.lane, bundle=args.bundle,
                  verifier_path=args.verifier_result, output=args.output)
    print(result["binding_sha256"])
    return 0


def _command_verify(args: argparse.Namespace) -> int:
    result = verify_binding(
        args.root, args.binding, semantic=not args.structural_only
    )
    print(result["binding_sha256"])
    return 0


def _command_seal(args: argparse.Namespace) -> int:
    archive_sha256, binding_sha256 = seal_bundle(
        args.root, args.bundle, args.binding, args.destination
    )
    print(json.dumps({
        "archive_sha256": archive_sha256,
        "binding_sha256": binding_sha256,
        "archive": str(args.destination),
    }, sort_keys=True))
    return 0


def _command_unseal(args: argparse.Namespace) -> int:
    archive_sha256, binding_sha256 = unseal_archive(
        args.root,
        args.archive,
        args.destination,
        semantic=args.semantic,
    )
    print(json.dumps({
        "archive_sha256": archive_sha256,
        "binding_sha256": binding_sha256,
        "destination": str(args.destination),
    }, sort_keys=True))
    return 0


def _command_admit(args: argparse.Namespace) -> int:
    verifier = args.bundle / "verifier-result.json"
    binding = args.bundle / "evidence-binding.json"
    attest(root=args.root, lane_id=args.lane, bundle=args.bundle, output=verifier)
    result = bind(root=args.root, lane_id=args.lane, bundle=args.bundle,
                  verifier_path=verifier, output=binding)
    verified = verify_binding(args.root, binding)
    _require(verified["binding_sha256"] == result["binding_sha256"],
             "post-write evidence verification changed binding identity")
    print(result["binding_sha256"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.set_defaults(func=_command_validate)
    attest_parser = sub.add_parser("attest")
    attest_parser.add_argument("--lane", required=True)
    attest_parser.add_argument("--bundle", required=True, type=Path)
    attest_parser.add_argument("--output", required=True, type=Path)
    attest_parser.set_defaults(func=_command_attest)
    bind_parser = sub.add_parser("bind")
    bind_parser.add_argument("--lane", required=True)
    bind_parser.add_argument("--bundle", required=True, type=Path)
    bind_parser.add_argument("--verifier-result", required=True, type=Path)
    bind_parser.add_argument("--output", required=True, type=Path)
    bind_parser.set_defaults(func=_command_bind)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--binding", required=True, type=Path)
    verify_parser.add_argument("--structural-only", action="store_true")
    verify_parser.set_defaults(func=_command_verify)
    seal_parser = sub.add_parser("seal")
    seal_parser.add_argument("--bundle", required=True, type=Path)
    seal_parser.add_argument("--binding", required=True, type=Path)
    seal_parser.add_argument("--destination", required=True, type=Path)
    seal_parser.set_defaults(func=_command_seal)
    unseal_parser = sub.add_parser("unseal")
    unseal_parser.add_argument("--archive", required=True, type=Path)
    unseal_parser.add_argument("--destination", required=True, type=Path)
    unseal_parser.add_argument("--semantic", action="store_true")
    unseal_parser.set_defaults(func=_command_unseal)
    admit_parser = sub.add_parser("admit")
    admit_parser.add_argument("--lane", required=True)
    admit_parser.add_argument("--bundle", required=True, type=Path)
    admit_parser.set_defaults(func=_command_admit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (EvidenceError, envelope_lib.EnvelopeError) as exc:
        print(f"qualification evidence error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
