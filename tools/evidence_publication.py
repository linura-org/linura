#!/usr/bin/env python3
"""Fail-closed, append-only R2 qualification evidence publication.

Do not run the publish command on PR-controlled runners. GitHub workflow provenance
and environment approval are checked *outside* of the downloaded evidence archive.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import subprocess
import sys
import tomllib
from urllib.parse import urlsplit
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/evidence-publication.toml"
MANIFEST = "V010-SHELL-RUNTIME-EVIDENCE.json"
SIDECAR = "V010-SHELL-RUNTIME-EVIDENCE.sha256"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class AdmissionError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AdmissionError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_json(content: str) -> Any:
    return json.loads(content, object_pairs_hook=unique_object)


def verify_video(video: Path) -> dict[str, Any]:
    try:
        proc = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
            "format=format_name,duration:stream=codec_type,codec_name,width,height", "-of", "json", str(video)],
            capture_output=True, text=True, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdmissionError("video probe unavailable or timed out") from exc
    require(proc.returncode == 0, "recording format probe failed")
    data = parse_json(proc.stdout)
    streams = data.get("streams", [])
    require(len(streams) == 1 and streams[0].get("codec_type") == "video" and streams[0].get("codec_name") == "ffv1", "video codec or stream contract mismatch")
    width, height = streams[0].get("width"), streams[0].get("height")
    require(type(width) is int and type(height) is int and 0 < width <= 16384 and 0 < height <= 16384, "invalid recording dimensions")
    require("matroska" in data.get("format", {}).get("format_name", "").split(","), "invalid recording container")
    duration = float(data.get("format", {}).get("duration", 0))
    require(0.25 <= duration <= 600.0, "recording duration outside bounds")
    return {"codec": "ffv1", "container": "matroska", "width": width, "height": height, "duration_seconds": duration}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def safe_file(root: Path, name: str, max_bytes: int) -> Path:
    require(isinstance(name, str) and FILE.fullmatch(name) is not None and name not in (".", ".."), "unsafe file name")
    path = root / name
    require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1, f"missing or unsafe evidence file: {name}")
    require(0 < path.stat().st_size <= max_bytes, f"evidence file size outside limit: {name}")
    return path


def load_policy(path: Path = CONTRACT) -> dict[str, Any]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    require(data["schema_version"] == 1 and data["id"] == "qualification/evidence-publication", "invalid publication policy")
    require(data["visibility"] == "private" and data["allow_overwrite"] is False, "unsafe publication policy")
    require(data["bucket"] == "linura-qualification-evidence" and data["environment"] == "qualification-archive",
            "publication destination or approval environment drift")
    require(0 < data["max_files"] <= 128 and 0 < data["max_total_bytes"] <= 1073741824,
            "publication resource bounds drift")
    require(data["require_main_source"] is True and data["require_approval"] is True and data["require_independent_qualification"] is True, "publication gates disabled")
    for name, days in (("baselines", 180), ("regressions", 90)):
        require(data["category"][name]["retention_days"] == days, "retention policy drift")
        require(data["category"][name]["transport"] == "github-actions", "transport policy drift")
    for name in ("physical", "interactive", "releases"):
        require(data["category"][name]["retention_days"] == 0, "restricted evidence must require separate retention approval")
    return data


def verified_bundle(directory: Path, source: str, run_id: int, attempt: int, policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    require(SHA.fullmatch(source) is not None, "source SHA is invalid")
    require(run_id > 0 and attempt > 0, "run ID/attempt invalid")
    require(directory.is_dir() and not directory.is_symlink(), "invalid artifact directory")
    maximum = policy["max_total_bytes"]
    manifest_file = safe_file(directory, MANIFEST, maximum)
    sidecar = safe_file(directory, SIDECAR, 256)
    require(sidecar.read_text(encoding="ascii") == f"{sha256(manifest_file)}  {MANIFEST}\n", "manifest checksum sidecar mismatch")
    manifest = parse_json(manifest_file.read_text(encoding="utf-8"))
    require(type(manifest) is dict and manifest.get("schema_version") == 1, "unknown evidence schema")
    require(manifest.get("repository") == "linura-org/linura", "repository mismatch")
    require(manifest.get("source_sha") == source, "evidence source mismatch")
    require(manifest.get("result") == "passed" and manifest.get("release_support_promotion") is False, "no independently passing candidate evidence")
    require(manifest.get("claim") == "development-runtime-evidence-only", "unexpected qualification claim")
    require(manifest.get("target_profile") == "arch-hyprland-v1", "profile mismatch")
    workflow = manifest.get("workflow")
    require(isinstance(workflow, dict) and workflow.get("run_id") == run_id and workflow.get("run_attempt") == attempt, "workflow provenance mismatch")
    require(workflow.get("path") == ".github/workflows/v010-shell-runtime-qualification.yml", "unexpected qualification workflow")
    require(workflow.get("event") == "workflow_dispatch", "evidence must come from a trusted main workflow dispatch")
    cases = manifest.get("cases")
    require(type(cases) is dict and bool(cases) and all(
        isinstance(name, str) and result == "passed"
        for name, result in cases.items()
    ), "qualification cases not independently passed")
    artifacts = manifest.get("artifacts")
    require(type(artifacts) is dict and bool(artifacts) and "cases.tsv" in artifacts,
            "missing canonical case-results artifact binding")
    # The selected Level A producer checks all contract cases. Repeat that
    # independent check at publication, including the bound retained TSV,
    # rather than trusting an arbitrary nonempty manifest of passing cases.
    runtime_contract_file = ROOT / "contracts/v010-shell-runtime-qualification.toml"
    runtime_contract = tomllib.loads(runtime_contract_file.read_text(encoding="utf-8"))
    expected_cases = runtime_contract["required_cases"]
    require(type(expected_cases) is list and len(expected_cases) == len(set(expected_cases))
            and set(cases) == set(expected_cases),
            "runtime case set is incomplete or differs from the current publication contract")
    runtime_binding = manifest.get("runtime_contract")
    require(type(runtime_binding) is dict
            and runtime_binding.get("path") == "contracts/v010-shell-runtime-qualification.toml"
            and runtime_binding.get("sha256") == sha256(runtime_contract_file),
            "runtime qualification contract binding mismatch")
    retained_cases = {}
    for line in safe_file(directory, "cases.tsv", maximum).read_text(encoding="utf-8").splitlines():
        require(line.count("\t") == 1, "invalid retained runtime case row")
        case_id, outcome = line.split("\t")
        require(case_id not in retained_cases, "duplicate retained runtime case")
        retained_cases[case_id] = outcome
    require(retained_cases == cases, "retained runtime cases differ from manifest")
    record = manifest.get("workstation_recording")
    require(isinstance(record, dict) and record.get("scope") == "captured-automated-wayland-session", "missing Level A recording")
    recording_name = record.get("path")
    require(recording_name == "workstation-runtime.mkv", "unexpected Level A recording path")
    metadata_name = "workstation-runtime.metadata.json"
    digest_name = "workstation-runtime.sha256"
    # The real Level A manifest binds the video/sidecars in workstation_recording,
    # separately from artifacts. Both binding namespaces are independently enforced.
    recording_bindings = {
        recording_name: record.get("sha256"),
        metadata_name: record.get("metadata_sha256"),
        digest_name: record.get("digest_file_sha256"),
    }
    require(all(isinstance(value, str) and DIGEST.fullmatch(value) for value in recording_bindings.values()), "incomplete Level A recording bindings")
    expected = set(artifacts) | set(recording_bindings) | {MANIFEST, SIDECAR}
    result: dict[str, dict[str, Any]] = {}
    total = 0
    require(len(expected) <= policy["max_files"], "too many archived files")
    for name in expected:
        path = safe_file(directory, name, maximum)
        digest = sha256(path)
        size = path.stat().st_size
        total += size
        if name in artifacts:
            binding = artifacts[name]
            require(type(binding) is dict and binding.get("sha256") == digest and binding.get("size") == size, f"artifact binding mismatch: {name}")
        if name in recording_bindings:
            require(digest == recording_bindings[name], f"recording binding mismatch: {name}")
        result[name] = {"sha256": digest, "size": size}
    require(total <= maximum, "bundle exceeds size limit")
    # Unbound CI diagnostics, including unbound transcripts, remain excluded.
    require(1024 <= result[recording_name]["size"] <= 536870912,
            "recording size outside the Level A contract bounds")
    video_summary = verify_video(directory / recording_name)
    meta = parse_json((directory / metadata_name).read_text(encoding="utf-8"))
    required_metadata = {
        "schema_version": 1, "recording": recording_name,
        "source_sha": source, "sha256": record["sha256"],
        "size": result[recording_name]["size"],
        "codec": video_summary["codec"], "container": video_summary["container"],
        "width": video_summary["width"], "height": video_summary["height"],
    }
    require(isinstance(meta, dict) and all(meta.get(k) == v for k, v in required_metadata.items()), "recording metadata mismatch")
    require(isinstance(meta.get("duration_seconds"), (int, float)) and
            abs(meta["duration_seconds"] - video_summary["duration_seconds"]) < 0.001,
            "recording duration metadata mismatch")
    require((directory / digest_name).read_text(encoding="ascii") == f"{record['sha256']}  {recording_name}\n", "recording sidecar mismatch")
    return manifest, dict(sorted(result.items()))


def github_run(run: dict[str, Any], source: str, run_id: int, attempt: int) -> None:
    """The run payload comes from authenticated GitHub REST, never from artifacts."""
    require(run.get("id") == run_id and run.get("run_attempt") == attempt, "GitHub run/attempt mismatch")
    require(run.get("head_sha") == source and run.get("head_branch") == "main", "GitHub run did not execute the exact main source")
    require(run.get("event") == "workflow_dispatch" and run.get("conclusion") == "success" and run.get("status") == "completed", "originating qualification run not successful")
    require(run.get("path") in (
        ".github/workflows/v010-shell-runtime-qualification.yml",
        ".github/workflows/v010-shell-runtime-qualification.yml@main",
        ".github/workflows/v010-shell-runtime-qualification.yml@refs/heads/main",
    ), "untrusted workflow origin")
    require(run.get("repository", {}).get("full_name") == "linura-org/linura", "GitHub run repository mismatch")


def github_approval(reviews: Any, actor: str, publication_attempt: int) -> str:
    """Require an environment review from an unambiguous fresh publication run.

    GitHub's /runs/{id}/approvals history is run-wide and does not reliably
    identify the attempt of each approval. Refuse reruns: retry by starting a
    new workflow_dispatch, which has a new run ID and a fresh environment review.
    """
    require(type(publication_attempt) is int and publication_attempt == 1,
            "publication reruns require a fresh dispatch and environment approval")
    require(isinstance(reviews, list), "invalid GitHub environment review history")
    for review in reviews:
        if not isinstance(review, dict) or review.get("state") != "approved":
            continue
        reviewer = review.get("user", {}).get("login")
        if (
            isinstance(reviewer, str)
            and re.fullmatch(r"[A-Za-z0-9-]{1,39}", reviewer)
            and any(isinstance(env, dict) and env.get("name") == "qualification-archive"
                    for env in review.get("environments", []))
        ):
            return reviewer
    raise AdmissionError("no recorded GitHub qualification-archive environment approval")


def validate_approval_provenance(
    actor: Any, reviewer: Any, reason: Any, approved_at: Any,
    publication_run: Any,
) -> datetime:
    require(isinstance(actor, str)
            and re.fullmatch(r"[A-Za-z0-9-]{1,39}", actor) is not None,
            "invalid publisher identity")
    require(isinstance(reason, str) and 12 <= len(reason) <= 256
            and all(32 <= ord(c) <= 126 for c in reason),
            "explicit approval reason required")
    require(isinstance(reviewer, str)
            and re.fullmatch(r"[A-Za-z0-9-]{1,39}", reviewer) is not None,
            "verified environment reviewer is required")
    require(isinstance(approved_at, str), "admission timestamp requires timezone")
    try:
        timestamp = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdmissionError("invalid admission timestamp") from exc
    require(timestamp.tzinfo is not None and timestamp.utcoffset() is not None,
            "admission timestamp requires timezone")
    require(type(publication_run) is dict
            and type(publication_run.get("run_id")) is int
            and publication_run["run_id"] > 0
            and type(publication_run.get("run_attempt")) is int
            and publication_run["run_attempt"] == 1
            and isinstance(publication_run.get("head_sha"), str)
            and SHA.fullmatch(publication_run["head_sha"]) is not None
            and publication_run.get("workflow_ref") ==
            "linura-org/linura/.github/workflows/publish-qualification-evidence.yml@refs/heads/main",
            "exact publication run provenance is required")
    return timestamp


def make_record(manifest: dict[str, Any], files: dict[str, dict[str, Any]], category: str, actor: str, reason: str, approved_at: str, policy: dict[str, Any], *, reviewer: str | None = None, publication_run: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
    require(category in ("baselines", "regressions"), "only selected Level A categories are enabled for CI publication")
    timestamp = validate_approval_provenance(
        actor, reviewer, reason, approved_at, publication_run
    )
    workflow = manifest["workflow"]
    identity = f"{manifest['source_sha']}/{workflow['run_id']}/{workflow['run_attempt']}"
    prefix = f"{category}/{identity}"
    record = {
        "schema_version": 1, "category": category, "source_sha": manifest["source_sha"],
        "repository": "linura-org/linura", "workflow": workflow, "qualified_result": "passed",
        "evidence_sha256": files[MANIFEST]["sha256"], "retention_days": policy["category"][category]["retention_days"],
        "selected_by": actor, "approved_by": reviewer, "publication_run": publication_run,
        "admitted_at": timestamp.astimezone(timezone.utc).isoformat(),
        "approval_reason": reason, "privacy": policy["category"][category]["privacy"],
        "objects": {f"{prefix}/{name}": binding for name, binding in files.items()},
        "publication_scope": "private-archive-not-support-promotion",
    }
    return prefix, record


def aws(args: list[str], *, output: bool = False) -> str:
    env = os.environ.copy()
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    env["AWS_DEFAULT_REGION"] = "auto"
    command = ["aws", "--endpoint-url", env["R2_ENDPOINT"], "s3api", *args]
    try:
        proc = subprocess.run(command, env=env, check=False, capture_output=True,
                              text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdmissionError(f"R2 operation unavailable or timed out: {args[0]}") from exc
    if proc.returncode:
        raise AdmissionError(f"R2 operation failed: {args[0]} (status {proc.returncode}); inspect secured runner logs")
    return proc.stdout if output else ""


def put_new(bucket: str, key: str, path: Path, expected: str) -> None:
    require(DIGEST.fullmatch(expected) is not None, "invalid upload digest")
    # Reuse an interrupted publication only after reading back exact bytes.
    try:
        aws(["put-object", "--bucket", bucket, "--key", key, "--body", str(path),
             "--if-none-match", "*", "--metadata", f"sha256={expected}"])
    except AdmissionError:
        pass
    head = parse_json(aws(["head-object", "--bucket", bucket, "--key", key], output=True))
    require(head.get("Metadata", {}).get("sha256") == expected and head.get("ContentLength") == path.stat().st_size, "stored object verification failed")
    with tempfile.TemporaryDirectory(prefix="linura-r2-check-") as temp:
        target = Path(temp) / "readback"
        aws(["get-object", "--bucket", bucket, "--key", key, str(target)])
        require(target.stat().st_size == path.stat().st_size and sha256(target) == expected, "remote object bytes mismatch")


def put_index(bucket: str, key: str, path: Path, record: dict[str, Any]) -> None:
    """Commit index last. A subsequent approved retry retains the first audit record."""
    try:
        put_new(bucket, key, path, sha256(path))
        return
    except AdmissionError:
        # A successful earlier attempt may already have published the same
        # evidence using its original reviewer, reason and admission timestamp.
        pass
    head = parse_json(aws(["head-object", "--bucket", bucket, "--key", key], output=True))
    digest = head.get("Metadata", {}).get("sha256")
    require(isinstance(digest, str) and DIGEST.fullmatch(digest) is not None, "stored index digest is missing")
    with tempfile.TemporaryDirectory(prefix="linura-r2-index-check-") as temp:
        target = Path(temp) / "index.json"
        aws(["get-object", "--bucket", bucket, "--key", key, str(target)])
        require(
            head.get("ContentLength") == target.stat().st_size and sha256(target) == digest,
            "stored index bytes mismatch",
        )
        previous = parse_json(target.read_text(encoding="utf-8"))
    require(isinstance(previous, dict), "stored index is malformed")
    stable = (
        "schema_version", "category", "source_sha", "repository", "workflow",
        "qualified_result", "evidence_sha256", "retention_days", "privacy",
        "objects", "publication_scope",
    )
    require(all(previous.get(field) == record.get(field) for field in stable),
            "existing index conflicts with this qualified evidence")
    try:
        validate_approval_provenance(
            previous.get("selected_by"), previous.get("approved_by"),
            previous.get("approval_reason"), previous.get("admitted_at"),
            previous.get("publication_run"),
        )
    except (AdmissionError, ValueError, TypeError) as exc:
        raise AdmissionError("existing index has invalid approval provenance") from exc


def snapshot_file(source: Path, target: Path, expected_sha: str, expected_size: int) -> None:
    """Copy only a verified single-link file through an O_NOFOLLOW descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise AdmissionError("evidence changed or became unsafe before publication") from exc
    with os.fdopen(descriptor, "rb") as reader:
        before = os.fstat(reader.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == expected_size, "evidence changed or became unsafe before publication")
        digest = hashlib.sha256()
        with target.open("xb") as writer:
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        after = os.fstat(reader.fileno())
        identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        require(identity(before) == identity(after) and digest.hexdigest() == expected_sha,
                "evidence changed during private publication snapshot")
    require(target.stat().st_size == expected_size and sha256(target) == expected_sha,
            "private publication snapshot differs from approved evidence")


def publication_identity() -> dict[str, Any]:
    """Capture the GitHub run whose environment review authorized publication."""
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    head_sha = os.environ.get("GITHUB_SHA", "")
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None
            and attempt == "1"
            and SHA.fullmatch(head_sha) is not None
            and workflow_ref ==
            "linura-org/linura/.github/workflows/publish-qualification-evidence.yml@refs/heads/main",
            "missing or unsafe GitHub publication-run identity")
    return {"run_id": int(run_id), "run_attempt": int(attempt),
            "head_sha": head_sha, "workflow_ref": workflow_ref}


ADMISSION = "publication-admission.json"


def admit(directory: Path, staged: Path, run_file: Path, category: str, source: str,
          run_id: int, attempt: int, actor: str, reason: str,
          policy: dict[str, Any]) -> str:
    """Probe untrusted media only in the credential-free admission job."""
    require(os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("GITHUB_ACTOR") == actor,
            "admission requires trusted main workflow dispatch")
    publisher = publication_identity()
    github_run(parse_json(run_file.read_text(encoding="utf-8")),
               source, run_id, attempt)
    require(category in ("baselines", "regressions"), "unsafe admission category")
    # Reject bad reasons before any publication artifact is produced.
    require(isinstance(reason, str) and 12 <= len(reason) <= 256
            and all(32 <= ord(c) <= 126 for c in reason),
            "explicit approval reason required")
    manifest, files = verified_bundle(directory, source, run_id, attempt, policy)
    require(not staged.exists(), "admission staging destination already exists")
    staged.mkdir(mode=0o700)
    # This is an independent snapshot in a job that has no R2 credentials.
    for name, binding in files.items():
        snapshot_file(directory / name, staged / name,
                      binding["sha256"], binding["size"])
    receipt = {
        "schema_version": 1, "publisher": publisher,
        "source_sha": source, "run_id": run_id, "attempt": attempt,
        "category": category, "selected_by": actor, "approval_reason": reason,
        "policy_sha256": sha256(CONTRACT),
        "manifest": manifest, "files": files,
    }
    path = staged / ADMISSION
    path.write_bytes(canonical(receipt))
    return sha256(path)


def read_admission(directory: Path, expected_sha: str | None, source: str,
                   run_id: int, attempt: int, category: str, actor: str,
                   reason: str, policy: dict[str, Any],
                   ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Verify the previous job's digest-pinned receipt; never probe media."""
    require(isinstance(expected_sha, str) and DIGEST.fullmatch(expected_sha) is not None,
            "trusted admission digest is required")
    receipt_path = safe_file(directory, ADMISSION, 131072)
    require(sha256(receipt_path) == expected_sha, "admission receipt digest mismatch")
    receipt_bytes = receipt_path.read_bytes()
    receipt = parse_json(receipt_bytes.decode("utf-8"))
    require(type(receipt) is dict and receipt_bytes == canonical(receipt),
            "noncanonical admission receipt")
    require(receipt.get("schema_version") == 1
            and receipt.get("publisher") == publication_identity()
            and receipt.get("source_sha") == source
            and type(receipt.get("run_id")) is int and receipt["run_id"] == run_id
            and type(receipt.get("attempt")) is int and receipt["attempt"] == attempt
            and receipt.get("category") == category
            and receipt.get("selected_by") == actor
            and receipt.get("approval_reason") == reason
            and receipt.get("policy_sha256") == sha256(CONTRACT),
            "admission receipt identity or policy mismatch")
    manifest = receipt.get("manifest")
    files = receipt.get("files")
    require(type(manifest) is dict and manifest.get("source_sha") == source
            and manifest.get("repository") == "linura-org/linura"
            and manifest.get("result") == "passed"
            and manifest.get("release_support_promotion") is False
            and type(manifest.get("workflow")) is dict
            and manifest["workflow"].get("run_id") == run_id
            and manifest["workflow"].get("run_attempt") == attempt,
            "invalid admitted qualification manifest")
    require(type(files) is dict and MANIFEST in files and SIDECAR in files
            and bool(files) and len(files) <= policy["max_files"],
            "invalid admitted evidence inventory")
    expected_files = set(manifest.get("artifacts", {})) | {
        MANIFEST, SIDECAR, "workstation-runtime.mkv",
        "workstation-runtime.metadata.json", "workstation-runtime.sha256",
    }
    require(set(files) == expected_files, "admission file set mismatch")
    total = 0
    for name, binding in files.items():
        require(type(name) is str and FILE.fullmatch(name) is not None
                and type(binding) is dict and set(binding) == {"sha256", "size"}
                and isinstance(binding["sha256"], str)
                and DIGEST.fullmatch(binding["sha256"]) is not None
                and type(binding["size"]) is int
                and 0 < binding["size"] <= policy["max_total_bytes"],
                "invalid admitted file binding")
        total += binding["size"]
    require(total <= policy["max_total_bytes"], "admitted bundle exceeds size limit")
    return manifest, files

def publish(directory: Path, run_file: Path, approval_file: Path, category: str, source: str, run_id: int, attempt: int, actor: str, reason: str, approved_at: str, policy: dict[str, Any], *, admission_sha: str | None = None) -> str:
    require(os.environ.get("GITHUB_REF") == "refs/heads/main" and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "publisher requires trusted main workflow dispatch")
    require(os.environ.get("GITHUB_ACTOR") == actor, "publisher identity mismatch")
    require(os.environ.get("GITHUB_WORKFLOW_REF", "").startswith("linura-org/linura/.github/workflows/publish-qualification-evidence.yml@refs/heads/main"), "publisher workflow origin mismatch")
    require(os.environ.get("R2_BUCKET") == policy["bucket"], "R2 bucket mismatch")
    endpoint = os.environ.get("R2_ENDPOINT", "")
    parsed = urlsplit(endpoint)
    require(parsed.scheme == "https"
            and re.fullmatch(
                r"[0-9a-f]{32}(?:\.(?:eu|us|fedramp))?\.r2\.cloudflarestorage\.com",
                parsed.hostname or "",
            ) is not None
            and endpoint == f"https://{parsed.hostname}"
            and parsed.username is None and parsed.password is None
            and parsed.port is None and not parsed.path and not parsed.query
            and not parsed.fragment,
            "untrusted R2 endpoint")
    require(os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"), "missing restricted publisher credentials")
    run = parse_json(run_file.read_text(encoding="utf-8"))
    github_run(run, source, run_id, attempt)
    reviewer = github_approval(parse_json(approval_file.read_text(encoding="utf-8")),
                               actor, publication_identity()["run_attempt"])
    manifest, files = read_admission(
        directory, admission_sha, source, run_id, attempt, category, actor, reason, policy
    )
    prefix, record = make_record(manifest, files, category, actor, reason, approved_at, policy,
                                 reviewer=reviewer, publication_run=publication_identity())
    bucket = policy["bucket"]
    # Never hand aws a mutable or symlink-substituted downloaded artifact path.
    # Fail the entire admission before writing any remote object on local drift.
    with tempfile.TemporaryDirectory(prefix="linura-r2-publish-") as private_dir:
        staged = Path(private_dir)
        for name, binding in files.items():
            snapshot_file(directory / name, staged / name, binding["sha256"], binding["size"])
        for name, binding in files.items():
            put_new(bucket, f"{prefix}/{name}", staged / name, binding["sha256"])
        # The index is the commit marker; an absent index means incomplete.
        index_key = f"index/{category}/{source}/{run_id}/{attempt}/{files[MANIFEST]['sha256']}.json"
        record_path = staged / "publication-index.json"
        require(not record_path.exists() and not record_path.is_symlink(), "index staging file already exists")
        record_path.write_bytes(canonical(record))
        put_index(bucket, index_key, record_path, record)
    return index_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("admit", "publish"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--run-json", required=True, type=Path)
    parser.add_argument("--approval-json", type=Path)
    parser.add_argument("--staging-directory", type=Path)
    parser.add_argument("--admission-sha256")
    parser.add_argument("--category", required=True, choices=("baselines", "regressions"))
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--attempt", required=True, type=int)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--approved-at")
    args = parser.parse_args()
    try:
        policy = load_policy()
        if args.command == "admit":
            require(args.staging_directory is not None, "admission staging destination missing")
            digest = admit(args.directory, args.staging_directory, args.run_json,
                           args.category, args.source_sha, args.run_id,
                           args.attempt, args.actor, args.reason, policy)
            print(f"credential-free admission passed: {digest}")
        else:
            require(args.approval_json is not None and args.approved_at is not None,
                    "approved publication provenance required")
            print(publish(args.directory, args.run_json, args.approval_json,
                          args.category, args.source_sha, args.run_id, args.attempt,
                          args.actor, args.reason, args.approved_at, policy,
                          admission_sha=args.admission_sha256))
        return 0
    except (AdmissionError, ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
        print(f"evidence publication refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
