#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import workstation_acceptance  # noqa: E402

STATE_ARTIFACT_TYPE = "linura-v010-q11-run-state"
FINALIZATION_ARTIFACT_TYPE = "linura-v010-q11-candidate-finalization"
ATTESTATION_TYPE = "linura-v010-qualification-case"
RUNNER_ID = "qualification/v010/workstation-runner"
Q11_PREFIX = Path("qualification/v010/interactive-workstation")
MANIFEST = Path("qualification/v010/interactive-workstation-evidence.json")
ALLOWED_CONTROLLERS = {
    "maintainer-console",
    "systemd-host",
    "network-harness",
    "storage-harness",
}
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = 768 * 1024 * 1024
MAX_BUNDLE_FILES = 512
FIXTURE_EVIDENCE = Q11_PREFIX / "fixture-contract.json"


class RunnerError(ValueError):
    pass


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _validate_hex(value: object, label: str, size: int) -> str:
    if not isinstance(value, str) or len(value) != size or any(
        ch not in "0123456789abcdef" for ch in value
    ):
        raise RunnerError(f"{label} must be {size} lowercase hexadecimal characters")
    return value


def _identifier(value: str, label: str, maximum: int) -> str:
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
    if (
        not value
        or len(value) > maximum
        or not value[0].isalnum()
        or any(ch not in allowed for ch in value)
    ):
        raise RunnerError(f"{label} must be a bounded identifier")
    return value


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise RunnerError("short write while persisting Q11 run state")
        offset += written


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RunnerError(f"refusing to replace symlink: {path}")
    data = _canonical_json(value)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    _write_new(temporary, data)
    os.replace(temporary, path)


def _regular_file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_regular(path: Path, maximum: int = MAX_FILE_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise RunnerError(f"cannot safely open {path}: {error}") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RunnerError(f"artifact is not a single-link regular file: {path}")
        if before.st_size < 1 or before.st_size > maximum:
            raise RunnerError(f"artifact size is outside bounds: {path}")
        data = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise RunnerError(f"artifact changed while reading: {path}")
            data.extend(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise RunnerError(f"artifact grew while reading: {path}")
        after = os.fstat(fd)
        if _regular_file_identity(before) != _regular_file_identity(after):
            raise RunnerError(f"artifact changed while reading: {path}")
        return bytes(data)
    finally:
        os.close(fd)


def _digest_regular(path: Path, maximum: int = MAX_FILE_BYTES) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise RunnerError(f"cannot safely open {path}: {error}") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RunnerError(f"artifact is not a single-link regular file: {path}")
        if before.st_size < 1 or before.st_size > maximum:
            raise RunnerError(f"artifact size is outside bounds: {path}")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise RunnerError(f"artifact changed while hashing: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise RunnerError(f"artifact grew while hashing: {path}")
        after = os.fstat(fd)
        if _regular_file_identity(before) != _regular_file_identity(after):
            raise RunnerError(f"artifact changed while hashing: {path}")
        return digest.hexdigest(), before.st_size
    finally:
        os.close(fd)

def _read_json(path: Path) -> dict[str, Any]:
    try:
        result = json.loads(_read_regular(path).decode())
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"invalid JSON artifact {path}: {error}") from error
    if not isinstance(result, dict):
        raise RunnerError(f"JSON artifact must be an object: {path}")
    return result


def _exact_source(source_root: Path, source_sha: str) -> Path:
    source_root = source_root.resolve()
    source_sha = _validate_hex(source_sha, "source SHA", 40)
    head = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    status = subprocess.run(
        ["git", "-C", str(source_root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if head.returncode or head.stdout.strip() != source_sha or status.returncode or status.stdout:
        raise RunnerError("Level C orchestration requires a fully clean exact-source checkout")
    return source_root


def _state_root(path: Path, source_root: Path, *, create: bool) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    candidate = candidate.absolute()
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if cursor.exists() and cursor.is_symlink():
            raise RunnerError("Q11 run state path must not contain symlink components")
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(source_root.resolve())
    except ValueError:
        pass
    else:
        raise RunnerError("Q11 run state must live outside the source checkout")
    if create:
        if candidate.exists() and (candidate.is_symlink() or any(candidate.iterdir())):
            raise RunnerError("Q11 run state root must be a new empty directory")
        candidate.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(candidate, 0o700)
    if not candidate.is_dir() or candidate.is_symlink():
        raise RunnerError("Q11 run state root is missing or unsafe")
    if stat.S_IMODE(candidate.stat().st_mode) & 0o077:
        raise RunnerError("Q11 run state root must be private")
    return candidate


@contextmanager
def _locked_state(root: Path) -> Iterator[None]:
    """Serialize the entire read/verify/update transaction for one Q11 run."""
    lock_path = root / ".run-state.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise RunnerError(f"cannot safely open Q11 state lock: {error}") from error
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RunnerError("Q11 state lock must be a private single-link regular file")
        deadline = time.monotonic() + 180
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RunnerError("Q11 run state is busy; concurrent update timed out")
                time.sleep(0.05)
        path_info = os.lstat(lock_path)
        if (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
            raise RunnerError("Q11 state lock changed during acquisition")
        yield
    finally:
        os.close(fd)


def _state_file(root: Path) -> Path:
    return root / "run-state.json"


def _load_state(root: Path) -> dict[str, Any]:
    state = _read_json(_state_file(root))
    if state.get("artifact_type") != STATE_ARTIFACT_TYPE or state.get("schema_version") != 1:
        raise RunnerError("Q11 run state identity drifted")
    if state.get("release_support_promotion") is not False or state.get("evidence_ready") is not False:
        raise RunnerError("Q11 run state cannot claim support or evidence readiness")
    return state


def _enrolled_fixture_matches(state: dict[str, Any]) -> None:
    fixture_id = _identifier(state["fixture_id"], "fixture-id", 64)
    digest = _validate_hex(state["fixture_contract_sha256"], "fixture contract digest", 64)
    enrolled_path = Path(state["fixture_contract_path"])
    enrolled, observed_digest = workstation_acceptance.read_hardware_fixture(
        enrolled_path, fixture_id=fixture_id
    )
    if observed_digest != digest or enrolled != state["fixture"]:
        raise RunnerError("maintained fixture enrollment changed after Q11 run started")


def _request_file(root: Path, case: str) -> Path:
    return root / "requests" / f"{case}.json"


def _request_set(root: Path, state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    required = state.get("required_cases")
    digests = state.get("request_sha256")
    if not isinstance(required, list) or not isinstance(digests, dict) or set(required) != set(digests):
        raise RunnerError("Q11 request bindings are invalid")
    result: dict[str, dict[str, Any]] = {}
    for case in required:
        data = _read_regular(_request_file(root, case))
        if _sha_bytes(data) != digests[case]:
            raise RunnerError(f"Q11 request was modified: {case}")
        request = json.loads(data)
        if not isinstance(request, dict):
            raise RunnerError(f"Q11 request must be an object: {case}")
        result[case] = request
    return result


def _bundle_tree(bundle: Path) -> None:
    if not bundle.is_dir() or bundle.is_symlink():
        raise RunnerError("Q11 bundle root is missing or unsafe")
    count = 0
    total = 0
    allowed_ancestors = {
        Path("qualification"),
        Path("qualification/v010"),
        Q11_PREFIX,
    }
    for directory, directories, files in os.walk(bundle, followlinks=False):
        base = Path(directory)
        for name in directories:
            path = base / name
            info = os.lstat(path)
            relative = path.relative_to(bundle)
            within_evidence = (
                relative == Q11_PREFIX
                or Q11_PREFIX in relative.parents
            )
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or (relative not in allowed_ancestors and not within_evidence)
            ):
                raise RunnerError("Q11 bundle contains an unsafe or out-of-namespace directory")
        for name in files:
            path = base / name
            info = os.lstat(path)
            relative = path.relative_to(bundle)
            within_evidence = Q11_PREFIX in relative.parents
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1
                or (relative != MANIFEST and not within_evidence)
            ):
                raise RunnerError(f"Q11 bundle path is outside the candidate evidence namespace: {relative}")
            count += 1
            total += info.st_size
            if count > MAX_BUNDLE_FILES or total > MAX_BUNDLE_BYTES:
                raise RunnerError("Q11 bundle exceeds bounded resource limits")


def _freeze_bundle(source: Path, snapshot: Path) -> None:
    """Copy one bounded, validated bundle into a private, run-owned tree.

    External case writers do not acquire our state lock, so hashing the live
    tree separately from its manifest and verifier input is insufficient.
    Every subsequent admission check reads only this frozen copy.
    """
    _bundle_tree(source)
    snapshot.mkdir(mode=0o700)
    count = 0
    total = 0
    for directory, directories, files in os.walk(source, followlinks=False):
        directories.sort()
        files.sort()
        relative = Path(directory).relative_to(source)
        destination = snapshot / relative
        destination.mkdir(parents=True, exist_ok=True)
        for name in files:
            data = _read_regular(
                Path(directory) / name, maximum=MAX_BUNDLE_BYTES
            )
            count += 1
            total += len(data)
            if count > MAX_BUNDLE_FILES or total > MAX_BUNDLE_BYTES:
                raise RunnerError("Q11 frozen bundle exceeds bounded resource limits")
            _write_new(destination / name, data)
    _bundle_tree(snapshot)


def _bundle_snapshot_digest(bundle: Path) -> str:
    _bundle_tree(bundle)
    entries: list[dict[str, object]] = []
    for directory, directories, files in os.walk(bundle, followlinks=False):
        directories.sort()
        files.sort()
        base = Path(directory)
        for name in directories:
            relative = (base / name).relative_to(bundle).as_posix()
            entries.append({"path": relative, "type": "directory"})
        for name in files:
            path = base / name
            relative = path.relative_to(bundle).as_posix()
            digest, size = _digest_regular(path, maximum=MAX_BUNDLE_BYTES)
            entries.append(
                {"path": relative, "type": "file", "size": size, "sha256": digest}
            )
    return _sha_bytes(_canonical_json(entries))

def _binding(bundle: Path, value: object, label: str) -> tuple[Path, str]:
    if not isinstance(value, dict):
        raise RunnerError(f"{label} binding must be an object")
    relative_value = value.get("path")
    digest = _validate_hex(value.get("sha256"), f"{label} digest", 64)
    if not isinstance(relative_value, str):
        raise RunnerError(f"{label} path must be a string")
    relative = Path(relative_value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not relative.as_posix().startswith(Q11_PREFIX.as_posix() + "/")
    ):
        raise RunnerError(f"{label} path is outside the Q11 evidence tree")
    path = bundle / relative
    data = _read_regular(path)
    if _sha_bytes(data) != digest:
        raise RunnerError(f"{label} digest mismatch")
    return path, digest


def begin_run(
    source_root: Path,
    state_root: Path,
    run_id: str,
    fixture_id: str,
    source_sha: str,
    fixture_contract: Path,
) -> dict[str, Any]:
    run_id = _identifier(run_id, "run-id", 128)
    fixture_id = _identifier(fixture_id, "fixture-id", 64)
    source_root = _exact_source(source_root, source_sha)
    contract = workstation_acceptance.load_contract(
        source_root / "contracts/v010-workstation-acceptance.toml"
    )
    requests = workstation_acceptance.hardware_run_requests(
        contract,
        run_id=run_id,
        fixture_id=fixture_id,
        source_sha=source_sha,
        slice_path=source_root / "contracts/v010-workstation-slices.toml",
    )
    fixture, fixture_digest = workstation_acceptance.read_hardware_fixture(
        fixture_contract, fixture_id=fixture_id
    )
    failures = workstation_acceptance.hardware_doctor(
        fixture_contract=fixture_contract, fixture_id=fixture_id
    )
    if failures:
        raise RunnerError("Level C physical prerequisites failed: " + "; ".join(failures))
    state_root = _state_root(state_root, source_root, create=True)
    bundle_fixture = state_root / "bundle" / FIXTURE_EVIDENCE
    fixture_bytes = _read_regular(fixture_contract)
    if _sha_bytes(fixture_bytes) != fixture_digest:
        raise RunnerError("maintained fixture changed during run enrollment")
    _write_new(bundle_fixture, fixture_bytes)
    request_digests = {}
    for request in requests:
        data = _canonical_json(request)
        path = _request_file(state_root, request["case"])
        _write_new(path, data)
        request_digests[request["case"]] = _sha_bytes(data)
    state = {
        "schema_version": 1,
        "artifact_type": STATE_ARTIFACT_TYPE,
        "run_id": run_id,
        "source_commit_sha": source_sha,
        "fixture_id": fixture_id,
        "fixture_contract_sha256": fixture_digest,
        "fixture_contract_path": str(fixture_contract.resolve()),
        "fixture": fixture,
        "required_cases": [request["case"] for request in requests],
        "request_sha256": request_digests,
        "accepted_cases": {},
        "status": "collecting",
        "release_support_promotion": False,
        "evidence_ready": False,
    }
    _atomic_json(_state_file(state_root), state)
    return state


def _validate_case(
    bundle: Path,
    path: Path,
    request: dict[str, Any],
    state: dict[str, Any],
) -> str:
    try:
        relative = path.resolve().relative_to(bundle.resolve())
    except ValueError as error:
        raise RunnerError("case attestation must live inside the Q11 bundle") from error
    if not relative.as_posix().startswith(Q11_PREFIX.as_posix() + "/"):
        raise RunnerError("case attestation must live under the Q11 evidence tree")
    data = _read_regular(path)
    digest = _sha_bytes(data)
    attestation = json.loads(data)
    if not isinstance(attestation, dict):
        raise RunnerError("case attestation must be an object")
    expected = {
        "schema_version": 1,
        "attestation_type": ATTESTATION_TYPE,
        "case": request["case"],
        "result": "passed",
        "run_id": state["run_id"],
    }
    for key, value in expected.items():
        if attestation.get(key) != value:
            raise RunnerError(f"case attestation {key} does not match the bounded request")
    if not isinstance(attestation.get("captured_at_utc"), str) or not attestation["captured_at_utc"]:
        raise RunnerError("case attestation requires captured_at_utc")
    runner = attestation.get("runner")
    if not isinstance(runner, dict) or runner.get("id") != RUNNER_ID:
        raise RunnerError("case runner identity is invalid")
    if runner.get("commit_sha") != state["source_commit_sha"]:
        raise RunnerError("case runner source identity mismatch")
    _validate_hex(runner.get("linurad_sha256"), "linurad digest", 64)
    _validate_hex(runner.get("shell_bridge_sha256"), "ShellBridge digest", 64)
    observations = attestation.get("observations")
    if not isinstance(observations, list):
        raise RunnerError("case observations must be an array")
    observed = {}
    for item in observations:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or item["name"] in observed:
            raise RunnerError("case observations must have unique names")
        observed[item["name"]] = item
    if set(observed) != set(request["required_observations"]):
        raise RunnerError("case observations do not match the bounded request")
    for name in request["required_observations"]:
        item = observed[name]
        if item.get("result") != "passed":
            raise RunnerError(f"case observation did not pass: {name}")
        value = item.get("value")
        if name.endswith("-version"):
            if not isinstance(value, str) or not value:
                raise RunnerError(f"provider version is empty: {name}")
        elif value is not True:
            raise RunnerError(f"case observation must carry boolean success: {name}")
    execution = attestation.get("machine_execution")
    if not isinstance(execution, dict) or execution.get("scope") != "machine":
        raise RunnerError("case requires machine execution provenance")
    controller = execution.get("controller")
    if controller not in ALLOWED_CONTROLLERS:
        raise RunnerError("case controller is not an allowed external physical controller")
    if execution.get("mechanism") != request["mechanism"]:
        raise RunnerError("case mechanism does not match the bounded request")
    if execution.get("fixture_id") != state["fixture_id"]:
        raise RunnerError("case execution fixture identity mismatch")
    if execution.get("fixture_contract_sha256") != state["fixture_contract_sha256"]:
        raise RunnerError("case execution fixture enrollment digest mismatch")
    environment = _validate_hex(execution.get("environment_sha256"), "environment digest", 64)
    boot_id = execution.get("boot_id")
    if not isinstance(boot_id, str) or len(boot_id) != 36:
        raise RunnerError("case boot identity is invalid")
    provenance_path, _ = _binding(bundle, execution.get("provenance"), "case provenance")
    provenance = _read_json(provenance_path)
    expected_provenance = {
        "schema_version": 1,
        "artifact_type": "linura-v010-physical-workstation-case-provenance",
        "source_commit_sha": state["source_commit_sha"],
        "run_id": state["run_id"],
        "case": request["case"],
        "fixture_id": state["fixture_id"],
        "fixture_contract_sha256": state["fixture_contract_sha256"],
        "environment_sha256": environment,
        "boot_id": boot_id,
        "scope": "machine",
        "controller": controller,
        "mechanism": request["mechanism"],
        "external_controller": True,
        "process_local_mock": False,
    }
    for key, value in expected_provenance.items():
        if provenance.get(key) != value:
            raise RunnerError(f"case provenance {key} mismatch")
    event_path, _ = _binding(bundle, provenance.get("event_log"), "case event log")
    lines = set(_read_regular(event_path).decode().splitlines())
    required_lines = {
        f"case={request['case']}",
        f"controller={controller}",
        f"mechanism={request['mechanism']}",
        f"environment_sha256={environment}",
        f"fixture_id={state['fixture_id']}",
        f"fixture_contract_sha256={state['fixture_contract_sha256']}",
        f"source_commit_sha={state['source_commit_sha']}",
        f"run_id={state['run_id']}",
        "scope=machine",
        f"boot_id={boot_id}",
    }
    if not required_lines.issubset(lines):
        raise RunnerError("case event log does not bind the bounded execution")
    return digest


def record_case(
    source_root: Path, state_root: Path, case_id: str, attestation: Path
) -> dict[str, Any]:
    state_root = _state_root(state_root, source_root, create=False)
    with _locked_state(state_root):
        state = _load_state(state_root)
        source_root = _exact_source(source_root, state["source_commit_sha"])
        _enrolled_fixture_matches(state)
        requests = _request_set(state_root, state)
        if case_id not in requests:
            raise RunnerError(f"unsupported Q11 case: {case_id}")
        if state.get("status") != "collecting":
            raise RunnerError("validated Q11 candidate is immutable; start a new run for new evidence")
        bundle = state_root / "bundle"
        _bundle_tree(bundle)
        digest = _validate_case(bundle, attestation, requests[case_id], state)
        relative = attestation.resolve().relative_to(bundle.resolve()).as_posix()
        record = {"path": relative, "sha256": digest}
        accepted = state.setdefault("accepted_cases", {})
        if case_id in accepted and accepted[case_id] != record:
            raise RunnerError(f"Q11 case evidence substitution rejected: {case_id}")
        accepted[case_id] = record
        state["status"] = "collecting"
        _atomic_json(_state_file(state_root), state)
        return record


def _patch_contract(path: Path, digest: str) -> None:
    digest = _validate_hex(digest, "manifest digest", 64)
    text = path.read_text()
    start = text.find("[interactive_workstation]\n")
    end = text.find("\n[", start + 1)
    if start < 0:
        raise RunnerError("qualification contract is missing interactive_workstation")
    if end < 0:
        end = len(text)
    section = text[start:end]
    if section.count("evidence_ready = false") != 1 or section.count('evidence_manifest_sha256 = ""') != 1:
        raise RunnerError("interactive workstation readiness markers drifted")
    section = section.replace("evidence_ready = false", "evidence_ready = true", 1)
    section = section.replace(
        'evidence_manifest_sha256 = ""',
        f'evidence_manifest_sha256 = "{digest}"',
        1,
    )
    path.write_text(text[:start] + section + text[end:])


def _extract_source(source_root: Path, source_sha: str, destination: Path) -> None:
    archive = destination.parent / "source.tar"
    result = subprocess.run(
        ["git", "-C", str(source_root), "archive", "--format=tar", "--output", str(archive), source_sha],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode:
        raise RunnerError("failed to archive exact source: " + result.stderr.strip())
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r:") as handle:
        members = handle.getmembers()
        if any(
            Path(item.name).is_absolute()
            or ".." in Path(item.name).parts
            or item.issym()
            or item.islnk()
            or item.isdev()
            or item.isfifo()
            for item in members
        ):
            raise RunnerError("exact-source archive contains unsupported entries")
        handle.extractall(destination)
    archive.unlink()


def _manifest_cases(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise RunnerError("Q11 candidate manifest cases must be an array")
    result = {}
    for item in cases:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or item["name"] in result:
            raise RunnerError("Q11 candidate manifest has invalid or duplicate cases")
        result[item["name"]] = item
    return result


def finalize_run(source_root: Path, state_root: Path) -> dict[str, Any]:
    state_root = _state_root(state_root, source_root, create=False)
    with _locked_state(state_root):
        state = _load_state(state_root)
        source_root = _exact_source(source_root, state["source_commit_sha"])
        _enrolled_fixture_matches(state)
        _request_set(state_root, state)
        required = state["required_cases"]
        accepted = state.get("accepted_cases")
        if not isinstance(accepted, dict) or set(accepted) != set(required):
            missing = sorted(set(required) - set(accepted or {}))
            raise RunnerError(
                "Q11 candidate cannot finalize before every case is accepted: "
                + ", ".join(missing)
            )
        bundle = state_root / "bundle"
        with tempfile.TemporaryDirectory(prefix="linura-q11-frozen-") as frozen_dir:
            frozen_bundle = Path(frozen_dir) / "bundle"
            _freeze_bundle(bundle, frozen_bundle)
            bundle_digest = _bundle_snapshot_digest(frozen_bundle)
            if _bundle_snapshot_digest(bundle) != bundle_digest:
                raise RunnerError("Q11 candidate bundle changed during snapshot acquisition")
            manifest_data = _read_regular(frozen_bundle / MANIFEST)
            manifest_digest = _sha_bytes(manifest_data)
            manifest = json.loads(manifest_data)
            if not isinstance(manifest, dict) or manifest.get("run_id") != state["run_id"]:
                raise RunnerError("Q11 candidate manifest does not bind the run")
            source = manifest.get("source")
            if not isinstance(source, dict) or source.get("commit_sha") != state["source_commit_sha"]:
                raise RunnerError("Q11 candidate manifest source mismatch")
            fixture_binding = manifest.get("fixture")
            expected_binding = {
                "fixture_id": state["fixture_id"],
                "contract": {
                    "path": FIXTURE_EVIDENCE.as_posix(),
                    "sha256": state["fixture_contract_sha256"],
                },
            }
            if fixture_binding != expected_binding:
                raise RunnerError("Q11 candidate fixture enrollment binding mismatch")
            fixture_path, _ = _binding(frozen_bundle, fixture_binding["contract"], "candidate fixture")
            if _read_json(fixture_path) != state["fixture"]:
                raise RunnerError("Q11 candidate fixture payload mismatch")
            cases = _manifest_cases(manifest)
            if set(cases) != set(required):
                raise RunnerError("Q11 candidate manifest case set drifted")
            for case in required:
                item = cases[case]
                if (
                    item.get("result") != "passed"
                    or item.get("evidence") != accepted[case]["path"]
                    or item.get("sha256") != accepted[case]["sha256"]
                ):
                    raise RunnerError(f"Q11 candidate manifest binding mismatch: {case}")

            with tempfile.TemporaryDirectory(prefix="linura-q11-candidate-") as temporary:
                verification = Path(temporary) / "root"
                _extract_source(source_root, state["source_commit_sha"], verification)
                for directory, _directories, files in os.walk(frozen_bundle):
                    relative = Path(directory).relative_to(frozen_bundle)
                    target = verification / relative
                    target.mkdir(parents=True, exist_ok=True)
                    for name in files:
                        source_file = Path(directory) / name
                        target_file = target / name
                        target_file.write_bytes(
                            _read_regular(source_file, maximum=MAX_BUNDLE_BYTES)
                        )
                _patch_contract(
                    verification / "contracts/v010-workstation-qualification.toml",
                    manifest_digest,
                )
                environment = os.environ.copy()
                environment["LINURA_EXPECTED_SOURCE_SHA"] = state["source_commit_sha"]
                result = subprocess.run(
                    [
                        sys.executable,
                        str(verification / "tools/check_v010_workstation_qualification.py"),
                        str(verification),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                    timeout=120,
                )
                if result.returncode:
                    raise RunnerError(
                        "Q11 candidate failed the canonical verifier: "
                        + (result.stderr.strip() or result.stdout.strip())
                    )
            if _bundle_snapshot_digest(bundle) != bundle_digest:
                raise RunnerError("Q11 candidate bundle changed during canonical verification")
            finalization = {
                "schema_version": 1,
                "artifact_type": FINALIZATION_ARTIFACT_TYPE,
                "run_id": state["run_id"],
                "source_commit_sha": state["source_commit_sha"],
                "fixture_id": state["fixture_id"],
                "fixture_contract_sha256": state["fixture_contract_sha256"],
                "fixture_contract": {
                    "path": FIXTURE_EVIDENCE.as_posix(),
                    "sha256": state["fixture_contract_sha256"],
                },
                "manifest_path": MANIFEST.as_posix(),
                "manifest_sha256": manifest_digest,
                "bundle_sha256": bundle_digest,
                "required_cases": required,
                "result": "validated-candidate",
                "canonical_verifier": "tools/check_v010_workstation_qualification.py",
                "release_support_promotion": False,
                "evidence_ready": False,
            }
            finalization_data = _canonical_json(finalization)
            # State and the finalization receipt are a single publication boundary.
            # An external controller does not participate in our state flock, so
            # the bundle can change while the records are being written. Check it
            # again *after* publishing both records and revoke the candidate on
            # any mismatch. Subsequent consumers independently recheck in status().
            previous_state = dict(state)
            finalization_path = state_root / "candidate-finalization.json"
            try:
                _atomic_json(finalization_path, finalization)
                state["status"] = "validated-candidate"
                state["candidate_manifest_sha256"] = manifest_digest
                state["candidate_bundle_sha256"] = bundle_digest
                state["candidate_finalization_sha256"] = _sha_bytes(finalization_data)
                _atomic_json(_state_file(state_root), state)
                try:
                    published_bundle = _bundle_snapshot_digest(bundle)
                except (OSError, RunnerError) as exc:
                    raise RunnerError(
                        "Q11 candidate bundle changed during finalization publication"
                    ) from exc
                if published_bundle != bundle_digest:
                    raise RunnerError(
                        "Q11 candidate bundle changed during finalization publication"
                    )
            except Exception:
                # Fail closed even when the external writer races publication:
                # revoke validated status, and always clear the receipt.
                try:
                    _atomic_json(_state_file(state_root), previous_state)
                finally:
                    finalization_path.unlink(missing_ok=True)
                raise
            return finalization


def status(source_root: Path, state_root: Path) -> dict[str, Any]:
    state_root = _state_root(state_root, source_root, create=False)
    with _locked_state(state_root):
        state = _load_state(state_root)
        _exact_source(source_root, state["source_commit_sha"])
        _request_set(state_root, state)
        accepted = state.get("accepted_cases", {})
        run_status = state.get("status")
        if run_status == "validated-candidate":
            expected_bundle = _validate_hex(
                state.get("candidate_bundle_sha256"), "candidate bundle digest", 64
            )
            observed_bundle = _bundle_snapshot_digest(state_root / "bundle")
            if observed_bundle != expected_bundle:
                raise RunnerError("validated Q11 candidate bundle changed after finalization")
            if _sha_bytes(_read_regular(state_root / "bundle" / MANIFEST)) != state.get(
                "candidate_manifest_sha256"
            ):
                raise RunnerError("validated Q11 candidate manifest changed after finalization")
            finalization_data = _read_regular(state_root / "candidate-finalization.json")
            expected_finalization = _validate_hex(
                state.get("candidate_finalization_sha256"),
                "candidate finalization digest",
                64,
            )
            if _sha_bytes(finalization_data) != expected_finalization:
                raise RunnerError("Q11 candidate finalization record changed after validation")
            finalization = json.loads(finalization_data)
            if (
                not isinstance(finalization, dict)
                or finalization.get("artifact_type") != FINALIZATION_ARTIFACT_TYPE
                or finalization.get("run_id") != state["run_id"]
                or finalization.get("source_commit_sha") != state["source_commit_sha"]
                or finalization.get("fixture_id") != state["fixture_id"]
                or finalization.get("result") != "validated-candidate"
                or finalization.get("bundle_sha256") != expected_bundle
                or finalization.get("manifest_sha256")
                != state.get("candidate_manifest_sha256")
                or finalization.get("release_support_promotion") is not False
                or finalization.get("evidence_ready") is not False
            ):
                raise RunnerError("Q11 candidate finalization binding is invalid")
        elif run_status != "collecting":
            raise RunnerError("Q11 run state status is invalid")
        return {
            "run_id": state["run_id"],
            "source_commit_sha": state["source_commit_sha"],
            "fixture_id": state["fixture_id"],
            "status": state["status"],
            "required_cases": len(state["required_cases"]),
            "accepted_cases": len(accepted),
            "pending_cases": [case for case in state["required_cases"] if case not in accepted],
            "release_support_promotion": False,
            "evidence_ready": False,
        }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Linura v0.10 bounded physical Q11 run orchestrator"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    begin = sub.add_parser("begin-run")
    begin.add_argument("--source-root", type=Path, required=True)
    begin.add_argument("--state-root", type=Path, required=True)
    begin.add_argument("--run-id", required=True)
    begin.add_argument("--fixture-id", required=True)
    begin.add_argument("--source-sha", required=True)
    begin.add_argument(
        "--fixture-contract",
        type=Path,
        default=workstation_acceptance.DEFAULT_HARDWARE_FIXTURE_CONTRACT,
    )
    record = sub.add_parser("record-case")
    record.add_argument("--source-root", type=Path, required=True)
    record.add_argument("--state-root", type=Path, required=True)
    record.add_argument("--case", required=True)
    record.add_argument("--attestation", type=Path, required=True)
    finalize = sub.add_parser("finalize-run")
    finalize.add_argument("--source-root", type=Path, required=True)
    finalize.add_argument("--state-root", type=Path, required=True)
    query = sub.add_parser("status")
    query.add_argument("--source-root", type=Path, required=True)
    query.add_argument("--state-root", type=Path, required=True)
    args = parser.parse_args(argv[1:])
    try:
        if args.command == "begin-run":
            value = begin_run(
                args.source_root,
                args.state_root,
                args.run_id,
                args.fixture_id,
                args.source_sha,
                args.fixture_contract,
            )
        elif args.command == "record-case":
            value = record_case(
                args.source_root, args.state_root, args.case, args.attestation
            )
        elif args.command == "finalize-run":
            value = finalize_run(args.source_root, args.state_root)
        else:
            value = status(args.source_root, args.state_root)
        print(json.dumps(value, indent=2, sort_keys=True))
        return 0
    except (
        RunnerError,
        workstation_acceptance.AcceptanceError,
        OSError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
