#!/usr/bin/env python3
"""Reviewed semantic verifier adapters for retained qualification evidence.

These adapters do not accept a workflow's self-declared pass bit.  Each adapter
re-derives the lane outcome from retained command results, transcripts, exact
repository contracts, and the already-verified execution envelope.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Any

REPOSITORY = "linura-org/linura"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _stable_bytes(path: Path) -> bytes:
    _require(hasattr(os, "O_NOFOLLOW"), "no-follow file opens are unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(f"cannot open verifier input safely: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), f"verifier input is not regular: {path}")
        _require(before.st_nlink == 1, f"verifier input must have one link: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        _require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            f"verifier input changed while being read: {path}",
        )
        named = os.lstat(path)
        _require(
            stat.S_ISREG(named.st_mode)
            and named.st_nlink == 1
            and named.st_dev == after.st_dev
            and named.st_ino == after.st_ino,
            f"verifier input path changed while being read: {path}",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _stable_repository_bytes(path: Path) -> bytes:
    """Read a repository/build artifact without rejecting legitimate hardlinks.

    Retained evidence remains single-link-only via _stable_bytes(). Repository
    build outputs (notably Cargo release binaries) may legitimately be hardlinked
    by the build system, so this reader instead requires a no-follow regular-file
    descriptor, stable inode metadata for the duration of the read, and stable
    pathname-to-inode identity.
    """
    _require(hasattr(os, "O_NOFOLLOW"), "no-follow file opens are unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(
            f"cannot open repository verifier input safely: {path}: {exc}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode),
            f"repository verifier input is not regular: {path}",
        )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        _require(
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            f"repository verifier input changed while being read: {path}",
        )
        named = os.lstat(path)
        _require(
            stat.S_ISREG(named.st_mode)
            and named.st_dev == after.st_dev
            and named.st_ino == after.st_ino,
            f"repository verifier input path changed while being read: {path}",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _text(path: Path) -> str:
    try:
        return _stable_bytes(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"verifier input is not UTF-8: {path}") from exc


def _json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(_text(path))
    except json.JSONDecodeError as exc:
        raise VerificationError(f"invalid verifier JSON: {path}: {exc}") from exc
    _require(isinstance(payload, dict), f"verifier JSON must be an object: {path}")
    return payload


def _sha256(path: Path) -> str:
    return hashlib.sha256(_stable_bytes(path)).hexdigest()


def _repo_file(root: Path, relative: str) -> Path:
    _require(relative and not relative.startswith("/"), "repository path must be relative")
    _require(".." not in Path(relative).parts, "repository path may not traverse")
    path = root / relative
    _require(path.is_file() and not path.is_symlink(), f"missing repository verifier input: {relative}")
    _require(path.resolve().is_relative_to(root.resolve()), f"repository input escapes root: {relative}")
    return path


def _bundle_file(bundle: Path, name: str) -> Path:
    _require(name and Path(name).name == name, f"unsafe verifier artifact name: {name!r}")
    path = bundle / name
    _require(path.is_file() and not path.is_symlink(), f"missing verifier artifact: {name}")
    _require(path.resolve().parent == bundle.resolve(), f"verifier artifact escapes bundle: {name}")
    return path


def _common_primary(primary: dict[str, Any], envelope: dict[str, Any]) -> None:
    _require(primary.get("repository") == REPOSITORY, "primary repository mismatch")
    _require(primary.get("source_sha") == envelope["source"]["commit_sha"], "primary source mismatch")


def _artifact_digest_record(root: Path, record: object, label: str) -> None:
    _require(isinstance(record, dict), f"{label} artifact binding is missing")
    _require(set(record) == {"path", "sha256", "size"}, f"{label} artifact binding fields drifted")
    path_value = record["path"]
    _require(isinstance(path_value, str), f"{label} path is invalid")
    path = _repo_file(root, path_value)
    data = _stable_repository_bytes(path)
    _require(
        record["sha256"] == hashlib.sha256(data).hexdigest(),
        f"{label} repository digest mismatch",
    )
    _require(record["size"] == len(data), f"{label} repository size mismatch")


def _require_markers(text: str, markers: list[str], label: str) -> None:
    missing = [marker for marker in markers if marker not in text]
    _require(not missing, f"{label} is missing verified markers: {missing}")


def _cargo_log(
    path: Path,
    label: str,
    *,
    required_runner_patterns: tuple[str, ...],
) -> dict[str, Any]:
    text = _text(path)
    _require("test result: ok." in text, f"{label} has no successful cargo test result")
    _require("test result: FAILED" not in text and "\nFAILED" not in text, f"{label} contains a failed test")
    matches = re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed;", text)
    _require(matches, f"{label} cargo result summary is missing")
    _require(all(int(failed) == 0 for _, failed in matches), f"{label} reports failed tests")
    missing = [
        pattern
        for pattern in required_runner_patterns
        if re.search(pattern, text, re.MULTILINE) is None
    ]
    _require(not missing, f"{label} does not identify reviewed Cargo runners: {missing}")
    return {
        "result_blocks": len(matches),
        "passed_tests": sum(int(passed) for passed, _ in matches),
        "reviewed_runners": len(required_runner_patterns),
    }


def _envelope_guest_environment(envelope: dict[str, Any]) -> dict[str, Any]:
    subject = envelope.get("execution_subject")
    _require(isinstance(subject, dict) and subject.get("kind") == "virtual-machine",
             "lane did not execute in a verified virtual-machine subject")
    for key in ("architecture", "virtualization", "distribution_id", "distribution_version"):
        _require(isinstance(subject.get(key), str) and subject[key], f"guest subject lacks {key}")
    return subject


def _require_base_image_binding(primary: dict[str, Any], envelope: dict[str, Any]) -> None:
    subject = _envelope_guest_environment(envelope)
    images = subject.get("image_digests")
    _require(isinstance(images, dict), "guest subject image identity is missing")
    primary_image = primary.get("base_image")
    _require(isinstance(primary_image, dict), "primary base-image identity is missing")
    _require(
        primary_image.get("sha256") == images.get("base_image_sha256"),
        "primary base image does not match execution envelope",
    )


def _host_environment_verified(envelope: dict[str, Any]) -> bool:
    subject = envelope.get("execution_subject")
    runner = envelope.get("runner")
    if not isinstance(subject, dict) or subject.get("kind") != "runner":
        return False
    if not isinstance(runner, dict):
        return False
    return (
        HEX64.fullmatch(str(runner.get("os_release_sha256", ""))) is not None
        and HEX64.fullmatch(str(runner.get("package_manifest_sha256", ""))) is not None
        and isinstance(runner.get("architecture"), str)
        and bool(runner["architecture"])
    )


def _machine_environment_verified(
    primary: dict[str, Any], envelope: dict[str, Any]
) -> bool:
    _require_base_image_binding(primary, envelope)
    subject = _envelope_guest_environment(envelope)
    return (
        subject.get("virtualization") == "qemu"
        and subject.get("architecture") == "x86_64"
        and isinstance(subject.get("package_manifest_sha256"), str)
        and HEX64.fullmatch(subject["package_manifest_sha256"]) is not None
    )


def _aggregate_environment_verified(
    envelope: dict[str, Any], expected_environment_id: str
) -> bool:
    subject = envelope.get("execution_subject")
    observations = envelope.get("observations")
    return (
        isinstance(subject, dict)
        and subject.get("kind") == "aggregate"
        and HEX64.fullmatch(str(subject.get("component_envelope_set_sha256", ""))) is not None
        and isinstance(observations, dict)
        and observations.get("qualification_environment_id") == expected_environment_id
    )


def _outcome(
    *,
    adapter: str,
    test_ids: list[str],
    contract_ids: list[str],
    claims: list[str],
    environment_verified: bool,
    details: dict[str, Any],
) -> dict[str, Any]:
    _require(bool(claims) and len(claims) == len(set(claims)), f"{adapter} verified-claim inventory is invalid")
    semantic_verification_complete = (
        environment_verified
        and bool(test_ids)
        and bool(contract_ids)
        and bool(claims)
    )
    _require(
        semantic_verification_complete,
        f"{adapter} did not independently establish the reviewed qualification",
    )
    return {
        "adapter": adapter,
        "result": "passed" if semantic_verification_complete else "failed",
        "independent": semantic_verification_complete,
        "environment_verified": environment_verified,
        "verified_claims": sorted(claims),
        "test_ids": sorted(test_ids),
        "contract_ids": sorted(contract_ids),
        "details": details,
    }


def _verify_vm(
    root: Path,
    lane_id: str,
    bundle: Path,
    primary: dict[str, Any],
    envelope: dict[str, Any],
    *,
    required_scenario: str | None,
    test_id: str,
    contract_id: str,
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 2, "VM primary schema mismatch")
    result = _json(_bundle_file(bundle, "acceptance-result.json"))
    _require(result.get("schema_version") == 1, "VM runner result schema mismatch")
    _require(result.get("source_sha") == envelope["source"]["commit_sha"], "VM runner source mismatch")
    _require(result.get("result") == "passed", "VM runner did not complete successfully")
    scenario = result.get("scenario")
    _require(isinstance(scenario, dict) and set(scenario) == {"id", "path", "sha256"},
             "VM runner scenario identity is malformed")
    if required_scenario is not None:
        _require(scenario["id"] == required_scenario, "VM runner scenario mismatch")
    primary_scenario = primary.get("scenario")
    _require(primary_scenario == scenario, "VM primary scenario identity disagrees with runner result")
    scenario_path = _repo_file(root, scenario["path"])
    _require(_sha256(scenario_path) == scenario["sha256"], "VM scenario repository digest mismatch")
    scenario_payload = _json(scenario_path)
    _require(scenario_payload.get("schema_version") == 1, "VM scenario schema mismatch")
    _require(scenario_payload.get("id") == scenario["id"], "VM scenario id mismatch")
    expected_steps = scenario_payload.get("steps")
    observed_steps = result.get("steps")
    _require(isinstance(expected_steps, list) and expected_steps, "VM scenario has no steps")
    _require(isinstance(observed_steps, list) and len(observed_steps) == len(expected_steps),
             "VM runner step inventory mismatch")
    for expected, observed in zip(expected_steps, observed_steps, strict=True):
        _require(isinstance(expected, dict) and isinstance(observed, dict), "VM runner step is malformed")
        command = expected.get("command")
        name = expected.get("name")
        _require(isinstance(command, str) and isinstance(name, str), "VM scenario step is invalid")
        expected_digest = hashlib.sha256(command.encode("utf-8")).hexdigest()
        _require(
            observed == {
                "name": name,
                "command_sha256": expected_digest,
                "returncode": 0,
            },
            f"VM runner step did not independently prove success: {name}",
        )

    _require_base_image_binding(primary, envelope)
    subject = _envelope_guest_environment(envelope)
    qualification = primary.get("qualification_environment")
    _require(isinstance(qualification, dict), "VM qualification environment is missing")
    guest = qualification.get("guest_observation")
    _require(isinstance(guest, dict), "VM guest observation is missing")
    for key in ("architecture", "virtualization", "distribution_id", "distribution_version"):
        _require(guest.get(key) == subject.get(key), f"VM guest environment mismatch: {key}")

    binaries = primary.get("binaries")
    _require(isinstance(binaries, dict) and binaries, "VM executable identity evidence is missing")
    for name, binding in binaries.items():
        _require(isinstance(name, str) and isinstance(binding, dict), "VM binary binding is malformed")
        host = binding.get("host_build")
        guest_binding = binding.get("guest_installed")
        _require(binding.get("identity_match") is True, f"VM binary identity did not match: {name}")
        _require(isinstance(host, dict) and guest_binding == host, f"VM installed bytes differ: {name}")
        _require(HEX64.fullmatch(str(host.get("sha256", ""))) is not None, f"VM binary digest invalid: {name}")
        _require(isinstance(host.get("size"), int) and host["size"] > 0, f"VM binary size invalid: {name}")

    return _outcome(
        adapter=f"{lane_id}-semantic-v1",
        test_ids=[test_id],
        contract_ids=[contract_id],
        claims=[
            "scenario-definition-digest-matched",
            "every-scenario-command-returned-zero",
            "guest-environment-matched-execution-envelope",
            "installed-binary-bytes-matched-host-build",
        ],
        environment_verified=_machine_environment_verified(primary, envelope),
        details={"scenario_id": scenario["id"], "step_count": len(observed_steps), "binary_count": len(binaries)},
    )


def _verify_v04_durability(
    root: Path, bundle: Path, primary: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 1, "v0.4 durability schema mismatch")
    _require(primary.get("result") == "passed", "v0.4 durability primary is not a pass")
    _require(primary.get("qualified_boundary", {}).get("hypervisor") == "QEMU TCG",
             "v0.4 durability hypervisor claim mismatch")
    _require_base_image_binding(primary, envelope)
    probe = primary.get("probe")
    _require(
        isinstance(probe, dict) and set(probe) == {"source", "host_executable"},
        "v0.4 durability probe binding is malformed",
    )
    source_binding = probe["source"]
    _require(
        isinstance(source_binding, dict)
        and set(source_binding) == {"path", "sha256", "size"},
        "v0.4 durability probe source binding is malformed",
    )
    source_path = _repo_file(
        root, "crates/linura-persistence-sqlite/examples/v04_fault_probe.rs"
    )
    _require(
        source_binding["path"]
        == "crates/linura-persistence-sqlite/examples/v04_fault_probe.rs"
        and source_binding["sha256"] == _sha256(source_path)
        and source_binding["size"] == source_path.stat().st_size,
        "v0.4 durability probe source identity mismatch",
    )
    executable_binding = probe["host_executable"]
    _require(
        isinstance(executable_binding, dict)
        and set(executable_binding) == {"path", "sha256", "size"}
        and executable_binding["path"] == "v04-fault-probe.bin",
        "v0.4 durability retained executable binding is malformed",
    )
    executable_path = _bundle_file(bundle, executable_binding["path"])
    executable_bytes = _stable_bytes(executable_path)
    _require(
        executable_binding["sha256"] == hashlib.sha256(executable_bytes).hexdigest()
        and executable_binding["size"] == len(executable_bytes),
        "v0.4 durability retained executable identity mismatch",
    )
    witness = _text(_bundle_file(bundle, "durability-verifier.log"))
    _require_markers(
        witness,
        [
            "check=process-indeterminate",
            "check=power-indeterminate",
            "check=power-wal-checkpoint",
            "check=probe-executable-identity",
            "verifier=durability-complete",
        ],
        "v0.4 durability verifier witness",
    )
    _require(witness.count("indeterminate transaction=") >= 4,
             "v0.4 durability witness lacks independently reopened indeterminate states")
    probe_sha = re.search(r"^probe_executable_sha256=([0-9a-f]{64})$", witness, re.MULTILINE)
    probe_size = re.search(r"^probe_executable_size=([0-9]+)$", witness, re.MULTILINE)
    _require(
        probe_sha is not None
        and probe_size is not None
        and probe_sha.group(1) == executable_binding["sha256"]
        and int(probe_size.group(1)) == executable_binding["size"],
        "v0.4 durability guest executable identity mismatch",
    )
    _require("fault probe failed:" not in witness, "v0.4 durability witness contains probe failure")
    return _outcome(
        adapter="v04-durability-semantic-v1",
        test_ids=["qualification/v0.4/durability/result-v1"],
        contract_ids=["qualification/v0.4/durability/v1"],
        claims=[
            "process-kill-state-reopened-indeterminate",
            "power-loss-state-reopened-indeterminate",
            "wal-checkpoint-preserved-indeterminate-state",
            "probe-source-identity-matched",
            "probe-executable-host-guest-bytes-matched",
        ],
        environment_verified=_machine_environment_verified(primary, envelope),
        details={
            "indeterminate_observations": witness.count("indeterminate transaction="),
            "probe_executable_sha256": executable_binding["sha256"],
        },
    )


def _verify_v04_enospc(
    root: Path, bundle: Path, primary: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 1, "v0.4 ENOSPC schema mismatch")
    _require(primary.get("result") == "success", "v0.4 ENOSPC primary is not successful")
    _require_base_image_binding(primary, envelope)
    qualification = _text(_bundle_file(bundle, "enospc-qualification.log"))
    _require_markers(
        qualification,
        [
            "check=reserve-prepared",
            "check=real-enospc-pressure",
            "check=aborted-under-enospc",
            "check=aborted-after-remount",
        ],
        "v0.4 ENOSPC qualification witness",
    )
    reserve_logical = re.search(
        r"^reserve_logical_before_abort_bytes=([0-9]+)$",
        qualification,
        re.MULTILINE,
    )
    reserve_allocated = re.search(
        r"^reserve_allocated_before_abort_bytes=([0-9]+)$",
        qualification,
        re.MULTILINE,
    )
    fill_rc = re.search(r"^filler_exit_code=([0-9]+)$", qualification, re.MULTILINE)
    available_before = re.search(
        r"^available_before_abort_bytes=([0-9]+)$",
        qualification,
        re.MULTILINE,
    )
    reserve_after_qualification = re.search(
        r"^reserve_logical_after_abort_bytes=([0-9]+)$",
        qualification,
        re.MULTILINE,
    )
    _require(
        reserve_logical is not None
        and reserve_allocated is not None
        and int(reserve_logical.group(1)) >= 2 * 1024 * 1024
        and int(reserve_allocated.group(1)) >= int(reserve_logical.group(1)),
        "v0.4 ENOSPC witness does not prove physical recovery reserve",
    )
    _require(
        fill_rc is not None
        and int(fill_rc.group(1)) != 0
        and available_before is not None
        and int(available_before.group(1)) < 262144,
        "v0.4 ENOSPC witness does not prove real pre-retirement exhaustion",
    )
    _require(
        reserve_after_qualification is not None
        and int(reserve_after_qualification.group(1)) == 0,
        "v0.4 ENOSPC qualification did not reconcile the terminal reserve",
    )
    _require(
        qualification.count("aborted-reopen transaction=") >= 2
        and "unexpected terminal snapshot" not in qualification,
        "v0.4 ENOSPC qualification witness lacks durable aborted re-observation",
    )

    witness = _text(_bundle_file(bundle, "enospc-verifier.log"))
    _require_markers(
        witness,
        [
            "check=aborted-after-remount",
            "filesystem=ext4",
            "aborted-reopen transaction=",
            "verifier=enospc-complete",
        ],
        "v0.4 ENOSPC verifier witness",
    )
    filler_allocated = re.search(
        r"^filler_allocated_bytes=([0-9]+)$", witness, re.MULTILINE
    )
    reserve_after = re.search(
        r"^reserve_logical_after_abort_bytes=([0-9]+)$",
        witness,
        re.MULTILINE,
    )
    available_after = re.search(
        r"^available_after_abort_bytes=([0-9]+)$", witness, re.MULTILINE
    )
    _require(
        filler_allocated is not None
        and int(filler_allocated.group(1)) > 0
        and reserve_after is not None
        and int(reserve_after.group(1)) == 0,
        "v0.4 ENOSPC independent witness does not prove retained pressure and reserve reconciliation",
    )
    _require(
        available_after is not None,
        "v0.4 ENOSPC independent witness lacks post-recovery free-space observation",
    )
    _require("unexpected terminal snapshot" not in witness, "v0.4 ENOSPC witness contains terminal-state failure")
    return _outcome(
        adapter="v04-enospc-semantic-v1",
        test_ids=["qualification/v0.4/enospc-recovery/result-v1"],
        contract_ids=["qualification/v0.4/enospc-recovery/v1"],
        claims=[
            "physical-recovery-reserve-existed-before-retirement",
            "real-ext4-enospc-pressure-observed-before-terminal-retirement",
            "prepared-state-retired-under-real-enospc",
            "aborted-state-survived-unmount-remount",
            "terminal-recovery-reserve-reconciled-to-zero",
            "independent-reobservation-retained-filler-allocation",
        ],
        environment_verified=_machine_environment_verified(primary, envelope),
        details={
            "available_before_abort_bytes": int(available_before.group(1)),
            "available_after_abort_bytes": int(available_after.group(1)),
            "reserve_allocated_before_abort_bytes": int(reserve_allocated.group(1)),
            "filler_allocated_after_abort_bytes": int(filler_allocated.group(1)),
        },
    )


def _verify_v05(
    root: Path, bundle: Path, primary: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 1 and primary.get("result") == "passed",
             "v0.5 primary result mismatch")
    _require(primary.get("claim") == "isolated qualification-only systemd executor and independent verifier",
             "v0.5 claim drifted")
    _require(primary.get("managed_mutation_support") == "none" and primary.get("complete_lifecycle") is False,
             "v0.5 support boundary drifted")
    _require_base_image_binding(primary, envelope)
    transcript = _text(_bundle_file(bundle, "qualification.log"))
    markers = [
        "unauthorized-caller=denied",
        "wrong-namespace=rejected-before-dispatch",
        "malformed-binding=rejected-before-dispatch",
        "effect-substitution=rejected-before-dispatch",
        "missing-fixture=indeterminate",
        "dispatch=acknowledged",
        "independent-verification=satisfied",
    ]
    _require_markers(transcript, markers, "v0.5 qualification transcript")
    _require("guest-error " not in transcript, "v0.5 transcript contains guest error")
    pre = re.search(r"pre-active-enter-timestamp-monotonic=([0-9]+)", transcript)
    post = re.search(r"post-active-enter-timestamp-monotonic=([0-9]+)", transcript)
    _require(pre is not None and post is not None and int(post.group(1)) > int(pre.group(1)),
             "v0.5 transcript does not prove a fresh activation")
    artifacts = primary.get("artifacts")
    _require(isinstance(artifacts, dict) and artifacts, "v0.5 repository artifact bindings are missing")
    for name, record in artifacts.items():
        _artifact_digest_record(root, record, f"v0.5 {name}")
    return _outcome(
        adapter="v05-executor-verifier-semantic-v1",
        test_ids=["qualification/v0.5/executor-verifier/result-v1"],
        contract_ids=["qualification/v0.5/executor-verifier/v1"],
        claims=[
            "ordinary-caller-denied",
            "binding-substitution-rejected",
            "qualified-restart-dispatched",
            "fresh-systemd-transition-observed",
            "native-independent-verifier-satisfied",
        ],
        environment_verified=_machine_environment_verified(primary, envelope),
        details={"repository_artifacts": len(artifacts), "activation_delta": int(post.group(1)) - int(pre.group(1))},
    )


def _verify_v06(
    root: Path, bundle: Path, primary: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 1 and primary.get("result") == "passed",
             "v0.6 primary result mismatch")
    _require(primary.get("complete_lifecycle") is True, "v0.6 complete lifecycle was not proven")
    _require(primary.get("managed_mutation_support") == "narrow-experimental",
             "v0.6 managed mutation scope drifted")
    _require_base_image_binding(primary, envelope)
    transcript = _text(_bundle_file(bundle, "qualification.log"))
    matrix = _text(_bundle_file(bundle, "v06-matrix.log"))
    _require_markers(
        transcript,
        [
            "live-contracts=present",
            "sqlite-integrity=ok",
            "real-authority1-success=qualified",
            "real-polkit-denial=qualified",
            "real-direct-executor-denial=qualified",
            "real-idempotency=qualified",
            "real-verification-not-satisfied-explicit-recovery=qualified",
            "real-crash-restart-explicit-no-effect-recovery=qualified",
            "deterministic-fault-matrix=11/11",
        ],
        "v0.6 qualification transcript",
    )
    _require("guest-error " not in transcript, "v0.6 transcript contains guest error")
    _require("test result: ok. 11 passed" in matrix and "FAILED" not in matrix,
             "v0.6 retained fault matrix did not independently pass 11 cases")
    fault_matrix = primary.get("fault_matrix")
    _require(isinstance(fault_matrix, dict) and fault_matrix.get("cases") == 11,
             "v0.6 primary fault-matrix cardinality mismatch")
    artifacts = primary.get("artifacts")
    _require(isinstance(artifacts, dict) and artifacts, "v0.6 repository artifact bindings are missing")
    for name, record in artifacts.items():
        _artifact_digest_record(root, record, f"v0.6 {name}")
    return _outcome(
        adapter="v06-managed-lifecycle-semantic-v1",
        test_ids=["qualification/v0.6/managed-lifecycle/result-v1"],
        contract_ids=["qualification/v0.6/managed-lifecycle/v1"],
        claims=[
            "authority-and-executor-live-contracts-present",
            "policy-denial-and-direct-executor-denial-proved",
            "idempotent-managed-lifecycle-proved",
            "verification-failure-recovery-proved",
            "crash-restart-no-blind-replay-proved",
            "sqlite-integrity-proved",
            "fault-matrix-11-of-11-passed",
        ],
        environment_verified=_machine_environment_verified(primary, envelope),
        details={"fault_matrix_cases": 11, "repository_artifacts": len(artifacts)},
    )


def _verify_v07(
    root: Path, bundle: Path, primary: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 1 and primary.get("result") == "passed",
             "v0.7 primary result mismatch")
    unit = _cargo_log(
        _bundle_file(bundle, "library-unit-tests.txt"),
        "v0.7 Library unit log",
        required_runner_patterns=(r"Running unittests src/lib\.rs \([^\n]*linura_library-",),
    )
    matrix = _cargo_log(
        _bundle_file(bundle, "v07-qualification-tests.txt"),
        "v0.7 qualification matrix log",
        required_runner_patterns=(r"Running tests/v07_qualification\.rs \([^\n]*v07_qualification-",),
    )
    sdk = _cargo_log(
        _bundle_file(bundle, "sdk-tests.txt"),
        "v0.7 SDK log",
        required_runner_patterns=(r"Running unittests src/lib\.rs \([^\n]*linura_sdk-",),
    )
    digest = _text(_bundle_file(bundle, "portable-roundtrip.sha256")).strip()
    _require(HEX64.fullmatch(digest) is not None, "v0.7 portable round-trip digest is invalid")
    _require(primary.get("portable_roundtrip_sha256") == digest, "v0.7 portable digest disagrees with primary")
    crash = _text(_bundle_file(bundle, "process-crash-atomicity.txt")).strip()
    expected_crash = (
        "passed: child was SIGKILLed after the uncommitted history write and before "
        "projection/operation commit; reopen exposed only the old complete state, then an "
        "exact retry committed/replayed the new complete state"
    )
    _require(crash == expected_crash, "v0.7 crash-atomicity witness is not the reviewed proof")
    _require(primary.get("process_crash_atomicity") == crash, "v0.7 primary crash witness mismatch")
    _require(primary.get("database_integrity_after_restart_recovery") == "ok",
             "v0.7 database integrity recovery was not proven")
    _require(primary.get("imported_approval_or_executor_authority") is False,
             "v0.7 imported authority boundary drifted")
    scenarios = primary.get("qualified_scenarios")
    _require(isinstance(scenarios, list) and len(scenarios) == 23, "v0.7 qualified-scenario inventory mismatch")
    _require(all(isinstance(item, dict) and item.get("result") == "passed" and isinstance(item.get("name"), str)
                 for item in scenarios), "v0.7 scenario result is not independently acceptable")
    return _outcome(
        adapter="v07-library-semantic-v1",
        test_ids=["qualification/v0.7/library/result-v1"],
        contract_ids=["qualification/v0.7/library/v1"],
        claims=[
            "library-unit-suite-passed",
            "persistent-qualification-matrix-passed",
            "public-sdk-suite-passed",
            "portable-roundtrip-witness-present",
            "process-crash-atomicity-witness-proved",
            "restart-recovery-integrity-proved",
        ],
        environment_verified=_host_environment_verified(envelope),
        details={
            "qualified_scenarios": len(scenarios),
            "cargo_passed_tests": unit["passed_tests"] + matrix["passed_tests"] + sdk["passed_tests"],
        },
    )


def _verify_v08(
    root: Path, bundle: Path, primary: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 2 and primary.get("result") == "passed",
             "v0.8 primary result mismatch")
    boundary = _text(_bundle_file(bundle, "boundary-check.txt"))
    _require("v0.8 authority-boundary checks passed" in boundary and "ERROR:" not in boundary,
             "v0.8 boundary verifier did not pass")
    logs = {}
    reviewed_runners = {
        "linura-intent-tests.txt": (r"Running unittests src/lib\.rs \([^\n]*linura_intent-",),
        "linura-provider-sdk-tests.txt": (r"Running unittests src/lib\.rs \([^\n]*linura_provider_sdk-",),
        "linura-agent-runtime-tests.txt": (r"Running unittests src/lib\.rs \([^\n]*linura_agent_runtime-",),
        "linura-control-unit-tests.txt": (r"Running unittests src/lib\.rs \([^\n]*linura_control-",),
        "linura-library-unit-tests.txt": (r"Running unittests src/lib\.rs \([^\n]*linura_library-",),
        "v08-integration-tests.txt": (r"Running tests/v08_qualification\.rs \([^\n]*v08_qualification-",),
    }
    for filename, runner_patterns in reviewed_runners.items():
        logs[filename] = _cargo_log(
            _bundle_file(bundle, filename),
            f"v0.8 {filename}",
            required_runner_patterns=runner_patterns,
        )
    for key in (
        "provider_credentials_cross_agent_boundary",
        "agent_can_mint_approval_authority",
        "agent_can_mint_executor_authority",
        "library_acceptance_signing_authority_present",
        "retired_control_token_present",
    ):
        _require(primary.get(key) is False, f"v0.8 forbidden authority claim failed: {key}")
    _require(primary.get("library_acceptance_requires_provisioned_verifier") is True,
             "v0.8 Library verifier provisioning boundary drifted")
    _require(primary.get("control_acceptance_persistent_key_required") is True,
             "v0.8 Control persistent-key boundary drifted")
    source_contracts = primary.get("source_contracts")
    rust_tests = primary.get("rust_tests")
    _require(isinstance(source_contracts, list) and len(source_contracts) == 14
             and all(isinstance(item, dict) and item.get("result") == "passed" for item in source_contracts),
             "v0.8 source-contract inventory mismatch")
    _require(isinstance(rust_tests, list) and len(rust_tests) == 29
             and all(isinstance(item, dict) and item.get("result") == "passed" for item in rust_tests),
             "v0.8 reviewed Rust-test inventory mismatch")
    return _outcome(
        adapter="v08-agent-semantic-v1",
        test_ids=["qualification/v0.8/agent/result-v1"],
        contract_ids=["qualification/v0.8/agent/v1"],
        claims=[
            "authority-boundary-source-checks-passed",
            "intent-provider-agent-control-library-tests-passed",
            "proposal-agent-integration-matrix-passed",
            "agent-cannot-mint-approval-or-executor-authority",
            "library-acceptance-requires-provisioned-verifier",
            "retired-control-token-absent",
        ],
        environment_verified=_host_environment_verified(envelope),
        details={"source_contracts": len(source_contracts), "reviewed_rust_tests": len(rust_tests)},
    )


def _verify_v09(
    root: Path, bundle: Path, primary: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 2 and primary.get("result") == "passed",
             "v0.9 primary result mismatch")
    qualification_environment = primary.get("qualification_environment")
    _require(isinstance(qualification_environment, dict), "v0.9 qualification environment is missing")
    _require(
        qualification_environment.get("id") == "qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless",
        "v0.9 qualification environment id mismatch",
    )
    vm = _json(_bundle_file(bundle, "VM-ACCEPTANCE-EVIDENCE.json"))
    _require(vm.get("schema_version") == 2 and vm.get("repository") == REPOSITORY
             and vm.get("source_sha") == envelope["source"]["commit_sha"]
             and vm.get("result") == "passed", "v0.9 VM evidence is not a valid exact-source pass")
    _require(vm.get("scenario", {}).get("id") == "firstboot-offline", "v0.9 VM scenario mismatch")
    production = vm.get("binaries", {}).get("linura-authorityd")
    _require(isinstance(production, dict) and production.get("identity_match") is True,
             "v0.9 authority runtime identity was not proven")
    _require(production.get("host_build") == production.get("guest_installed"),
             "v0.9 authority runtime host/guest bytes differ")
    adversarial = _json(_bundle_file(bundle, "V09-ADVERSARIAL-EVIDENCE.json"))
    _require(adversarial.get("schema_version") == 1 and adversarial.get("repository") == REPOSITORY
             and adversarial.get("source_sha") == envelope["source"]["commit_sha"]
             and adversarial.get("result") == "passed", "v0.9 adversarial evidence is not an exact-source pass")
    transcript_path = _bundle_file(bundle, "guest-qualification.txt")
    transcript = _text(transcript_path)
    binding = adversarial.get("transcript")
    _require(isinstance(binding, dict)
             and binding.get("path") == transcript_path.name
             and binding.get("sha256") == _sha256(transcript_path)
             and binding.get("size") == transcript_path.stat().st_size,
             "v0.9 adversarial transcript identity mismatch")
    required = [
        "bootstrap_effect_started=durable",
        "bootstrap_producer=linura-firstboot",
        "bootstrap_restart=reobserved",
        "system_restart=persistent-qemu-power-cycle",
        "clone_machine_binding=cross-hardware-rejected",
        "qualification_transport=explicit-out-of-band-ssh",
        "security_baseline=q8-fixture-passed",
        "security_baseline=inbound-default-deny",
        "owner_enrollment=owner-enrollment-pending",
        "preparer_authority_inherited=false",
        "manifest_replay=cross-machine-rejected",
        "manifest_command_field=rejected",
        "q11_migration=real-v08-sqlite-stores",
        "q11_backup_restore=injected-library-failure-restored",
        "q11_update_restart=reobserve-no-blind-replay",
        "q11_package_transaction=dpkg-killed-mid-postinst",
        "q11_package_reconcile=dpkg-configure-authoritative",
        "q11_package_poststate=authoritatively-verified",
        "q11_indeterminate=recovery-required",
        "native_recovery=available_without_firstboot_network_or_model",
    ]
    required.extend(f"prepared_restart_boundary_{index:02d}=persistent-qemu-power-cycle" for index in range(1, 14))
    required.extend(f"restart_boundary_{index:02d}=persistent-qemu-power-cycle" for index in range(1, 14))
    _require_markers(transcript, required, "v0.9 adversarial transcript")
    source_contracts = primary.get("source_contracts")
    _require(isinstance(source_contracts, list) and len(source_contracts) == 12
             and all(isinstance(item, str) and item for item in source_contracts),
             "v0.9 source-contract inventory mismatch")
    return _outcome(
        adapter="v09-qualification-semantic-v1",
        test_ids=["qualification/v0.9/result-v1"],
        contract_ids=["qualification/v0.9/v1"],
        claims=[
            "offline-firstboot-vm-pass-revalidated",
            "production-authority-host-guest-bytes-matched",
            "adversarial-transcript-byte-binding-revalidated",
            "bootstrap-restart-and-machine-binding-adversarial-markers-proved",
            "security-baseline-and-owner-enrollment-markers-proved",
            "migration-update-dpkg-and-native-recovery-markers-proved",
            "all-thirteen-restart-boundaries-proved",
        ],
        environment_verified=_aggregate_environment_verified(
            envelope, "qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless"
        ),
        details={"source_contracts": len(source_contracts), "adversarial_markers": len(required)},
    )


def _verify_v010(
    root: Path, bundle: Path, primary: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    _common_primary(primary, envelope)
    _require(primary.get("schema_version") == 1 and primary.get("result") == "passed",
             "v0.10 shell primary result mismatch")
    contract_path = _repo_file(root, "contracts/v010-shell-runtime-qualification.toml")
    contract = tomllib.loads(_text(contract_path))
    _require(primary.get("claim") == contract["claim"], "v0.10 runtime claim mismatch")
    _require(primary.get("target_profile") == contract["target_profile"], "v0.10 target profile mismatch")
    for field, path_name in (
        ("runtime_contract", "contracts/v010-shell-runtime-qualification.toml"),
        ("substrate_contract", "contracts/v010-shell-runtime-substrate.toml"),
        ("workstation_acceptance_contract", "contracts/v010-workstation-acceptance.toml"),
    ):
        binding = primary.get(field)
        path = _repo_file(root, path_name)
        _require(isinstance(binding, dict) and binding.get("path") == path_name
                 and binding.get("sha256") == _sha256(path),
                 f"v0.10 {field} identity mismatch")
    _require_base_image_binding(primary, envelope)
    cases_text = _text(_bundle_file(bundle, "cases.tsv"))
    observed: dict[str, str] = {}
    for line in cases_text.splitlines():
        parts = line.split("\t", 1)
        _require(len(parts) == 2 and parts[0] not in observed, "v0.10 case transcript is malformed")
        observed[parts[0]] = parts[1]
    _require(set(observed) == set(contract["required_cases"]), "v0.10 required case set mismatch")
    _require(all(value == "passed" for value in observed.values()), "v0.10 runtime case did not pass")
    _require(primary.get("cases") == observed, "v0.10 primary case map disagrees with retained transcript")

    metadata_path = _bundle_file(bundle, "workstation-runtime.metadata.json")
    recording_path = _bundle_file(bundle, "workstation-runtime.mkv")
    digest_path = _bundle_file(bundle, "workstation-runtime.sha256")
    metadata = _json(metadata_path)
    _require(metadata.get("source_sha") == envelope["source"]["commit_sha"], "v0.10 recording source mismatch")
    _require(metadata.get("sha256") == _sha256(recording_path), "v0.10 recording digest mismatch")
    _require(_text(digest_path).strip() == f"{_sha256(recording_path)}  {recording_path.name}",
             "v0.10 recording digest sidecar mismatch")
    recording_binding = primary.get("workstation_recording")
    _require(isinstance(recording_binding, dict)
             and recording_binding.get("sha256") == _sha256(recording_path)
             and recording_binding.get("metadata_sha256") == _sha256(metadata_path)
             and recording_binding.get("scope") == "captured-automated-wayland-session",
             "v0.10 primary recording identity mismatch")

    # Re-run the repository-owned FFV1/Matroska semantic verifier over the
    # retained bytes rather than trusting the workflow-generated metadata.
    from tools import workstation_acceptance
    acceptance_contract = workstation_acceptance.load_contract(
        _repo_file(root, "contracts/v010-workstation-acceptance.toml")
    )
    verified_recording = workstation_acceptance.verify_recording(
        recording_path,
        contract=acceptance_contract,
        source_sha=envelope["source"]["commit_sha"],
    )
    _require(verified_recording.get("sha256") == _sha256(recording_path),
             "v0.10 recording verifier digest mismatch")

    artifacts = primary.get("artifacts")
    _require(isinstance(artifacts, dict) and artifacts, "v0.10 retained artifact bindings are missing")
    for name, binding in artifacts.items():
        _require(isinstance(binding, dict) and set(binding) == {"sha256", "size"},
                 f"v0.10 artifact binding is malformed: {name}")
        path = _bundle_file(bundle, name)
        _require(binding["sha256"] == _sha256(path) and binding["size"] == path.stat().st_size,
                 f"v0.10 artifact bytes disagree with primary: {name}")
    _require(primary.get("release_support_promotion") is False,
             "v0.10 development evidence attempted release promotion")
    return _outcome(
        adapter="v010-shell-runtime-semantic-v1",
        test_ids=["qualification/v0.10/shell-runtime/result-v1"],
        contract_ids=["qualification/v0.10/shell-runtime/v1"],
        claims=[
            "all-reviewed-runtime-cases-passed",
            "runtime-substrate-and-acceptance-contract-digests-matched",
            "retained-artifact-map-revalidated",
            "ffv1-recording-semantically-reverified",
            "recording-source-and-byte-identity-matched",
            "development-evidence-did-not-promote-release-support",
        ],
        environment_verified=_machine_environment_verified(primary, envelope),
        details={"runtime_cases": len(observed), "retained_artifacts": len(artifacts)},
    )


ADAPTER_IDS = {
    "vm-acceptance": "vm-acceptance-semantic-v1",
    "control1-plan-preview-vm": "control1-plan-preview-vm-semantic-v1",
    "v04-durability": "v04-durability-semantic-v1",
    "v04-enospc": "v04-enospc-semantic-v1",
    "v05-executor-verifier": "v05-executor-verifier-semantic-v1",
    "v06-managed-lifecycle": "v06-managed-lifecycle-semantic-v1",
    "v07-library": "v07-library-semantic-v1",
    "v08-agent": "v08-agent-semantic-v1",
    "v09-qualification": "v09-qualification-semantic-v1",
    "v010-shell-runtime": "v010-shell-runtime-semantic-v1",
}


def verify_retained_evidence(
    *,
    root: Path,
    lane_id: str,
    bundle: Path,
    primary: dict[str, Any],
    envelope: dict[str, Any],
) -> dict[str, Any]:
    if lane_id == "vm-acceptance":
        return _verify_vm(
            root, lane_id, bundle, primary, envelope,
            required_scenario=None,
            test_id="qualification/vm-acceptance/result-v1",
            contract_id="qualification/vm-acceptance/v1",
        )
    if lane_id == "control1-plan-preview-vm":
        return _verify_vm(
            root, lane_id, bundle, primary, envelope,
            required_scenario="control1-plan-preview",
            test_id="qualification/control1-plan-preview/result-v1",
            contract_id="qualification/control1-plan-preview/v1",
        )
    if lane_id == "v04-durability":
        return _verify_v04_durability(root, bundle, primary, envelope)
    if lane_id == "v04-enospc":
        return _verify_v04_enospc(root, bundle, primary, envelope)
    if lane_id == "v05-executor-verifier":
        return _verify_v05(root, bundle, primary, envelope)
    if lane_id == "v06-managed-lifecycle":
        return _verify_v06(root, bundle, primary, envelope)
    if lane_id == "v07-library":
        return _verify_v07(root, bundle, primary, envelope)
    if lane_id == "v08-agent":
        return _verify_v08(root, bundle, primary, envelope)
    if lane_id == "v09-qualification":
        return _verify_v09(root, bundle, primary, envelope)
    if lane_id == "v010-shell-runtime":
        return _verify_v010(root, bundle, primary, envelope)
    raise VerificationError(f"no reviewed semantic verifier adapter for lane: {lane_id}")
