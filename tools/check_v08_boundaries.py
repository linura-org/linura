#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import sys


def fail(message: str, failures: list[str]) -> None:
    failures.append(message)


def require(text: str, marker: str, label: str, failures: list[str]) -> None:
    if marker not in text:
        fail(f"{label} missing required marker: {marker}", failures)


def forbid(text: str, marker: str, label: str, failures: list[str]) -> None:
    if marker in text:
        fail(f"{label} contains forbidden marker: {marker}", failures)


def rust_code_without_line_comments(text: str) -> str:
    """Remove Rust line/doc-comment lines before executable API marker checks."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("//")
    )


def validate_schema(root: Path, failures: list[str]) -> None:
    path = root / "schemas/intent-proposal.v1.schema.json"
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"intent proposal schema is not readable strict JSON: {error}", failures)
        return

    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("intent proposal schema must use JSON Schema draft 2020-12", failures)
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        fail("intent proposal schema root must be a closed object", failures)
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        fail("intent proposal schema properties are missing", failures)
        return
    if properties.get("schema_version") != {"const": 1}:
        fail("intent proposal schema_version must be exactly v1", failures)

    canonical_fields = {
        "schema_version",
        "proposal_id",
        "actor",
        "requested_outcome",
        "requirements",
        "capability_refs",
        "assumptions",
        "unresolved_questions",
        "confidence",
        "context",
        "attribution",
        "explanation",
        "canonical_digest",
    }
    if set(properties) != canonical_fields:
        fail(
            "intent proposal schema field set drifted from the canonical proposal-only contract",
            failures,
        )
    required = schema.get("required")
    if not isinstance(required, list):
        fail("intent proposal schema required field list is missing", failures)
    elif set(required) != canonical_fields - {"confidence"}:
        fail("intent proposal required field set drifted", failures)

    forbidden_authority_terms = {
        "approved",
        "approval",
        "authorized",
        "authorization",
        "policy_decision",
        "policy_result",
        "executor",
        "execution",
        "mutation",
        "permit",
        "dispatch",
        "apply",
    }
    if {field.lower() for field in properties} & forbidden_authority_terms:
        fail("intent proposal schema contains authority-bearing fields", failures)
    if schema.get("x-linura-authority") != "proposal-only":
        fail("intent proposal schema must declare proposal-only authority", failures)

    for object_field in ("actor", "context", "attribution"):
        child = properties.get(object_field)
        if not isinstance(child, dict) or child.get("additionalProperties") is not False:
            fail(f"intent proposal {object_field} schema must be a closed object", failures)


def validate(root: Path) -> list[str]:
    failures: list[str] = []

    root_toml = (root / "Cargo.toml").read_text(encoding="utf-8")
    cargo_lock = (root / "Cargo.lock").read_text(encoding="utf-8")
    layering = (root / "contracts/layering.toml").read_text(encoding="utf-8")
    components = (root / "contracts/components.toml").read_text(encoding="utf-8")
    control_lib = (root / "crates/linura-control/src/lib.rs").read_text(encoding="utf-8")
    internal_engine = (root / "crates/linura-control/src/agent_interpretation.rs").read_text(
        encoding="utf-8"
    )
    secure_engine = (root / "crates/linura-control/src/secure_agent_interpretation.rs").read_text(
        encoding="utf-8"
    )
    secure_engine_code = rust_code_without_line_comments(secure_engine)
    control_acceptance = (
        root / "crates/linura-control/src/proposal_acceptance_secure.rs"
    ).read_text(encoding="utf-8")
    control_acceptance_code = rust_code_without_line_comments(control_acceptance)
    secure_acceptance = (
        root / "crates/linura-control/src/secure_proposal_acceptance.rs"
    ).read_text(encoding="utf-8")
    secure_acceptance_code = rust_code_without_line_comments(secure_acceptance)
    capabilityless = (
        root / "crates/linura-provider-sdk/src/capabilityless_adapter.rs"
    ).read_text(encoding="utf-8")
    provider_interpretation = (
        root / "crates/linura-provider-sdk/src/interpretation.rs"
    ).read_text(encoding="utf-8")
    library_lib = (root / "crates/linura-library/src/lib.rs").read_text(encoding="utf-8")
    library_acceptance = (
        root / "crates/linura-library/src/proposal_acceptance_secure.rs"
    ).read_text(encoding="utf-8")
    library_acceptance_code = rust_code_without_line_comments(library_acceptance)
    transaction = (root / "crates/linura-transaction/src/lib.rs").read_text(encoding="utf-8")
    control_toml = (root / "crates/linura-control/Cargo.toml").read_text(encoding="utf-8")
    library_toml = (root / "crates/linura-library/Cargo.toml").read_text(encoding="utf-8")

    require(
        control_lib,
        '#[path = "proposal_acceptance_secure.rs"]',
        "Control acceptance module routing",
        failures,
    )
    require(
        library_lib,
        '#[path = "proposal_acceptance_secure.rs"]',
        "Library acceptance module routing",
        failures,
    )
    require(
        control_lib,
        "pub use secure_agent_interpretation::{AdapterHealth, ControlInterpretationEngine};",
        "Control public interpretation surface",
        failures,
    )
    if re.search(
        r"pub\s+use\s+agent_interpretation::\{[^}]*ControlInterpretationEngine",
        control_lib,
        re.DOTALL,
    ):
        fail("generic interpretation engine is publicly re-exported", failures)
    for marker in ("ProposalAcceptanceAuthoritySource", "ProposalAcceptanceAuthorityGuard"):
        forbid(control_lib, marker, "Control public API", failures)

    require(
        secure_engine_code,
        "adapter: CapabilitylessInterpretationAdapter",
        "secure interpretation registration",
        failures,
    )
    forbid(
        secure_engine_code,
        "adapter: Box<dyn InterpretationAdapter>",
        "secure interpretation registration",
        failures,
    )
    require(
        secure_engine_code,
        "pub fn adapter_health(&self, adapter_id: &str, offline: bool) -> AdapterHealth",
        "metadata-only adapter health surface",
        failures,
    )

    for marker in (
        "std::net",
        "std::process",
        "std::fs",
        "std::env",
        "std::os::unix::process",
        "unsafe {",
        'extern "C"',
    ):
        forbid(capabilityless, marker, "capabilityless adapter implementation", failures)
    require(
        capabilityless,
        "pub struct CapabilitylessInterpretationAdapter",
        "capabilityless adapter implementation",
        failures,
    )
    require(
        capabilityless,
        "PreparedProviderInvocation::new",
        "capabilityless adapter implementation",
        failures,
    )

    permit_match = re.search(
        r"#\[derive\((?P<derive>[^)]*)\)\]\s*pub struct ProviderInvocationPermit\s*\{(?P<body>.*?)\n\}",
        internal_engine,
        re.DOTALL,
    )
    if permit_match is None:
        fail("provider invocation permit declaration is missing", failures)
    else:
        derives = {item.strip() for item in permit_match.group("derive").split(",")}
        if derives != {"Debug"}:
            fail(
                "provider invocation permit must remain Debug-only and non-clone/non-serializable",
                failures,
            )
        if re.search(r"\bpub\s+", permit_match.group("body")):
            fail("provider invocation permit fields must remain private", failures)

    gate_markers = (
        "permit.authority_id != self.authority_id",
        "permit.request_digest != request.digest()",
        "permit.prepared_digest != prepared.digest()",
        "permit.adapter_id != prepared.adapter_id",
        "permit.provider != prepared.provider",
        "permit.endpoint_class != prepared.endpoint_class",
        "permit.protocol_version != prepared.protocol_version",
        "permit.network_access != prepared.network_access",
        "permit.deadline_unix_ms != request.attempt_deadline_unix_ms",
        "permit.output_budget_bytes != request.max_response_bytes",
        "deadline.deadline_unix_ms() != permit.deadline_unix_ms",
        "if now_unix_ms >= permit.deadline_unix_ms",
        "if self.consumed_permits.contains(&permit.nonce)",
        "self.consumed_permits.insert(permit.nonce);",
        "registered.transport.invoke_once(prepared, deadline)",
    )
    for marker in gate_markers:
        require(internal_engine, marker, "provider invocation gate", failures)
    consume_at = internal_engine.find("self.consumed_permits.insert(permit.nonce);")
    transport_at = internal_engine.find("registered.transport.invoke_once(prepared, deadline)")
    if consume_at < 0 or transport_at < 0 or consume_at >= transport_at:
        fail("provider invocation permit must be consumed before transport invocation", failures)

    for marker in (
        "struct AttemptDeadline",
        "started: Instant",
        "self.started.elapsed().as_millis()",
        "deadline.ensure_live()?;",
        "deadline.transport_deadline()?",
        "ProviderInvocationDeadline::new(self.deadline_unix_ms, self.remaining_ms()?)",
    ):
        require(internal_engine, marker, "cumulative provider attempt deadline", failures)
    if internal_engine.count("deadline.ensure_live()?;") < 3:
        fail(
            "provider attempt deadline must be rechecked across preparation, transport, and decode",
            failures,
        )

    require(
        provider_interpretation,
        "pub struct ProviderInvocationDeadline",
        "provider deadline contract",
        failures,
    )
    require(
        provider_interpretation,
        "deadline: ProviderInvocationDeadline",
        "provider transport deadline",
        failures,
    )
    transport_match = re.search(
        r"pub trait ProviderInvocationTransport: Send\s*\{(?P<body>.*?)\n\}",
        provider_interpretation,
        re.DOTALL,
    )
    if transport_match is None:
        fail("trusted provider transport trait is missing", failures)
    else:
        body = transport_match.group("body")
        if re.findall(r"\bfn\s+([A-Za-z0-9_]+)\s*\(", body) != ["invoke_once"]:
            fail("trusted provider transport must expose exactly one invocation method", failures)
        for forbidden_name in ("retry", "resume", "reconnect", "redirect", "reissue"):
            if forbidden_name in body.lower():
                fail(
                    f"trusted provider transport exposes forbidden repeat primitive: {forbidden_name}",
                    failures,
                )

    for marker in (
        "TransactionAuthoritySigner",
        "signer: TransactionAuthoritySigner",
        "TransactionAuthorityKey",
        "from_authority_key(key: TransactionAuthorityKey)",
        "let (signer, verifier) = key.split();",
        ".signing_challenge(&material, time_seal)",
        ".authorize_handoff(",
        ".bind_signed_handoff(&self.library_authority, challenge, handoff)",
    ):
        require(control_acceptance_code, marker, "Control acceptance signing authority", failures)

    for marker in (
        "authority: &mut ControlProposalAuthority",
        "clock: &mut ControlAuthorityClock",
        "from_authority_key(key: TransactionAuthorityKey)",
        "pub fn provision_library(",
    ):
        require(secure_acceptance_code, marker, "secure proposal acceptance facade", failures)
    forbid(
        secure_acceptance_code,
        "ProposalAcceptanceAuthoritySource",
        "secure proposal acceptance facade",
        failures,
    )
    forbid(
        secure_acceptance_code,
        "impl Default for ProposalAcceptanceControl",
        "secure proposal acceptance facade",
        failures,
    )
    if re.search(r"pub\s+fn\s+new\s*\(\s*\)", secure_acceptance_code):
        fail("production proposal acceptance must not mint ephemeral authority", failures)

    for marker in (
        "TransactionAuthorityVerifier",
        "verifier: TransactionAuthorityVerifier",
        "AuthorityNotProvisioned",
        "pub fn provision(",
        "require_authority_binding(&library.connection, &self.verifier)?;",
        "pub struct AcceptanceSigningChallenge",
        "pub fn signing_challenge(",
        "pub fn bind_signed_handoff(",
        "self.verifier.verify_handoff(handoff)",
        "handoff.transaction_id() == &challenge.snapshot.transaction_id",
        "handoff.expected_generation() == challenge.snapshot.current_generation",
        "handoff.expected_state_version() == challenge.snapshot.state_version",
        "handoff.expected_binding_digest() == &challenge.snapshot.binding_digest",
        "handoff.authority_use_digest() == &challenge.authority_use_digest",
        "handoff.authorized_at_unix_ms() == challenge.time_seal.time_floor_unix_ms",
        "handoff.expires_at_unix_ms() == challenge.time_seal.exclusive_deadline_unix_ms",
    ):
        require(library_acceptance_code, marker, "Library acceptance verifier", failures)
    for forbidden in (
        "TransactionAuthoritySigner",
        "TransactionAuthorityKey",
        "bind_or_verify_authority",
        "ProposalAcceptanceControlToken",
        "from_control_token",
    ):
        forbid(library_acceptance_code, forbidden, "Library acceptance verifier", failures)

    begin_at = library_acceptance_code.find("pub fn begin<'a>(")
    binding_at = library_acceptance_code.find(
        "require_authority_binding(&library.connection, &self.verifier)?;",
        begin_at,
    )
    transaction_at = library_acceptance_code.find("transaction_with_behavior", begin_at)
    if begin_at < 0 or binding_at < 0 or transaction_at < 0 or binding_at >= transaction_at:
        fail("Library begin must verify provisioned authority before opening acceptance transaction", failures)

    validate_target_at = control_acceptance_code.find("validate_target_under_library_guard")
    challenge_at = control_acceptance_code.find(".signing_challenge(&material, time_seal)")
    sign_at = control_acceptance_code.find(".authorize_handoff(", challenge_at)
    bind_at = control_acceptance_code.find(
        ".bind_signed_handoff(&self.library_authority, challenge, handoff)", sign_at
    )
    if min(validate_target_at, challenge_at, sign_at, bind_at) < 0 or not (
        validate_target_at < challenge_at < sign_at < bind_at
    ):
        fail(
            "Control must final-check target, create challenge, sign, then bind proof in that order",
            failures,
        )

    for marker in (
        "pub struct TransactionAuthorityKey",
        "pub struct TransactionAuthoritySigner",
        "pub struct TransactionAuthorityVerifier",
        '"linura.transaction-authority.handoff.v1"',
        "verify_handoff",
        "zeroize",
    ):
        require(transaction, marker, "sealed transaction authority primitive", failures)

    for text, label in (
        (root_toml, "workspace manifest"),
        (cargo_lock, "Cargo lockfile"),
        (control_toml, "Control manifest"),
        (library_toml, "Library manifest"),
        (layering, "layering contract"),
        (components, "component registry"),
    ):
        forbid(text, "linura-control-token", label, failures)
        forbid(text, "control-internal", label, failures)
    if (root / "crates/linura-control-token").exists():
        fail("obsolete linura-control-token crate still exists", failures)
    require(
        library_toml,
        'linura-transaction = { path = "../linura-transaction" }',
        "Library verifier dependency",
        failures,
    )
    require(
        control_toml,
        'linura-transaction = { path = "../linura-transaction" }',
        "Control signer dependency",
        failures,
    )

    library_rule = re.search(
        r'\[\[rules\]\]\s*package\s*=\s*"linura-library"(?P<body>.*?)(?=\n\[\[rules\]\]|\n\[\[markers\]\]|\Z)',
        layering,
        re.DOTALL,
    )
    if library_rule is None:
        fail("layering contract is missing linura-library rule", failures)
    elif '"linura-transaction"' in library_rule.group("body"):
        fail("layering contract still forbids Library verifier dependency", failures)

    if re.search(r'(?m)^id\s*=\s*"linura-control-token"\s*$', components):
        fail("component registry still declares retired linura-control-token", failures)

    for manifest in root.rglob("Cargo.toml"):
        manifest_text = manifest.read_text(encoding="utf-8")
        if "linura-control-token" in manifest_text or "control-internal" in manifest_text:
            fail(
                f"obsolete v0.8 authority mechanism remains in {manifest.relative_to(root)}",
                failures,
            )

    provider_sdk_toml = (root / "crates/linura-provider-sdk/Cargo.toml").read_text(
        encoding="utf-8"
    )
    agent_runtime_toml = (root / "crates/linura-agent-runtime/Cargo.toml").read_text(
        encoding="utf-8"
    )
    forbid(agent_runtime_toml, "linura-provider-sdk", "agent runtime dependency graph", failures)
    forbid(agent_runtime_toml, "linura-library", "agent runtime dependency graph", failures)
    require(provider_sdk_toml, "linura-intent", "provider SDK proposal contract", failures)

    validate_schema(root, failures)
    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("v0.8 authority-boundary checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
