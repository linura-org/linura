# Security Policy

Linura changes operating-system state and accepts untrusted model/user/imported configuration input. Security is a product requirement, not a later hardening phase.

## Supported versions

No production-supported version exists yet. Security fixes apply to the active development branch until a supported release line is declared.

## Security invariants

1. **Agents propose; Linura authorizes.** Model output can become an `IntentProposal`; it never becomes execution authority.
2. **Approved structured intent is durable.** Conversation/model text is not authoritative configuration.
3. **Semantic provenance is required.** Managed state must retain a trustworthy why-chain to approved intent/requirements/capabilities.
4. **No root monolith.** `linurad` runs unprivileged; privileged effects use narrow executors.
5. **No generic privileged shell.** Public/agent APIs cannot execute arbitrary elevated command text.
6. **Explicit actors and grants.** Human/service/agent identity and scope are authenticated and policy-evaluated.
7. **Deny by default.** Unknown actors, capabilities, resources, policy states and unsupported observations cannot mutate the machine.
8. **Plan before apply.** Material effects, risk, reversibility and verification are inspectable before privilege.
9. **Verify after apply.** Success requires authoritative postcondition evidence.
10. **Prepare before managed external effects.** Supported `ManagedExternalEffect` paths durably record intent-to-execute before dispatch and recover indeterminate operations by re-observation rather than blind replay. A qualified `TransientExternalEffect` is deliberately exempt from durable prepare only while it remains unprivileged, no higher than `UserState` risk, non-durable desired state, independently verifiable/auditable, and bounded so failure does not require durable indeterminate recovery; otherwise it is promoted to `ManagedExternalEffect` or remains unsupported.
11. **Safe retirement.** Removing intent performs dependency/shared-ownership analysis before cleanup.
12. **No secret argv or general model-context leakage.** Secrets use protected handles/channels and are minimized/redacted.
13. **No unsandboxed extension/generated code in authority processes.** Derived UI is constrained; custom extensions are isolated.
14. **Agent-native is not agent-dependent.** Deterministic offline control/recovery remains available if model providers fail or are compromised.
15. **Least privilege.** Each privileged executor exposes only a narrow typed method set with minimum OS access.
16. **Portable artifacts are secret-free.** Reusable setups and machine profiles may contain credential/secret references, never secret values, private keys or bearer tokens.
17. **Imported/synchronized setups are untrusted.** A setup/profile carries no authority grant and can only affect the machine after local validation, observation, capability resolution, fresh planning, policy/approval and the canonical mutation lifecycle.
18. **Snapshots are not portable policy.** Exact recovery snapshots remain machine-specific recovery artifacts and never substitute for validated setup/profile adoption.

## Reporting a vulnerability

Do not open a public issue for suspected vulnerabilities. Use GitHub private vulnerability reporting when hosted, or the security contact published by the project owner.

Include the affected version/commit, component/trust boundary, reproduction/PoC, impact, required attacker access and suggested mitigation if known.

## Security-review triggers

A pull request requires a threat-model update or explicit “no threat-model impact” rationale when it changes:
- intent/provenance trust semantics;
- reusable setup/profile/Library import, export, synchronization or signature semantics;
- agent/provider/context boundaries;
- authentication/actor identity or grants;
- policy/approval evaluation;
- privileged executor interfaces;
- D-Bus/remote exposure;
- persistence/audit formats;
- dependency/conflict solver semantics;
- capability/workflow/extension loading;
- generated/derived UI authority;
- package/update/release verification;
- secret handling.

## Install, update, setup adoption and recovery baseline

The first supported Linura OS profile is fail-closed by design: encrypted supported installs, inbound firewall deny-by-default, SSH initially disabled, and untrusted package sources disabled until explicitly enabled. The agent/model layer is never a recovery dependency.

Linura coordinates system upgrades so snapshot, migrations, reconciliation, and verification cannot be silently skipped. An Arch ALPM guard represents this policy for the initial profile. Administrators retain an explicit break-glass native recovery path (`LINURA_ALLOW_DIRECT_PACMAN=1`) because a broken Linura control plane must not make the host unrecoverable.

Portable setup/profile adoption is also fail-closed: unsupported requirements, missing required secret references, invalid/cyclic setup composition or ambiguous target capability resolution block mutation until resolved. Imported artifacts do not execute historical commands.

Hardware fixtures and acceptance evidence must be sanitized. Never commit serial numbers, MAC addresses, private account identifiers, raw credentials, portable exports containing secret values, or raw diagnostic archives containing user data.
