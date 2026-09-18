# Policy task guide

Policy decides whether an exact validated canonical reconciliation plan may enter or satisfy authority review. It does not create execution authority.

- Derive `PolicySubject` from `linura-planner::ReconciliationPlan` plus the transport-authenticated principal; do not accept a client-authored executable plan model.
- Treat `Actor` as request provenance and authenticated principal as authority identity; never substitute one for the other.
- Policy outcomes are typed and fail closed: allow, deny, require-approval, or blocked.
- Bind evaluation/approval to the exact principal, request/plan, authoritative evidence, provider/resource/capability, material plan content/provenance, and policy revision.
- `PlanId` alone is not sufficient approval authority.
- Agent identity never implies elevated authority and an agent cannot satisfy its own protected human/admin approval requirement.
- Security-sensitive, destructive, exposure-changing, and credential-affecting changes require explicit policy treatment.
- Keep `RiskClass` orthogonal to `OperationClass`. Policy/risk may increase ceremony or force promotion to the managed-effect path, but a caller/provider/model cannot use risk metadata to select a weaker operation class. Transient external effects may not exceed trusted `UserState` risk.
- Approval surfaces must describe the canonical typed planned changes/findings and authoritative evidence, not only an agent's prose summary.
- Expired, revoked, wrong-principal, wrong-plan, stale-evidence, wrong-policy-revision and wrong-approver evidence fail closed.
- Policy `allow`, valid approval, and reviewed-plan status are not executor credentials and may not bypass durable `prepare` in later milestones.
- Add deny/blocked/replay/substitution tests before allow-path convenience.
- Any policy/approval contract change requires threat-model review under `SECURITY.md`.
