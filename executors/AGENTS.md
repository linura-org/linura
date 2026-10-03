# Privileged effectors

Root `AGENTS.md` remains applicable. Paths below are relative to the repository root.

- Read `agents/skills/privileged-executors.md`, `agents/skills/security-review.md`, `docs/security-model.md` and applicable authority ADRs from the repository root.
- Keep effectors narrow. Do not accept arbitrary argv, shell evaluation, model-selected principals or reusable privileged grants.
- Test denial, stale identity/authorization, bounded input, crashes, ambiguous outcomes and recovery before the full canonical gate.
