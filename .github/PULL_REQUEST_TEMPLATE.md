## Summary

## Why

## Architecture / trust-boundary impact
- [ ] No impact
- [ ] Contract/API change
- [ ] Security-sensitive change
- [ ] Privileged executor change
- [ ] Persistence/migration/recovery change
- [ ] Release-control/supply-chain change

Explain if checked:

## Regression impact
- Existing consumers, tests and fixtures affected by the change:
- Old assertions changed (with rationale), or none:
- Positive, failure/denial and adversarial coverage added or preserved:

## Internal review
- [ ] Reviewed existing consumers, tests and regression assumptions before changing behavior
- [ ] Architecture, ownership and public-contract review complete (or not applicable with reason)
- [ ] Code, security/trust-boundary and adversarial review complete (or not applicable with reason)
- [ ] All valid internal findings resolved; no tests or gates weakened to clear failures

## Applicable qualification
- Required native PR gates: canonical CI, Security (fresh cargo-audit), CodeQL
- Specialized gates required by change impact, or none with rationale:
- Exact-head results/evidence; record unavailable or incomplete gates as blocked:

## Verification

## Migration / rollback

## Release traceability
- [ ] Not release-note worthy
- [ ] `CHANGELOG.md` updated
- [ ] Target milestone/release contract updated when applicable
- [ ] Security/migration/recovery/release-control changes have an immutable commit reference plan when useful

Release contracts use the final PR URL as human provenance after the PR number exists. PR/commit references do not replace acceptance evidence.

The [canonical review sequence](../docs/development-infrastructure.md#pull-request-qualification-sequence) requires one clean commit and green applicable exact-head gates before final Codex review. Complete pending review items before marking the PR ready; checkboxes are attestations, not independently verified evidence.

## Checklist
- [ ] Change compacted into one clean commit after internal review
- [ ] All applicable checks passed on the final exact head; no stale-source pass substituted
- [ ] Final Codex review requested only after internal review and green gates; new findings addressed and revalidated
- [ ] I have the right to submit this contribution under the project's Apache-2.0 inbound contribution policy
- [ ] Tests cover negative/failure paths
- [ ] Docs/ADR/RFC updated as needed
- [ ] No secrets/logging regressions
- [ ] No new generic privileged command execution
- [ ] Claim/support language does not exceed proven evidence
