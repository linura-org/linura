# Contributing

Linura welcomes focused contributions while keeping its authority, security, recovery, and release boundaries explicit. The amount of architecture you need to read depends on the kind of change you are making.

## First contribution

For a documentation fix, focused test improvement, contained Rust change, or other change that does not alter a public contract or trust boundary:

```bash
git clone https://github.com/linura-org/linura.git
cd linura
cargo xtask check
```

Then:

1. choose an issue labeled `good first issue` or `help wanted`, or open a narrowly scoped issue if none fits;
2. keep the change atomic;
3. run `cargo xtask check`;
4. add or update tests when behavior changes;
5. open a pull request using the repository template.

You do **not** need to read every architecture document before fixing a typo, improving a test, or making a routine internal change. If the change expands in scope, follow the deeper contribution path below.

Codex contributors should also follow [Codex development](docs/codex-development.md) for environment preparation, capability diagnostics and task commands.

Useful discovery commands:

```bash
cargo xtask acceptance-list
python3 tools/vm.py doctor
python3 tools/image.py doctor
python3 tools/visual.py list
```

See [`docs/community/labels.md`](docs/community/labels.md) for the contributor-facing label taxonomy and [`SUPPORT.md`](SUPPORT.md) for where questions, bugs, compatibility reports, and security reports belong.

## Architecture and security contribution

Before changing authority, security, public contracts, persistence, recovery, supported platform behavior, release control, or other system-wide semantics, read:

1. [`README.md`](README.md)
2. [`AGENTS.md`](AGENTS.md)
3. [`docs/product-vision.md`](docs/product-vision.md)
4. [`docs/vision-coverage.md`](docs/vision-coverage.md)
5. [`docs/architecture.md`](docs/architecture.md)
6. [`docs/security-model.md`](docs/security-model.md)
7. relevant [ADRs](docs/adr) and domain documentation
8. [`docs/rfcs/README.md`](docs/rfcs/README.md) when broader design discussion is required

This deeper path is mandatory when a change can alter what Linura treats as authoritative, what an actor may mutate, what evidence is sufficient, what is persisted, what a release claims, or how recovery works.

## Change classes

- **Routine:** internal implementation with no contract or trust-boundary change.
- **Domain/contract:** intent, graph, capability, desired state, protocol, schemas, public SDK, provider interfaces, or compatibility semantics.
- **Security-sensitive:** agent boundaries, provenance, policy, identity, privileged execution, solver constraints, secrets, remote access, extensions, derived UI, or supply-chain authority.
- **Architectural:** persistence, process/trust boundaries, major dependencies, platform/support guarantees, lifecycle ordering, or release-control semantics.

Domain, security-sensitive, and architectural changes require an ADR/RFC when an accepted decision does not already cover them. See [`docs/rfcs/README.md`](docs/rfcs/README.md) and [`docs/adr/README.md`](docs/adr/README.md).

Accepted ADRs are append-only historical records. Do not silently rewrite an accepted architectural decision to match newer code. A materially changed decision must be recorded in a new ADR that refines or supersedes the earlier record.

## Regression-impact and internal review

Perform a regression-impact review before changing behavior, a contract, CI routing or qualification semantics: search existing
consumers, callers, tests, fixtures and documentation for assumptions about the old behavior.
Record the affected assertions and distinguish deliberately changed expectations from regressions.
Update justified expectations and add positive, negative and adversarial tests in the same change;
never remove a failing test simply to obtain a green result. A typo-only change does not require
a heavyweight architecture review.

Before final validation, review the completed change for architecture and ownership, code and
API compatibility, trust boundaries and failure/recovery behavior, regression impact and
applicable qualification gates. Complete the concise **Regression impact** and **Internal review**
sections of the PR template; mark anything unfinished as pending rather than claiming it passed.
The canonical sequence and exact-head rules are in
[Pull-request qualification sequence](docs/development-infrastructure.md#pull-request-qualification-sequence).
These human review attestations supplement but cannot replace tests or independent evidence.

## Development quality gate

Run:

```bash
cargo xtask check
```

before opening a pull request. It is the canonical local entry point for the same primary repository checks used by CI.

New managed mutation behavior must test allow/deny, unsupported capability, executor failure, verification failure, provenance origin, and retry/idempotency semantics.

New intent/capability behavior must test dependency/conflict resolution, shared ownership/removal impact, and deterministic explanation.

New agent behavior must test malicious proposals/prompt injection, provider outage/offline behavior, and prove that no direct executor authority is introduced.

For system changes, also run the relevant task guide and disposable-machine evidence from [`agents/skills/`](agents/skills) and [`tests/acceptance/`](tests/acceptance).

## Pull requests

Keep changes atomic and explain:

- user intent/problem and scope;
- graph/provenance consequences;
- architecture/trust-boundary impact;
- ADR/RFC impact (new, refined/superseded, or explicitly none);
- tests/evidence;
- migration/rollback/recovery impact;
- release-note impact.

Do not mix unrelated refactors with privileged or trust-boundary changes. Resolve review conversations rather than hiding disagreement in follow-up commits. Keep a PR in draft until internal review is complete, its work is compacted into one coherent commit and all applicable exact-head checks succeed; request Codex review only then. Address genuinely new findings, recompact and revalidate the new head before a green-only authorized merge. Routine progress belongs in the commits and checks, not repetitive PR comments.

Security vulnerabilities must not be disclosed in a public pull request before coordinated handling under [`SECURITY.md`](SECURITY.md).

## Contribution licensing

Linura is licensed under the Apache License 2.0. Unless a contributor explicitly states otherwise before submission, contributions intentionally submitted for inclusion in Linura are provided under the same Apache-2.0 terms, consistent with Section 5 of the license.

By submitting a contribution, you represent that you have the right to submit it under those terms and that it does not knowingly include material that you are not permitted to contribute.

Linura does not currently require a separate Contributor License Agreement. Any future change to contributor licensing must be made explicitly through governance and must not be applied retroactively without a lawful basis.

## Conduct and community

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Use GitHub Discussions for questions, design exploration, and community conversation; use Issues for actionable tracked work. The routing model is documented in [`SUPPORT.md`](SUPPORT.md).

Sponsorship never grants technical, security, release, or governance authority. See [`docs/community/sponsorship.md`](docs/community/sponsorship.md).
