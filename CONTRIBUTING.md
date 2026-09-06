# Contributing

## Before coding

Read, in order:
1. [`README.md`](README.md)
2. [`AGENTS.md`](AGENTS.md)
3. [`docs/product-vision.md`](docs/product-vision.md)
4. [`docs/vision-coverage.md`](docs/vision-coverage.md)
5. [`docs/architecture.md`](docs/architecture.md)
6. [`docs/security-model.md`](docs/security-model.md)
7. relevant [ADRs](docs/adr)/[domain docs](docs)

## Change classes

- **Routine:** internal implementation with no contract/trust change.
- **Domain/contract:** intent, graph, capability, desired state, protocol, schemas or provider interfaces.
- **Security-sensitive:** agent boundaries, provenance, policy, identity, privileged execution, solver constraints, secrets, remote access, extensions/derived UI.
- **Architectural:** persistence, process/trust boundaries, major dependencies, platform/support guarantees.

Domain/security/architectural changes require an ADR/RFC when an accepted decision does not already cover them.

Accepted ADRs are append-only historical records. Do not silently rewrite an accepted architectural decision to match newer code. A materially changed decision must be recorded in a new ADR that refines or supersedes the earlier record, and [`docs/adr/README.md`](docs/adr/README.md) must remain a complete, uniquely numbered ledger.

## Development quality gate

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 scripts/check_repository.py
python3 tools/check_adrs.py
```

New managed mutation behavior must test allow/deny, unsupported capability, executor failure, verification failure, provenance origin and retry/idempotency semantics.

New intent/capability behavior must test dependency/conflict resolution, shared ownership/removal impact and deterministic explanation.

New agent behavior must test malicious proposals/prompt injection, provider outage/offline behavior and prove that no direct executor authority is introduced.

## Pull requests

Keep changes atomic. Explain:
- user intent/problem and scope;
- graph/provenance consequences;
- architecture/trust-boundary impact;
- ADR impact (new, refined/superseded, or explicitly none);
- tests/evidence;
- migration/rollback/recovery impact;
- release-note impact.

Do not mix unrelated refactors with privileged or trust-boundary changes.

## Canonical development command

Run:

```bash
cargo xtask check
```

before opening a pull request. This is the same primary check path used by CI. For system changes, also run the relevant task guide and disposable-machine evidence from [`agents/skills/`](agents/skills) and [`tests/acceptance/`](tests/acceptance).

Useful discovery commands:

```bash
cargo xtask acceptance-list
python3 tools/vm.py doctor
python3 tools/image.py doctor
python3 tools/visual.py list
```
