# Documentation and architecture records

Root `AGENTS.md` remains applicable. Paths below are relative to the repository root.

- Read the relevant contracts and current implementation before changing status or completion claims.
- Accepted ADRs are append-only; record changed decisions in a new ADR instead of rewriting history.
- Run `python3 scripts/check_repository.py`, `python3 tools/check_adrs.py` and `python3 tools/check_roadmap.py` from the repository root, then the canonical gate.
- When changing agent guidance, development policy or the PR template, also run `python3 tools/check_development_workflow.py` and its adversarial tests; do not introduce a competing review sequence.
- Do not turn implemented harnesses, screenshots or unavailable tests into support claims.
