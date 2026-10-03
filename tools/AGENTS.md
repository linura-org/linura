# Repository tooling

Root `AGENTS.md` remains applicable. Paths below are relative to the repository root.

- Read `docs/development-infrastructure.md` and the applicable existing task guides from the repository root.
- Use bounded diagnostics and explicit nonzero failure for missing prerequisites. A readiness report is not qualification evidence.
- Run `python3 -m unittest discover -s tests/tooling -p 'test_*.py'` and the affected validators from the repository root, then the canonical gate.
- Preserve canonical CI, Security (`cargo-audit`), CodeQL, and the scoped critical-path routing in `tools/check_validation_gates.py`; extend it when adding a qualification lane.
- For release changes also read `agents/skills/release.md`; never bypass native checks or grant new publication authority.
