# Development and CI scripts

Root `AGENTS.md` remains applicable. Paths below are relative to the repository root.

- Read `docs/development-infrastructure.md` and `docs/codex-development.md` from the repository root.
- Setup and maintenance belong to environment preparation; task diagnostics must not install tools or change source.
- Run shell syntax checks and `python3 -m unittest discover -s tests/tooling -p 'test_*.py'` from the repository root, then the canonical gate.
- Exercise failure, version drift, cached environment and source-mutation paths. Keep pins aligned with CI and release proof.
