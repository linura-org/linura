# Python client and package work

Root `AGENTS.md` remains applicable. Paths below are relative to the repository root.

- Read `agents/skills/protocol.md`, `docs/sdk.md`, `docs/api-versioning.md` and `contracts/stability.toml` from the repository root.
- Use the `bindings` readiness profile and the isolated hash-locked build environment in `docs/codex-development.md`.
- From the repository root run `PYTHONPATH=bindings/python/src python3 -m unittest discover -s bindings/python/tests -p 'test_*.py'`, build the wheel offline, then run the canonical gate.
- Keep the Python client non-privileged. Version, lockfile, metadata and package contents must agree.
