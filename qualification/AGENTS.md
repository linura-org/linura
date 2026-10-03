# Machine qualification

Root `AGENTS.md` remains applicable. Paths below are relative to the repository root.

- Read `agents/skills/vm-acceptance.md`, `agents/skills/visual-verification.md` and the applicable qualification contract from the repository root.
- Preserve `python3 tools/vm.py doctor` and exact source/image/profile/evidence bindings. Use the `vm` and `visual` readiness profiles.
- Keep destructive tests inside disposable guests. A cloud VM cannot supply physical Q11 evidence.
- Record unavailable lanes as unexecuted; do not weaken assertions, manufacture evidence, publish private recordings or promote support to clear a failure.
