# Qt/QML shell work

Root `AGENTS.md` remains applicable. Paths below are relative to the repository root.

- Read `agents/skills/shell-ui.md` and `agents/skills/visual-verification.md` from the repository root.
- Run `python3 tools/codex/doctor.py --profile shell --profile visual` from the repository root before claiming shell readiness.
- Build both `apps/linura-shell/bridge` and `apps/linura-shell/ui` with CMake/Ninja into separate `.artifacts/` directories; run the applicable graphical qualification workflow.
- Qt/QML remains presentation-only. Missing runtime, interaction or visual evidence is unexecuted evidence.
