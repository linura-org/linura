# Rust domain and adapter work

Root `AGENTS.md` remains applicable. Paths below are relative to the repository root.

- Read the root architecture ownership map and the applicable guides under `agents/skills/` before edits.
- For authority changes read architecture, policy, providers and security-review guides; for public APIs read protocol plus `contracts/stability.toml`.
- Use `bash scripts/run_codex.sh cargo test --locked -p <affected-crate>` for targeted checks, then `bash scripts/run_codex.sh cargo xtask check`.
- Provider/transport details stay in adapters; do not create another plan, observation or policy authority.
