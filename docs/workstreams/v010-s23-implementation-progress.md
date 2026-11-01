# S23 WIP implementation progress — Applications, Packages and Defaults

**Branch:** `wip/v010-s23-applications` only. **State:** unfinished engineering WIP; not suitable for a PR review, runtime support promotion, merge or release. S23 remains planned. No PR creation or modification is part of this work.

## Source actually implemented on this branch

| Slice boundary | Source | Implemented engineering scope | Remaining qualification / implementation |
| --- | --- | --- | --- |
| S23-1 application discovery | `crates/linura-linux-observation/src/xdg_applications.rs`, `apps/linurad/src/main.rs` | bounded XDG desktop source catalog, current-actor process paths, first-source precedence, source hashing, no launch authority | inherited exact source launcher A/B, hardened path traversal/locale/association coherence, regression gates |
| S23-2 installed ALPM | `crates/linura-linux-observation/src/alpm_installed.rs` | bounded read-only v9 local package database, exact desc and files source digests, declared ownership path count, package/version/reason/arch, db.lck check and change rejection | actual Arch native parser/ownership tests, full signed frozen catalog/keyring, scriptlets and file verification, trustworthy complete `PackageUniverseEpoch` |
| S23-3 impact analysis | `crates/linura-planner/src/package_impact.rs` | pure non-executable bounded package-name/reverse-dependency reachability; unknown, untrusted, protected, shared, S24 and recovery blockers; unconditional `UnqualifiedExecutor` | native ALPM version/provides/conflicts/replaces resolution, full dependency closure and exact snapshot binding, signed source, native disk/lock/Polkit and complete impact |
| S23-4 managed package effects | Candidate only in `contracts/v010-s23-design.toml` | design and high-risk fail-closed operation requirements; **no effect implementation, permission or native dispatcher** | approved complete plan, Control authority/Polkit, durable prepare, independently verified ALPM effect and interruption recovery, snapshot/S24 compatibility, disposable Arch A/B |
| S23-5 XDG MIME and favorites | `crates/linura-linux-observation/src/xdg_mimeapps.rs` | read-only ordered MIME config candidate parsing, strict file checks, candidate revision, `effective_handler_verified=false` | real desktop-entry MIME association/eligibility, effective fallback, safe revisioned user write/editor, reset/add/remove, local favorites authorization |
| S23-6 product/qualification | `tests/tooling/test_v010_s23_implementation.py` | regression/source guards for read-only boundaries and disabled effects | QML/CLI/SDK integration, accessibility/no-model UX, exact-head Arch A and interactive B, physical Q11/C, security/audit/operational release evidence |

## Safety and authenticity

- Application launch remains the existing S12/S14 Quickshell fixed user-session broker. No new `Exec`, arbitrary shell, `pacman` execution or UI-based privileged operation has been installed.
- New read-only providers reuse `ObservationCoordinator` and canonical `ObservationEnvelope`; they do not register effect operations.
- The local ALPM package metadata and declared file manifest are **database claims**. They do not prove the present filesystem content, signed provenance, synchronized catalog, global transaction closure or post-install correctness.
- A candidate from `mimeapps.list` is not an independently validated effective MIME handler. Association and eligibility need the complete XDG hierarchy and desktop file rules.
- The package impact preview cannot authorize effects. Even a caller-supplied full-trust universe cannot obtain an execution grant.
- `contracts/v010-s23-design.toml` remains `activation = "none"`, with every proposed effect disabled, and S24 retains coordinated upgrades and recovery ownership.
- Never claim VM tests as physical Q11, nor a signed repository simply because `desc`, `files` or `pacman` output was read.

## Validation and blockers

The repository source and contract material was inspected for provider registration, explicit denial markers, lock/version handling, bounded reads, pure planning and inert operation registration. This is **static inspection only**. The environment used for these WIP writes has no reachable checkout/build toolchain for the full repository and therefore did **not** execute `cargo fmt --check`, `cargo test --locked`, `cargo xtask check`, native Arch A, interactive B or physical C/Q11. Their evidence is pending, not green.

On a prepared and trusted checkout, the **first priority is a build/format and security pass** over the current WIP head before implementing any effect or consumer. Run:

```sh
bash scripts/preflight_codex_environment.sh
python3 -m unittest discover -s tests/tooling -p 'test_v010_s23*.py'
cargo fmt --all -- --check
cargo test --locked -p linura-linux-observation
cargo test --locked -p linura-planner
cargo xtask check
```

Treat failures as engineering defects to fix. Do not silence tests, downgrade operation class or reclassify absent native qualification as passes. Native ALPM effects must be tested only on disposable pinned Arch systems with actual signatures, lock/interrupt, verified postcondition and observe-only recovery evidence.

After the WIP work, independently re-evaluate the adaptive split and extract reviewed, fully qualified commits onto clean branches. **No PR is to be opened during S23 WIP implementation.**
