# Source formatting contract

The formatter is the authority for source layout; rulers are guidance, not an assertion that every literal or comment stays below the primary width. No formatter is permitted to alter security semantics to improve line widths.

| Source | Formatter | Primary width | Indentation |
| --- | --- | --- | --- |
| Rust | pinned rustfmt | 100 | 4 spaces |
| Python | Ruff 0.16.10 | 88 | 4 spaces |
| C/C++ | clang-format 18.1.8 | 100 | 4 spaces |
| JS, MJS, TS, formatter JSON configs | Prettier 3.6.2 | 100 | 2 spaces |
| QML | Qt 6 qmlformat | 100 | 4 spaces |
| Lua | StyLua 2.5.2 | 100 | 4 spaces |
| Shell | shfmt 3.11.0 | 100 (visual) | 4 spaces |

The cSpell dictionary remains curated; it is unrelated to format or type correctness. Use `.editorconfig` and the checked-in formatter configs rather than a developer's global defaults.

**Adoption policy:** Start with an exact, clean formatting baseline for each language. Use pinned tooling, enumerate Git-tracked inputs, check idempotence, review every changed executable source for semantic and security regressions, run negative and integration tests, then add a required check. Do not enable a red required gate against unformatted legacy content. Do not silently skip missing tools, reformat generated files, or auto-rewrite audited evidence.

**Sensitive files:** Preserve independent verification, source-to-commit and artifact bindings, hashes, policy literals, QML imports and execution ordering, and workflow expressions. Never enable QML import sorting or attribute normalization without a separate semantics review. Markdown and immutable evidence/contracts need narrower document-specific policies rather than destructive mass formatting.

Tool versions are the canonical baseline, not the VS Code extension version; the final check must run with the exact supported versions in CI.

## Canonical enforcement

The required GitHub CI `canonical-check` installs pinned C/C++ (including CXX/header variants), JS/MJS/TS (including `.mts` and `.cts`), QML, Lua and shell tools **outside the repository checkout** and runs `python3 tools/check_multilanguage_formatting.py` in check-only mode. It verifies the full Git-tracked C/C++, JavaScript/MJS/TypeScript, QML, Lua and shell corpus, along with the formatter's own JSON package/config files. The checker fails closed on missing tools, wrong versions, untracked symlink substitution and formatting drift. It never writes to tracked source. Each Prettier path is passed after the option terminator, with explicitly disabled Git/Prettier ignore rules and enabled tracked `node_modules` handling, so a force-added source cannot bypass the check or inject a mutating flag.

npm dependencies are integrity-locked in `tools/source-format/package-lock.json`; clang-format is SHA-256 locked to the Ubuntu x86-64 Python wheel; shfmt is fixed to a Go module version and checked with Go's checksum database; qmlformat is tied to the signed Ubuntu 24.04 Qt 6.4.2 package version. The GitHub Actions runtime is Ubuntu 24.04 x86-64.

The exact formatter baseline must be reviewed against the tested QML/runtime and evidence/publication security contracts. CI refuses changes until the already-formatted baseline is committed; it does not silently modify worktrees. Formatters not applicable to a tracked file are not invoked. Markdown, workflow YAML, release metadata, vendored/generated snapshots and hashed evidence require separate review before activating broad normalization.

## Tracked structured and document formats

The canonical formatter step also runs `python3 -m tools.check_tracked_formats`. See [Tracked-format contract](tracked-format-contract.md) for the complete fail-closed inventory, explicit format classifications, parser-only versus formatter-enforced boundaries, and production verification commands. The additional checker never rewrites tracked files. Repository-owned toolchain pins are validated as non-executable data by `tools/check_toolchain_env.py`; shell and workflow consumers load only its fixed-order validated output and do not source or evaluate the contract. The exact-source workstation launcher has an updated, audited SHA-256 exception for this data-loading migration.

## Security-bound formatting exceptions

Sixteen existing qualification and authority-sensitive source files intentionally retain their **exact original bytes** because the production qualification and shell/Qt contract validators bind specific source fragments, not merely runtime behavior. They are **not silently excluded**: `tools/check_multilanguage_formatting.py` requires their full SHA-256 digests to match the reviewed source in `FROZEN_FORMAT_INPUTS`. They remain under repository source hygiene, Rust/Python contract checks and all applicable qualification gates.

- `packaging/wireplumber/linura-session-audio.lua` — identity-bound WirePlumber/Audio Sink rule.
- `qualification/v010/shell-runtime/run-shell-runtime.sh` — exact runtime/evidence commands, redirections and negative-proof fragments.
- `qualification/v010/workstation-acceptance/record-session.sh` — recorder helper provenance, global lock and fail-closed abort ordering proof.
- `qualification/v010/workstation-acceptance/launch-interactive.sh` — exact-source interactive VM binary provenance, argument rejection, dedicated-storage/fresh-run guard and inode-lock proof. The workspace storage change deliberately updates its reviewed exact-source fingerprint; it does not exempt new source from hygiene or qualification.
- `qualification/v010/workstation-acceptance/capture-hardware-session.sh` — fail-closed physical-machine capture, checked volume/scratch, fresh retained-evidence refusal and recording identity. The storage rollout deliberately updates its reviewed fingerprint without removing exact-source, fixture, lock, source hygiene or recording checks.
- `scripts/qualification/v09-adversarial-guest.sh` — exact adversarial transport/power-cycle bootstrap and source-bound test fixtures.
- `apps/linura-shell/panel/WorkstationPanel.qml` — keyboard focus and keyboard-release UI authority contract.
- `apps/linura-shell/tray/SystemTrayView.qml` — tray popup interaction, seat/keyboard ownership, and dismissal contract.
- `apps/linura-shell/plugins/notifications-osd/LifecycleFeedback.qml` — initiating-screen binding and lifecycle state-machine invariants.
- `apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml` — trusted control-center routing signal contract.
- `apps/linura-shell/plugins/command-palette/CommandPalette.qml` — typed navigation/launch target identities and keyboard handoff.
- `apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml` — compositor-backed workspace-focus field contract.
- `apps/linura-shell/shell.qml` — exclusive transient surfaces, masks, anchors, margins and lifecycle output authority.
- `apps/linura-shell/ui/LinuraDialog.qml` — dialog acceptance/rejection signal API.
- `apps/linura-shell/bridge/audio_session_controller.cpp` — exactly reviewed audio authority retry/dispatched control-flow fragments.
- `apps/linura-shell/bridge/audio_session_controller.h` — exact lifecycle-feedback signal declaration and typed Qt API.

S21-5's read-only compositor inactivity advisory deliberately updates the two protected QML sources (`apps/linura-shell/shell.qml` and `apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml`). The exact-source SHA-256 fingerprints are re-bound to the consolidated, reviewed code, including the S21-5 Control-verified advisory timeout binding, while retaining the existing closed input, S17 authority, no-autodispatch and runtime qualification boundaries. The previous per-file fingerprint is never treated as valid evidence for the changed source. 

Any deliberate source edit requires an architectural review of every dependent proof, negative test and source hash, followed by a separately reviewed update to the expected SHA-256. Do not loosen a verifier to satisfy a generic formatter. No unprotected shell or Lua file has a blanket exemption.

The canonical QML checker mirrors each tracked QML path beneath a temporary root containing the exact checked-in `.qmlformat.ini`; it does not format an orphaned file with missing style settings. Extensionless Bash qualification helpers and shell shebangs (including scripts with non-shell suffixes and `env -S`) undergo the same shfmt check as `.sh` inputs. Tracked-file inventory rejects symlinked source or ancestor substitution. These boundaries have adversarial tests.
