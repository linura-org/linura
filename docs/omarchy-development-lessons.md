# Development lessons adopted from Omarchy

Linura is not an Omarchy fork and does not copy Omarchy's shell-command architecture. It does intentionally adopt several mature distro-development disciplines while implementing them through Linura's typed, intent-driven authority model.

| Lesson | Linura implementation | Status |
|---|---|---|
| Task-specific contributor/agent guides | `agents/skills/*` | implemented foundation |
| One blessed developer entry point | `cargo xtask` | implemented |
| Real/disposable desktop acceptance | QEMU/KVM + scenario runner | implemented harness |
| Installation as a staged pipeline | `linura-bootstrap` + image policy | implemented contract |
| Idempotent migrations | `linura-migrations` + ledgers/descriptors | implemented contract |
| Coordinated updates | `linura-update` state machine | implemented contract |
| Discourage bypass of blessed update path | update guard + Arch ALPM hook | implemented development policy |
| Snapshot/recovery thinking | bootstrap/update stages + recovery docs | implemented contract |
| Config ownership/resync | `linura-config` ownership/drift model | implemented |
| Hardware fixtures/matrix | `linura-hardware` + sanitized fixtures | implemented foundation |
| Visual verification | semantic tokens + baseline manifest + comparator | implemented harness |
| Shell coherence | single supervised Quickshell host + first-party QML surfaces | implementation candidate |
| CLI introspection | `linuractl commands --json` | implemented |
| Strong graphical acceptance discipline | VM/visual scenario boundaries | implemented harness |
| Supply-chain release proof | exact-SHA candidate, SBOM, checksums, attestations | implemented workflow |
| Build/publish separation | candidate promotion workflow | implemented |
| Verify released bytes independently | release verification workflow | implemented |

## Quattro-era shell lessons

Omarchy's move to a single Quickshell process reinforces the value of one coherent shell host for bar/panel/OSD/launcher-style surfaces instead of a fleet of independent desktop utilities. Linura adopts that **presentation topology** for its first-party shell.

The same architecture also makes lifecycle and trust boundaries more important. Quickshell/Qt package compatibility, shell reloads, lock-screen ownership and plugin teardown are workstation-runtime concerns that must be version-bound and exercised in Q11. Linura therefore does not make arbitrary in-process user QML or hot reload part of the v0.10 security/support boundary.

## Deliberately not copied

Linura rejects unsandboxed extension code as a default plugin model, string-only shell IPC as the authority API, UI-defined Bash predicates as system policy, arbitrary privileged lifecycle hooks, model-generated root shell, and Arch-specific assumptions in the core.

The goal is to inherit Omarchy's operational discipline while retaining Linura's stronger boundary:

> Agents propose. Typed deterministic authority decides, executes, verifies, and explains.
