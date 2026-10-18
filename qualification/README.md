# Qualification inventory

Qualification in Linura is distributed across versioned dossiers, Rust/Python tests, disposable guest runners, GitHub Actions and workstation-specific scripts. This index is **navigation**, not a new qualification authority or a release-readiness statement.

| Milestone | Qualification dossier | Executable gates and assets |
| --- | --- | --- |
| v0.1 | [v0.1.0](../docs/qualification/v0.1.0.md) | [Disposable VM acceptance](../.github/workflows/vm-acceptance.yml), [scenario runner](../tools/acceptance.py) |
| v0.2 | [v0.2.0](../docs/qualification/v0.2.0.md) | [Disposable VM acceptance](../.github/workflows/vm-acceptance.yml), [Rust integration tests](../crates/) |
| v0.3 | [v0.3.0](../docs/qualification/v0.3.0.md) | [Disposable VM acceptance](../.github/workflows/vm-acceptance.yml), [Rust integration tests](../crates/) |
| v0.4 | [v0.4.0](../docs/qualification/v0.4.0.md) | [Durability VM](../.github/workflows/v04-durability-vm.yml), [ENOSPC recovery VM](../.github/workflows/v04-enospc-recovery-vm.yml) |
| v0.5 | [v0.5.0](../docs/qualification/v0.5.0.md) | [Executor/verifier VM](../.github/workflows/v05-executor-verifier-vm.yml), [v05 fixtures](../tests/acceptance/v05/) |
| v0.6 | [v0.6.0](../docs/qualification/v0.6.0.md) | [Managed lifecycle VM](../.github/workflows/v06-managed-lifecycle-vm.yml), [v06 fixtures](../tests/acceptance/v06/) |
| v0.7 | [v0.7.0](../docs/qualification/v0.7.0.md) | [Library qualification](../.github/workflows/v07-library-qualification.yml) |
| v0.8 | [v0.8.0](../docs/qualification/v0.8.0.md) | [Agent qualification](../.github/workflows/v08-agent-qualification.yml) |
| v0.9 | [v0.9.0](../docs/qualification/v0.9.0.md) | [First Boot qualification](../.github/workflows/v09-qualification.yml), [adversarial guest workflow](../.github/workflows/v09-adversarial-security.yml), [guest scripts](../scripts/qualification/v09-adversarial-guest.sh) |
| v0.10 | [v0.10.0](../docs/qualification/v0.10.0.md) | [Workstation contract](../.github/workflows/v010-qualification.yml), [Arch shell runtime VM](../.github/workflows/v010-shell-runtime-qualification.yml), [v010 runners](v010/), [workstation acceptance contract](../contracts/v010-workstation-acceptance.toml) |

## Cross-version acceptance

- [General disposable VM scenarios](../tests/acceptance/) are numbered **scenarios**, not release versions. In particular, `008-control1-plan-preview.json` does not mean v0.8. The [default VM workflow](../.github/workflows/vm-acceptance.yml) executes one selected scenario; it does not execute all scenarios or all milestone qualification lanes.
- [Control1 plan-preview VM gate](../.github/workflows/control1-plan-preview-vm.yml) uses the shared guest runner with a different explicit scenario.
- [Qualification gate matrix](../contracts/qualification-gate-matrix.toml) governs applicable CI routing. [Execution envelopes](../contracts/qualification-execution-envelopes.toml) define runner execution context. [Evidence binding](../contracts/qualification-evidence-binding.toml) governs evidence admission. These are separate trust boundaries; this index does not replace any of them.
- [Trusted Release Proof](../.github/workflows/trusted-release-proof.yml) defines required inherited qualification at release time; a historic success is not proof for a changed candidate SHA.

## Execution environments and evidence

Historical milestone gates cover distinct claims, including Ubuntu/QEMU disposable guests. v0.10 introduces an Arch/Hyprland workstation profile with [automated shell-runtime guests](v010/shell-runtime/), [interactive/physical workstation runners](v010/workstation-acceptance/) and the [maintained hardware qualification entrypoint](v010/workstation-acceptance/run-hardware-qualification.sh). Level A automated VM, Level B interactive VM and Level C maintained physical hardware have different evidentiary roles; VM capture cannot satisfy physical Q11.

Release state must be read from the applicable dossier, machine-readable milestone and qualification contracts, and exact-source independently accepted execution evidence. In particular, v0.10 infrastructure existing does **not** mean the v0.10 workstation is release-qualified. Missing hardware, security, recovery or visual evidence remains pending and must not be relabeled as passed.

No runners are duplicated or relocated by this index. Changes to protected qualification files must continue to satisfy the applicable gate routing, security, review and release controls.
