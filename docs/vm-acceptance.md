# Disposable VM acceptance

Linura system changes require disposable-machine evidence. A repository scenario or workflow existing is only a harness; it becomes release evidence only after the required exact-source run succeeds.

## General harness

- `tools/vm.py` constructs/starts a disposable QEMU/KVM guest using a qcow2 image and snapshot mode;
- an optional read-only cloud-init seed can be attached for deterministic disposable guest provisioning;
- `tools/acceptance.py` loads versioned scenarios from `tests/acceptance/` and executes steps over SSH;
- `.github/workflows/vm-acceptance.yml` builds exact checked-out binaries, provisions an ephemeral guest identity and runs repository scenarios against a SHA-256-pinned released Ubuntu cloud image.

The harness defaults to `auto` acceleration: it selects KVM only when the current process can actually open `/dev/kvm` read/write and otherwise selects TCG. Device-node existence alone is not treated as KVM availability because hosted/containerized environments can expose `/dev/kvm` while denying access. Callers may explicitly select `--accel kvm` or `--accel tcg`; an explicit inaccessible KVM request fails before QEMU launches. Missing QEMU/SSH prerequisites are failed doctor checks, not passing evidence.

Guest execution uses QEMU snapshot mode so the verified base image is not mutated.

## Reproducible guest qualification

Automated release-gating VM workflows use an explicitly pinned Ubuntu 24.04 LTS amd64 cloud image from `cloud-images.ubuntu.com/releases/`, with repository-owned URL and SHA-256. Floating `current` images are not accepted as release evidence.

GitHub-hosted qualification explicitly uses TCG rather than inferring acceleration from `/dev/kvm`, because hosted runners do not promise that a visible KVM device is accessible. Local and dedicated-runner users retain `auto`/KVM support through the general harness.

A release-gating guest workflow must record enough evidence to identify:

1. exact source SHA and workflow identity;
2. exact guest image URL/digest;
3. accelerator and relevant harness/tool versions;
4. scenario/guest-script digest or equivalent repository identity;
5. tested binary digests;
6. success/failure of the named proof assertions;
7. diagnostics needed to distinguish infrastructure failure from product failure.

The release path consumes workflow success for the exact source, not merely an uploaded evidence file from a different run.

## General authoritative-observation scenario

The general `.github/workflows/vm-acceptance.yml` authoritative-observation scenario remains the baseline for native observation and Control1 behavior. It starts `linurad` on an isolated session bus, proves D-Bus/OS-derived caller identity, observes a disposable transient systemd unit through the native system bus, mutates that fixture out of band, proves the new authoritative state becomes visible, checks graph/explanation evidence, and observes NetworkManager manager state when available.

Its guest has passwordless sudo only for acceptance-fixture management. Linura remains unprivileged/read-only in this baseline scenario.

## Milestone-specific system qualification

The generic scenario does not replace milestone-specific privileged/recovery tests.

- v0.4 has permanent durability and real-ext4/ENOSPC recovery qualification.
- v0.5 has permanent isolated executor/verifier qualification.
- v0.6 has permanent complete managed-lifecycle qualification in `.github/workflows/v06-managed-lifecycle-vm.yml` with guest/host scripts under `tests/acceptance/v06/`.

Each proof has a different claim and all mandatory inherited gates remain explicit dependencies of Trusted Release Proof.

## v0.6 managed-lifecycle disposable guest

The v0.6 guest qualifies the **real bounded product topology**, not only an executor fixture:

```text
human/system-bus caller
→ org.linura.Authority1
→ caller binding + Authority1 Polkit approval
→ linura-authorityd / linura-control
→ SQLite/WAL durable authority
→ separately authorized root linura-executor-systemd
→ systemd StartUnit / StopUnit
→ fresh independent systemd observation/verifier
→ verified commit / audit / reconciliation
```

The guest installs/runs the exact-source `linura-authorityd` and `linura-executor-systemd`, canonical D-Bus policies, Polkit actions/rules and systemd service units. Test-only qualification grant material remains under `tests/acceptance/v06/`; it does not change production policy into a permissive default.

### Required real-boundary assertions

The guest protocol must prove at least:

- live `Authority1` introspection exposes `ConvergeSystemdActiveState`;
- live executor introspection exposes the bounded `SetManagedActiveState` operation;
- an unapproved caller fails before dispatch;
- ordinary/direct-root attempts to call the supported managed executor path fail;
- unsupported unit namespace and unsupported desired state fail before handoff;
- inactive→active succeeds through the complete lifecycle;
- exact retry returns the same committed authority outcome without a second systemd dispatch;
- same operation ID with changed request body fails closed and does not dispatch;
- active→inactive succeeds through the complete lifecycle;
- already-satisfied/no-change behavior does not create an unnecessary external effect;
- a real fixture that fails to retain the intended postcondition produces verification failure and no blind replay;
- executor loss around the handoff followed by authority-process restart does not reconstruct dispatch permission or mutate the fixture on retry;
- the authority database exists in WAL mode and passes SQLite integrity checks.

The fixture records real start/stop side effects so idempotency is proven by external dispatch count, not only by receipt text.

### Deterministic fault matrix inside the guest

The same disposable guest also runs the repository-owned deterministic v0.6 matrix against real SQLite persistence. The matrix covers eleven cases:

1. active success + exact retry + request substitution;
2. active→inactive success;
3. denial/out-of-scope before dispatch;
4. stale evidence;
5. executor failure → indeterminate/no redispatch;
6. verifier transport failure → no commit/replay;
7. indeterminate execution → no blind replay;
8. crash/restart after handoff → durable indeterminate/no reconstructed dispatch;
9. `NotSatisfied` → re-prepare semantics; restart retires stale `Prepared`;
10. conflicting recovery → block;
11. reconciliation failure after commit → retry verify/reconcile only, no execution replay.

Running the deterministic matrix inside the real guest provides a common exact-source environment but does not make simulated observer/executor failures equivalent to real D-Bus failures. The real-boundary assertions and deterministic matrix remain distinct evidence layers.

## Trusted Release Proof relationship

`Trusted Release Proof` directly calls all mandatory exact-source qualification workflows, including v0.6 managed-lifecycle qualification, before the reusable sealed release build may run.

Therefore:

- PR-head VM success is development evidence, not final release evidence if the source SHA later changes;
- compaction/rebase changes the SHA and requires fresh final exact-head qualification;
- CI/Security/CodeQL success cannot substitute for system acceptance;
- a successful v0.5 executor workflow cannot substitute for the v0.6 complete-lifecycle gate;
- build/promotion cannot bypass a failed/missing mandatory VM dependency.

## Reserved/future scenarios

The repository also reserves acceptance coverage for bootstrap resume, offline First Boot, fail-closed security baseline, intent retirement, interrupted updates and native recovery. These become release-gating only when the corresponding Linura capability/milestone actually activates.

Placeholder commands, scaffold applications and future architecture descriptions must never be interpreted as evidence of an implemented feature. Component maturity is governed by `contracts/components.toml`.
