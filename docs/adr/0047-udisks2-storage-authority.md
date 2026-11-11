# ADR 0047: S21-4 UDisks2 storage authority binds the actual subject, physical device and verified effect

- **Status:** Proposed
- **Date:** 2026-10-28
- **Scope:** v0.10 S21-4, PR #261, `arch-hyprland-v1`
- **Refines:** ADR 0012 (canonical lifecycle), ADR 0019/0020 (durable authority), ADR 0024 (recovery), ADR 0031/0032 (single authority and risk), ADR 0042 (session security), ADR 0045 (S21 device authority), and ADR 0046 (original user-session execution, allocated to PR #260)
- **Activation:** None. The four candidate operations remain disabled until separately qualified.

## Context

UDisks2 exposes different authorities over a physical drive, its logical units and partitions, individual filesystems, and mounting namespaces. A D-Bus object path, `/dev/sdX` name, label, filesystem UUID, device number or returned success string alone does not establish the identity of the actual medium, its original mount owner, data safety, or successful physical removal. Hotplug, PID reuse, bus owner replacement, changed mount namespaces, bind mounts and shared USB enclosures can invalidate a superficially valid snapshot.

The original user's operating-system permission is distinct from Linura Control's policy decision. A root-managed authority service cannot infer the original user's entitlement from **its own** Polkit/UDisks2 privileges. ADR 0046, reserved separately in PR #260, defines original user-session execution generally; this ADR specifies storage-specific consequences without changing that record. The S17/ADR 0045 managed Control authority, single-use durable dispatch and no-blind-replay recovery remain mandatory. Neither the source tree's read-only observer nor this ADR is a running executor.

## Decision: four distinct managed effects

Every operation is a separately registered, typed `ManagedExternalEffect` after qualification. The design-time identifiers and risk floors are immutable to UI, provider, agent and caller; the corresponding S21 design TOML remains inactive.

| Operation | Native method | Minimum risk | Distinct consequence | Independent completion evidence |
| --- | --- | --- | --- | --- |
| `operation:storage.filesystem.mount` | `Filesystem.Mount` | `SecuritySensitive` | Exposes untrusted filesystem content and can activate filesystem helpers | Exact approved filesystem mounted at a provider-qualified path in the relevant verified namespace; no unexpected changes |
| `operation:storage.filesystem.unmount` | `Filesystem.Unmount` | `Destructive` | Can interrupt active readers/writers and risk unsaved data | Exact filesystem has no relevant remaining mounts/references; no forced or lazy unmount |
| `operation:storage.drive.eject` | `Drive.Eject` | `Destructive` | Mechanically releases a medium; can affect all partitions or siblings | Positive, hardware-qualified ejection evidence for the exact selected medium, not just D-Bus success or disappearance |
| `operation:storage.drive.power-off` | `Drive.PowerOff` | `Destructive` | Removes power to a drive/enclosure; in-flight writes may be lost | Positive, independently qualified controller/physical power-off evidence for the full affected group |

`Destructive` is an approval *floor*, not a claim that every ordinary unmount destroys data. Operations are never interchangeable. Unmount does not authorize eject or power-off; eject never implies power-off; power-off never proves eject. A user-facing "safely remove" workflow must represent a sequence of separately validated and authorized operations, stop on any blocked or indeterminate step, and not silently broaden the approved scope.

An unsupported mechanism or missing physical success oracle is reported as unsupported/indeterminate. No success is manufactured by lowering a risk class or substituting another method.

## 1. Original Polkit subject and process authority

1. **Authenticate the transport first.** Authority1 authenticates the actual local bus sender and binds its unique bus name, kernel-attested UID/PID and protected caller-process lifetime to a canonical non-root principal, kernel boot, exact logind session epoch and seat. Actor metadata, input strings, PID and session names supplied by a client are never security credentials.
2. **Prove the real worker.** A separately supervised, protected user-session worker makes the final UDisks2 call on **its own** authenticated system-bus connection. Its actual UID, process generation, bus identity, logind `GetSessionByPID` result, current local/active user session and seat must agree with Control's original subject. The supervisor must protect immutable executable identity, IPC, invocation and one-use handoff against same-UID impersonation, socket/PID reuse, injection and restart substitution. A logind PID lookup is necessary but not sufficient.
3. **Bind provider names.** Validate the canonical system bus, expected root-owned unique UDisks2 and Polkit owners and the exact UDisks2 object. Owner rotation invalidates previous observations and permissions. Check ownership again at dispatch/verification, not just at discovery.
4. **Use the actual Polkit subject.** `CheckAuthorization` against `system-bus-name` must name the true final user-session sender, never a root broker or Control's own connection. An advisory, non-interactive Polkit result cannot be a durable grant or a `DispatchPermit`. An interactive challenge, if supported, needs independent protected authentication tied to the exact plan; the native provider always makes its own final authorization decision.
5. **Respect contextual policy.** The applicable native UDisks2/Polkit action depends on the installed provider/policy, mount owner, seat, system/internal classification and device context. Hard-coded base `filesystem-mount`, `eject-media` and `power-off-drive` observations cannot represent every UDisks2 action variant. There is **no universal generic unmount action**. `filesystem-unmount-others` is not a blanket authority to unmount the user's own or any other filesystem. Prove actual mount ownership and qualify per-method native authorization without inventing an action ID.

Neither a root-origin `Can*` result nor prior session approval may elevate a user's current entitlement. If a genuinely original-subject D-Bus route cannot be authenticated end-to-end, the operation remains disabled; no root, `udisksctl`, shell or unrestricted D-Bus fallback.

## 2. Device, drive and filesystem identity

Build a bounded *complete* UDisks2 `Drive`/`Block`/`Partition`/`Filesystem` graph joined with independently attested kernel and sysfs facts. Record separately:

- **Physical drive:** kernel boot and insertion generation, USB port/enclosure ancestry, UDisks2 unique owner and instance, physical media generation and complete physical sibling/power group.
- **Block/partition:** kernel major/minor `dev_t`, `/sys/dev/block` canonical ancestry, supported `diskseq`, correct parent disk, partition table/number and complete children; resolve device-mapper/RAID/encryption/holder/slave relationships.
- **Filesystem and mounts:** exact block lineage, native filesystem instance, mount ownership and mount IDs, mount root, bind/propagation relationships and the relevant namespace(s).
- **Temporal identity:** source owner, boot, authenticated user/session/seat, medium instance, topology generation and bounded freshness from planning through execution and a *newer* verification sample.

A serial, symlink, filesystem label, object path, device number, provider flag or synthesized sequence is a correlation only and never identity proof by itself. Refuse ambiguous, duplicate, missing, recycled, substituted or incomplete objects and all unsupported topology changes. Deny host root, boot, EFI, swap, mounted system disks, unknown/internal disks, loopback-backed/system paths, active dm/RAID/crypto, unavailable holders and any unproven shared physical lineage. The current read-only native/kernel sources provide preliminary evidence, **not** a trusted dispatch-time generation lease.

## 3. Mount namespaces and busy state

`/proc/self/mountinfo` describes the observer's mount namespace, **not** necessarily the user's, a container's, an application worker's or all namespaces holding mounts. A match with UDisks2 in that namespace is a contradiction check, not proof of system-wide unmount or flush safety.

Before mutation, independently bind the intended final caller's namespace using process/namespace lifetime evidence. Identify every affected mount tree, mount ID, bind mount, propagation/ownership and writer/reference across relevant namespaces and processes. An operation must not proceed if this completeness cannot be established, especially for unmount, eject and power-off. An inactive filesystem in one mount namespace is not evidence that another namespace is idle.

Mount accepts only fixed reviewed native UDisks2 defaults or a separately qualified bounded option set, not caller-chosen mountpoint, arbitrary helper, file-system operation, executable content or open-ended mount options. Unmount must independently establish actual mount ownership and absence of busy writers; force/lazy unmount is forbidden. Busy or hidden references cause a hard denial, never a best-effort retry. Root filesystem, swap or other protected-mount ancestry remains disallowed regardless of a UDisks2 hint.

## 4. Whole-group protection for eject and power-off

An enclosure may share power with multiple logical units, card-reader slots, partitions or separate drives. Before either physical operation, derive **all** affected siblings from attested USB/sysfs/provider ancestry and ensure no unlisted member, foreign-seat member, mounted filesystem, open writer, protected system object or uncertain device is present. The absence of a provider block object is not proof that its sibling cannot be affected.

The executor must not silently unmount siblings or change another drive's power state to satisfy an earlier request. Revalidate the complete physical group immediately before execution. Ejectability and power-off support are different capabilities and each needs an exact independent hardware postcondition. A lost device object, unplug event or a successful reply alone is not positive proof of either action. If no meaningful oracle exists for the hardware, do not claim verified success.

## 5. One Control authority and narrow execution

Control1/Authority1 owns the canonical eleven-stage lifecycle:

**Request → Observe → Plan → Validate → Authorize → Prepare → Execute → Verify → Commit → Audit → Reconcile.**

Register each approved operation/risk, exact allowed state keys, provider and resource in the trusted registry; do not treat `contracts/v010-s21-design.toml` as executable. Each plan binds the real subject, native session/seat epoch, exact target and group, operation, provider-owner and medium generation, approved arguments, policy decision, human approval scope/expiry and independently observed preconditions.

The existing durable authority store must persist and *atomically reserve* the single-use dispatch before the first possible native side effect. An independently protected worker consumes a non-forgeable, one-use, exact-bound handoff, rechecks all relevant facts and invokes precisely one method with fixed arguments. No arbitrary D-Bus method/option forwarding, formatting, partitioning, filesystem repair, force operations, shell helpers or escalation fallback. Workers never plan, approve, mint grants or rewrite the resource. Merely checking hashes of a user-supplied payload does not authenticate a handoff.

Dispatch outcomes distinguish definite pre-effect rejection from possible dispatch and uncertainty. Timeouts, lost replies, hotplug, PID or bus-owner changes, process crashes, blocked audits and durable-store interruptions **never** trigger redispatch of a possibly executed operation. An inverse mount/unmount requires a *new* user-approved transaction, not implicit rollback. Eject or power-off cannot be undone by a guessed automatic remount or repower.

## 6. Independent verification and recovery

The verifier is a separately trusted, read-only native observer. It must obtain a **later** source- and identity-bound snapshot independent of executor acknowledgement. For mount and unmount, verify the relevant namespace(s), precise filesystem and mount tree, absence of unexpected side effects, unchanged underlying medium, and all pertinent references. For eject and power-off, use a separately qualified hardware signal for the **specific** physical outcome. A D-Bus reply, exit status, cached `Can*` permission or object disappearance alone is never sufficient.

The durable transaction records prepared, potentially dispatched, verified, committed, aborted/blocked and indeterminate states with effect and generation integrity. Upon restart, lost reply, provider replacement, mount namespace shift or media substitution, perform **observation-only reconciliation**; neither Control nor the worker repeats an uncertain effect. Missing proof remains indeterminate/recovery-blocked with explicit diagnostics. A later unrelated unplug must not be credited as prior successful eject. New action means new observation, plan, authorization and dispatch permit.

## 7. Qualification and activation

Qualification must include exact-source Level A with **real UDisks2/Polkit** and disposable devices, and adversarial cases covering subject substitution, root permission laundering, session/seat swaps, PID reuse, provider-owner replacement, stale device path and `diskseq`, hotplug, incomplete siblings, active root/swap, writer/holder/bind mounts across namespaces, other-user mount ownership, malicious options, permission denial, successful reply without effect, partial failure, duplicate dispatch, crash/restart, failed audit and no-blind-replay recovery.

Physical Level C/Q11 separately requires maintained real USB devices to substantiate physical eject, power-off, multi-device group behavior and data integrity. Synthetic Rust tests, a loop block device, or a VM cannot be described as physical proof. Independent evidence admission must bind exact source, guest, policy and device identity; preserve all inherited security, CI, v0.5/v0.6/v0.9, S17 and v0.10 gates.

Implement and qualify mount, unmount, eject and power-off **individually**, in that order where feasible. Keep every unqualified operation disabled. No passing ADR/docs check, candidate Polkit preflight or partial implementation changes `interactive_workstation.evidence_ready`, S21 acceptance or release support.

## Consequences and rejected alternatives

This architecture costs more than direct `udisksctl` calls and may reject cases other desktop tools permit. Fail-closed behavior is preferable to claiming safe removal without identifying every affected medium or its data-loss exposure.

Rejected alternatives: root-origin UDisks2 execution claimed as the user's permission; a second storage-specific authority plane; arbitrary caller-supplied methods or mount options; one generic "safe eject" operation; one observer's mount namespace as a global oracle; inferred physical success from disappearance; and replay after ambiguous dispatch.

**Current PR #261 status:** read-only models, native kernel/UDisks2 topology probes and candidate Polkit preflight exist. The trusted user-session execution path, registered operations, durable native dispatch, production verifier and required hardware qualification remain unimplemented. This ADR defines their requirements; it does not assert their completion.
