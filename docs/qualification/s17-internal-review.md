# S17 candidate internal review and qualification boundary

This is a development review record, **not qualification evidence or a readiness
attestation**. The candidate is based on main `41949015545872faccc72563d986a06cbf3c562b`.
The final commit identity and exact-head results belong to the subsequent
qualification run. S17 remains `planned`; ADR 0042 remains Proposed. S21 and
workspace restructuring are outside this change.

## Summary / why

One vertical slice implements protected native locking/authentication, managed
session/power execution and observe-only recovery, and first-party controls.
Owner-approved protective pre-sleep locking is a separate login-scoped policy;
it cannot unlock, authorize sleep or replace manual-lock confirmation.

## Architecture / trust boundaries

- Core owns boot/session/owner-invocation/generation identities; Control owns
  canonical plans, operation/risk registration, approval, durable handoff,
  verification, audit and reconciliation. Neither UI nor models gain an executor.
- Public SDK/CLI/compiled shell bridge share typed Authority1 contracts. Private
  native transports retain their handles internally and freshly attest received
  sender, supervisor, process image, invocation and session identity.
- Lock/unlock and all four power/session actions remain managed effects. Consent
  uses its own authenticated Linura-owned state journal, not synthetic execution.
- Native Polkit/PAM proof is exact-purpose and short-lived, never serialized as
  reusable dispatch authority. Secure-exec, whole-process memory residency and
  capability removal precede input. The shell never accepts response text.
- AT-SPI exports only fixed nonsecret metadata on strictly bounded own-runtime
  Unix routes. Assistive peers remain untrusted. No Text, EditableText, Value,
  Action or geometry/input interface exists; the standard application ID is
  unused registry bookkeeping. The exporter has no authentication/entry handle.
- Durable request and consent journals have independent identities, schemas and
  protected keys. Existing transaction formats are not silently reinterpreted.
  Historical rows/digests cannot reconstruct dispatch permission.
- Native sleep entry is independently attested and coverage-fenced. Failure
  denies continuation on the declared service route, not through an expiring
  delay inhibitor. Root/kernel bypasses are not claimed preventable. Foreign
  strong/weak inhibitors and other sessions are not skipped by managed power.

## Code / security / adversarial review

Reviewed canonical request/plan/effect equality, caller versus Actor provenance,
approval-purpose separation, fresh consent at prepare/handoff, write-once request
retention, exact recovery joins, SQLite schema/size/CAS/integrity checks,
supervised native service/process attestation, protected response lifetime,
Wayland generation/coverage/release fencing, native transition rejection versus
ambiguity, client tracking/reload behavior and metadata worker lifecycle.

Review specifically considered cross-user/root/service substitution, stale
approval and owner replacement, replay after crash/boot change, unknown native
state, late replies, malicious same-UID readers, malformed wire data, output loss,
cancelled/reentrant PAM delivery, storage failure, deadline rollback, cleanup
failure and false success/support claims. Component tests address these invariants;
they do not establish their real-session or hardware qualification.

Resolved findings:

1. Repeated native sleep-fence admission must retain the exact systemd job ID,
   not merely invocation/helper identity. The fence and regression tests enforce it.
2. Native approval replies arriving after the original Control interaction
   deadline must not authorize anything. Both confirmation and PAM consumption
   paths now recheck that original deadline; deterministic late-reply tests deny.
3. Offscreen QAccessible metadata did not establish native assistive discovery.
   The separate official-GIO AT-SPI exporter and actual registry-discovery probe
   now implement that missing connection. Real execution remains required.
4. Native fixture record publication needed parent-directory synchronization;
   suspend wake also needed a post-reply original-deadline check. Both are fixed.
5. Durable power-off qualification cannot use an ephemeral snapshot or mutate
   cached substrate. The explicit private disposable-copy contract, before/after
   guards and exact two-launch anti-substitution tests preserve that distinction.
6. The authentication harness could start the next negative/positive conversation
   inside the native five-second failure cooldown. It now waits without owner
   restart/reset. Tests bind that wait to the production constant. A separately
   verified password-locked-account case permits early actual exit-1 rejection,
   never transport failure, timeout or successful exit.
7. A repeated digest pathname could conceal removal of one binding step. The
   native gate now separately requires digest creation and receipt inclusion;
   negative workflow mutations exercise both omissions.
8. Authentication/suspend reports omitted receipt lineage and accepted a
   valid-looking replacement transaction/effect on recovery. They now retain
   the validated nonsecret receipts and native assistive scope, require exact
   recovery continuity, and bind consent/unlock history to the original records.
   Substitution tests reject changed-but-canonical digests/timestamps and still
   require cleanup. These reports remain partial evidence, not support authority.
9. Official GIO returns `InvalidArgs` for a known read-only property, not
   necessarily `PropertyReadOnly`. The native probe previously falsely rejected
   that legitimate denial. Only the fixed typed property-set case admits this
   sender-authenticated error, with existing/unchanged value checks. Action/edit
   cases still reject it; classifier tests reject timeouts/disconnects and
   unknown errors. No product check or authentication path changes. Reference:
   [GIO property dispatch](https://github.com/GNOME/glib/blob/2.80.0/gio/gdbusconnection.c#L4140).
10. The complete gate caught the new `linura-linux-session` direct authority
    dependency missing from v0.9's full-impact routing contract. Its workflow
    trigger was present, but that did not qualify the impact classification.
    Added the full prefix and source/Cargo/helper regression cases; preserved
    the direct-dependency guard unchanged. S17 cannot use a fast regression lane
    for these native authority changes.
11. Reconciled PR #224 (`a3fc827`) with the preserved local `2829d97` candidate
    and uncommitted CI work. The domain implementation was identical. Retained
    the PR's reviewed exact-version APT selectors instead of duplicating local
    before/after caller checks. Added the local finding's installed-status
    invariant and executable drift/denial tests; selectors must equal signed
    candidates and installed versions. Cache hits still confer no evidence.
12. Retained the PR's tray keyboard-return fix: restoration waits for both
    logical hiding and native backing-window unmap. Updated the stale shell
    validator and removal tests to require this stronger condition, rather than
    reverting the fix to satisfy obsolete assertions.
13. PR CI exposed two shell-format discrepancies. Applied the pinned formatter's
    reported whitespace-only changes; mode checks and private QMP socket checks
    remain identical. Complete pinned multilingual CI must rerun on the final SHA.
14. The inherited v0.6 guest executed all 48 tests successfully, then failed an
    eleven-case historical evidence assertion. It now retains and requires the
    complete 48-case run, then additionally reruns the original eleven-case
    projection for the unchanged v0.6 verifier. No test is omitted overall and
    no historical acceptance assertion is relaxed. Failure/count/ignored-case
    regression tests ensure the complete run cannot be replaced by the subset.
15. The pinned Arch substrate lacks an optional `hostname` executable. The S17
    disposable-guest guard now reads the same kernel nodename via `os.uname()`;
    root, QEMU/KVM, exact hostname, Arch and immutable-source guards remain.
    Tests reject wrong host/OS/virtualization before any provisioning.
16. Independent execution tests found Bash command substitution could clear
    `errexit` and let a failed APT selector check continue while forming cache
    identity. Resolver candidate checks now explicitly exit on failure before
    installation; resolver and installed checks are tested independently.
    Missing, changed or unavailable candidates cannot produce usable identity.
17. The retained PR tray edit invalidated its byte-sensitive format-exception
    digest. Inspected pinned Qt 6.4.2 output and the accepted #219 policy: this
    file's source contract is intentionally preserved rather than rewritten by
    the formatter. Reviewed the complete native-unmap diff and stronger guard/
    two-callback assertions, then renewed only that existing exact-source digest.
    The sixteen-file whitelist and every other digest are unchanged. Additional
    mutations of the unmap guard, pending flag and callback must fail closed.
    This preserves the accepted exception policy; it is not a wildcard bypass
    or evidence that any native or formatting gate passed.

## PR #224 reconciliation

Both source variants were preserved before editing. The old local checkout,
including untracked files and unrelated editor changes, has a verified protected
recovery archive; the PR head has a verified complete-history Git bundle.
The four local CI/review files were compared with the five PR-side changes;
no secure locker, authentication, managed operation, recovery or shared foundation
was missing. Unrelated `.vscode/settings.json` changes remain outside S17.
The consolidated candidate keeps the PR-side tray fix and exact selectors and
incorporates the useful local pin-verification/adversarial-review invariants.
S21 remains untouched. Old-head passes are diagnostic history, not final evidence.

## Regression impact

Updated public XML, codecs, SDK/CLI, compiled UI consumers, operation registration,
layering, service/image assets, migrations, slice-owned paths and critical-path
routing together. Existing v0.6 lifecycle, baseline approval strength, transient
audio semantics, accepted ADRs and upstream evidence-publication changes remain.
New assertions cover failure/denial/substitution/recovery; no passing claim is
created by removing a native requirement or relaxing an old assertion.

The native AT-SPI fixture/client/CMake inputs and their tests trigger workstation
qualification. Authentication reports bind the compiled probe and exact fixture
sources. Reports explicitly remain partial, with support promotion disabled.

## Applicable qualification / unfinished acceptance

Required native PR gates remain canonical CI, fresh RustSec audit and Rust CodeQL.
Changed authority/persistence/protocol/executor and shell paths also require the
inherited specialized lanes resolved by `contracts/qualification-gate-matrix.toml`;
the native Arch/Hyprland workflow cannot substitute for those gates.

Local development checks include pinned preflight, Ruff/rustfmt, strict Clippy,
affected Rust suites, Qt native/bridge/UI builds and tests, pinned Python analysis,
workflow lint, validators and adversarial tooling tests. Their actual results are
recorded separately; this document does not assert an unrun or final-head pass.
Missing language-format tools are reported, never replaced with arbitrary versions.

Candidate development results observed before commit: pinned preflight and tracked
source hygiene, Ruff/rustfmt, workspace all-target/all-feature strict Clippy,
affected authority/Control/native-session/executor/policy/SQLite Rust suites,
51 native-harness component tests, 164 runtime-contract and 132 routing adversarial
tests, 11 native-owner and 3 compiled-client component suites, UI/probe builds,
repository/assets/ADR/roadmap/development validators and workflow lint passed.
The available pinned C/C++, JS/Lua and separate Qt QML formatting checks passed.
The combined language-format gate remains locally blocked by missing `shfmt`
(the source-only checker also lacks Qt, checked separately in the native builder).
Final exact-head full gates, fresh audit, CodeQL and native execution are not
claimed by these development results.

The precommit canonical run completed its workspace Rust suites, then correctly
refused committed-snapshot checks against an older HEAD: the mutation guard
creates a detached HEAD worktree, which cannot contain uncommitted S17 modules,
and execution-envelope tests require committed exact source. These checks are
not weakened; the complete gate must be rerun against the consolidated commit.
An earlier full-gate linker failure coincided with a full build filesystem;
only 48 superseded task-generated test binaries were removed to recover space.
Source, protected recovery archives, dependencies and evidence were preserved.

Still required before S17 acceptance:

- Retained exact-source native first-login activation, secure-exec/helper/PAM,
  lock/unlock/consent, same-UID denial, suspend and terminating recovery evidence.
- Real protective-event/failure, inhibitor/service-loss, multiple-output/hotplug,
  compositor/locker/shell failure and authentication edge-case evidence.
- Keyboard/pointer, scaling, screen-reader traversal/focus and secret-safe visual
  evidence. AT-SPI metadata discovery alone is not Orca or complete accessibility.
- Any applicable maintained-hardware/Q11 evidence; a cloud VM is not hardware.
- Final complete exact-head gates and the later independent review/merge sequence.

## Migration / rollback

Migrations 0005/0006 describe separate S17 request/consent journals and preserve
released transaction meaning. Unsupported schema, corruption or missing keys
fails closed. Preserve authority directories and verified recovery copies;
rollback never deletes journal state or reinterprets it as permission. Follow
[session recovery](../session-recovery.md) for offline exact-request inspection
and explicitly authenticated native-console break-glass recovery.

## Review / release checklist

- [x] Candidate architecture, ownership, code and adversarial review performed
- [x] Identified code/harness findings above resolved with regression coverage
- [ ] Applicable local checks complete on the final candidate
- [ ] One clean feature-branch commit and staged-scope inspection complete
- [ ] Native and inherited qualification green on the exact final commit
- [ ] Required native interaction/accessibility/hardware evidence retained
- [ ] ADR/ledger accepted on evidence; complete S17 readiness established

Unchecked items are unfinished work. No PR, external review, merge, issue closure
or support promotion is authorized by this record.
