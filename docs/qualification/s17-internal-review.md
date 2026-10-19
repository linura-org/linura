# S17 candidate internal review and qualification boundary

This is a development review record, **not qualification evidence or a readiness
attestation**. The integrated candidate is based on main
`3ed4da98fdb030d142066a7f777c814eaae2310f` (PRs #225–#232).
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
18. The previous native run rejected `/opt/linura-source` because the exact-source
    archive retained group-writable checkout modes during extraction. The
    provisioning route now stages the archive as a root-owned mode-0600 regular
    file, verifies its expected SHA-256 before extraction, extracts with a fixed
    umask and without retaining archive ownership or permissions, and verifies
    root ownership, non-writable modes and absence of symlinks throughout the
    resulting source tree. The existing native immutability check remains intact;
    no guest-wide permission rewrite or relaxed acceptance condition was added.
19. The complete tooling inventory exposed S17 configuration/build inputs that
    had never been registered with the fail-closed tracked-format classifier.
    They now have explicit narrow classifications, including XML, systemd,
    Polkit, CMake/container and fixture inputs. The Arch hook parser admits only
    its specified repeated Trigger operations/targets while still rejecting
    duplicate Action directives. The QMP component test now supplies a bounded
    storage stub and canonical run identity, preserving PR #225's production
    storage enforcement instead of inheriting a nonexistent empty run ID.
20. Exact-head execution from PR #225's long dedicated-storage namespace exposed
    the Linux Unix-socket pathname limit in QMP component test temporaries. Those
    small ephemeral test sockets now use private mode-0700 directories directly
    under `/tmp`, matching the already bounded native workflow path; VM images,
    builds, exact source and evidence remain on guarded dedicated storage. The
    same Python 3.12 run found that the guest's manual exact-source `image.py`
    loader had not registered its module before evaluating dataclasses. The
    loader now follows Python's import contract and has a 3.12 regression test;
    no interpreter fallback or version relaxation was introduced.
21. Once Python 3.12 could import the deployment test, it exposed a stale call to
    the pre-#225 native-owner image builder. The test now supplies and asserts the
    dedicated CMake build path required by the integrated contract. Production
    image builds continue to use the caller-provisioned storage namespace rather
    than creating a checkout-local or root-volume build directory.
22. Exact-head GitHub qualification exposed a conflict-resolution regression in
    the S17 disposable-disk creation block. PR #225's dedicated VM namespace had
    been preserved, but the disk was flattened directly into that directory and
    no longer satisfied S17's independently enforced private-directory/name
    contract. The workflow now creates a fresh mode-0700
    `linura-s17-disk.XXXXXX` directory inside `LINURA_VM_DIR` and copies the
    verified substrate to its mode-0600 `guest.qcow2`. This retains dedicated
    storage while restoring the distinct private-copy boundary. The workflow
    validator and mutation tests require both path components; the guard's
    ownership, link, size, digest and alias checks remain unchanged.
23. Review of the first exact-head candidate found an executor-side race between
    Control's reviewed session inventory and native machine-power dispatch. The
    executor now revalidates every non-target logind session using the same
    class/UID rules: user, greeter and lock-screen sessions always block;
    manager/background sessions block for a foreign UID; unknown classes fail
    closed. Tests cover same- and cross-UID cases. First-login activation now
    watches bounded Wayland socket-name patterns because the previous nested
    Hyprland glob could miss a newly created instance; this trigger grants no
    authority and the native owner still freshly attests sockets, kernel peers,
    compositor identity, PAM and logind state. Native startup failures expose
    only fixed nonsecret stage identifiers and preserve every fail-closed return.
24. Rebasing onto PRs #226–#228 retained the RustCrypto 0.11 HMAC/digest API and
    lockfile graph rather than restoring superseded dependency semantics. The
    test-only authority fixtures now use process-local kernel entropy, remain
    stable across reopen/recovery within the test process and use distinct keys
    per isolated domain. Exact-head CI then correctly rejected panic-oriented
    `expect()` calls under the repository's strict Clippy policy. Entropy open
    and complete-read failures now flow through the existing explicit test
    failure helper; there is no constant, zero-key or best-effort fallback.
25. Exact-head GitHub v0.6 qualification executed all 49 Authority1 tests
    successfully, then rejected the complete transcript because its exact-count
    assertion still named the 48 tests present before the executor-side session
    race regression was added. The complete-matrix contract now requires exactly
    49 passing, zero-failed, zero-ignored tests while the historical eleven-case
    projection remains unchanged. Tooling tests reject both missing and unexpected
    extra full-matrix cases, nonzero ignored cases and a nonzero runner exit; no
    test was removed, skipped or replaced by the legacy projection. The complete
    reviewed shell bytes were re-audited and their execution fingerprint updated
    for this single literal assertion change.
26. Exact-head GitHub v0.10 qualification built and installed the native owner
    with its exact file capability, then failed closed at the fixed
    `startup/insecure-exec` stage. The guest uses Linux `fs.suid_dumpable=2`, so
    secure file-capability exec correctly entered root-only/safe-path dumpability
    state 2 rather than state 0. Both deny unprivileged same-UID ptrace, but the
    startup guard had accepted only state 0. It now accepts exactly the two
    kernel-protected initial states (0 and 2), rejects user-dumpable state 1,
    errors and unknown values, and immediately sets and reads back state 0 before
    capability inspection/use, memory locking, native input or Qt initialization.
    The `AT_SECURE`, identity, no-new-privileges and exact-capability requirements
    remain unchanged; the post-drop state-zero check also remains. Component and
    deployment-contract tests cover the accepted/rejected states and the ordering,
    without changing the host sysctl or repairing an ordinary exec.
27. The next exact-head v0.10 run passed the immutable substrate and real shell
    runtime, then retained `startup/socket-routes` failures from the native owner.
    The first-login path unit correctly triggers on the first Wayland socket, but
    Hyprland publishes its separately required control socket shortly afterwards;
    five immediate service attempts exhausted the trigger limit before that second
    route existed. Native startup now uses the explicit shared compositor-readiness
    contract: strict scan, bounded Linux filesystem watches, strict rescan, then
    strict rescans on relevant events within one five-second monotonic window.
    Events never establish identity or authority. Watch failure, queue overflow,
    more than 256 relevant topology events, timeout and the unchanged ownership,
    file-type, link-count, name and cardinality bounds all fail closed. It still
    rejects every partial or ambiguous route, retains `Restart=no`, waits only
    after secure-exec process protection and before environment/toolkit
    initialization, and exposes only the same fixed failure stage. Component and
    deployment tests cover delayed
    nested creation, invalid matching files, timeout, invalid bounds and ordering.
28. Exact-head v0.10 diagnostics then showed the protected owner consuming roughly
    one CPU-second and failing `startup/socket-routes` well before the five-second
    deadline while the complete native session was starting. The watcher had
    counted every event under the user runtime root and performed a complete watch
    reinstall and strict rescan after each one, so ordinary PAM, logind, D-Bus and
    compositor startup traffic could exhaust the 256-event route-topology budget.
    Watches now classify the runtime root, Hyprland root and instance directories;
    only creation/removal/change of `hypr`, a valid `wayland-*` route, a valid
    Hyprland instance or `.socket.sock` consumes that budget and triggers strict
    rediscovery. Unrelated events are drained and remain bounded by the original
    monotonic deadline; queue overflow, malformed or unknown watch events and more
    than 256 relevant events still fail closed. Component tests reproduce more
    than 256 unrelated events before a valid route and separately prove that a
    matching-name regular-file event storm remains denied.
29. The next exact-head v0.10 run retained the same `startup/socket-routes`
    denial, including five rapid exits well before the unchanged five-second
    deadline. That disproved event-budget exhaustion as the complete cause and
    narrowed the remaining fault to an early watcher setup, event validation or
    reinstall denial. The readiness API now returns a closed fixed failure
    category and production startup emits only the corresponding constant stage
    identifier. No path, peer, event name, errno text or filesystem payload is
    logged, and every category still returns the same unavailable startup result.
    Component tests bind invalid bounds, timeout and relevant-event exhaustion to
    their categories. The next exact-source guest run must identify and correct
    the actual early denial; this diagnostic refinement is not qualification or
    a passing claim.

## PR #225–#232 integration

The original PR #224 head is retained locally and on GitHub as
`backup/pr-224-pre-main-225-20261017` before rewriting its feature branch. The
S17 commit was rebased individually onto PR #225 and then the #226–#228 main
head. It was subsequently rebased onto the #229–#232 main head. The sole conflict
was the changelog: main's restored v0.9 history and guarded v0.10 structure were
preserved, and the S17 entry was placed inside that current structure. Cargo kept
main's `cmov` update automatically. Every overlap was inspected rather than
resolved with a blanket side selection.

The previously locally qualified post-#225 candidate is retained as
`backup/pr-224-qualified-210e388-20261018`. The current candidate also includes
the reviewed action pins from #227/#228 and the RustCrypto migration from #226;
those base changes are not reimplemented or selectively reverted by S17. The
pre-#232 candidate is retained locally and on GitHub as
`backup/pr-224-pre-main-232-2c65d94-20261018`; #229–#232's dependency, changelog,
qualification-index and acceptance-schema protections remain inherited from main.

The integrated workflow retains PR #225's dedicated-storage root, environment
identity, free-space boundary, per-head/per-run namespaces, private persistent
copy and cache protections. S17's QMP input path and terminating-session recovery
run only against the separately guarded private VM copy; the shared prepared
substrate remains immutable and the ordinary launcher remains snapshot-based.
Build paths for the shell bridge, UI and security owner are supplied by the
dedicated-storage contract rather than silently returning to the root volume.
Runtime evidence also covers the S17 packages introduced into the substrate
contract, so a cache hit cannot substitute for installed-package evidence.

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
The pre-#232 candidate at `2c65d945353ce58070a81566df171da13a0c7f11`
passed the canonical exact-head local `cargo xtask check`: all workspace checks
and 1,844 tooling tests passed, with the two declared environment-dependent skips
preserved. The rebased event-driven candidate passed pinned preflight, a fresh
offline native build and all 11 native-owner component tests, plus 92 focused S17
and inherited #229–#232 acceptance/changelog/index tests. The final rebased
canonical run and GitHub exact-head gates remain the subsequent qualification
boundary; old-head results are not substituted for them. Fresh audit, CodeQL and
native execution are not claimed by these local results.

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
- Final complete GitHub exact-head gates and the later independent review/merge
  sequence.

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
- [x] Applicable local checks complete on the final candidate
- [x] One clean feature-branch commit and staged-scope inspection complete
- [ ] Native and inherited qualification green on the exact final commit
- [ ] Required native interaction/accessibility/hardware evidence retained
- [ ] ADR/ledger accepted on evidence; complete S17 readiness established

Unchecked items are unfinished work. No PR, external review, merge, issue closure
or support promotion is authorized by this record.
