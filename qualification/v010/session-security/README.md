# S17 native qualification fixture

This fixture extends the repository's existing pinned Arch/Hyprland QEMU lane.
It is not a new workstation runner, production credential store or support
promotion mechanism. The VM uses the exact triggering source, fresh Linura
release binaries and production image asset installer. The automated final
runtime lane now requires KVM on the pinned GitHub-hosted Ubuntu runner. It
checks the actual character device and runner access before boot and fails
closed instead of falling back to software emulation. The shared launcher
retains TCG by default for pre-existing substrate construction and local
callers; both private S17 runtime boots explicitly use the same KVM setting.
Acceleration changes neither identity, policy, protected input, negative tests,
real PAM/logind/Wayland authentication, source digest, nor evidence admission. Native bootstrap retains
the unchanged secure-exec, native session, Polkit and root-supervision guards.

Architecture and security requirements are defined by [ADR 0042](../../../docs/adr/0042-s17-session-security-and-power-authority.md) and the [S17 threat model](../../../docs/threat-model.md). Final acceptance and exact-source evidence are tracked in [PR #241](https://github.com/linura-org/linura/pull/241); [PR #224](https://github.com/linura-org/linura/pull/224) remains the unmerged diagnostic history. These references confer no release-support qualification.

`provision-native-session.py` refuses non-root, non-QEMU/KVM, wrong-hostname,
non-Arch and non-root-immutable source contexts. It creates a genuine local
PAM/logind Wayland session with Hyprland executing as its actual leader.
The native compositor explicitly uses libseat's logind backend, so that same
session controls DRM/input device pause and resume. It has no seatd fallback;
an unavailable logind controller fails native bootstrap. The earlier non-native
shell runtime retains its separate seatd setup. This fixture correction changes
neither the production owner nor acquisition, suspend or recovery acceptance.
`check-native-session.py` checks automatic first-login owner activation, native
identity, installed capability and post-drop process state. It independently
revalidates the pinned Polkit 127 systemd service fragment, absence of drop-ins,
current invocation/PID, exact running argv and local daemon UID before native
owner startup. The native authentication runner refuses legacy #224 bootstrap
reports lacking this supervised-daemon provenance. Neither check substitutes for
the production peer guard or Polkit authorization. The bootstrap report explicitly
does **not** qualify PAM authentication or complete S17.
It also compares the installed suspend gate, restricted sleep-mode configuration,
private bus policy and private XML against bounded root-immutable exact-source
bytes, retaining their digests. Installed-byte checks explicitly do not qualify
gate enforcement, automatic locking or suspend/resume correctness.

`run-same-uid-probes.py` runs the unprivileged owner's real memory/environment/
auxiliary-vector open and `PTRACE_SEIZE` denial probes. It temporarily removes
Yama inside the disposable guest, so ambient Yama restrictions cannot be mistaken
for the owner's secure-exec protection. It restores the original reversible
setting on ordinary errors, deadlines and handled cancellation. Forced process
death cannot guarantee cleanup; the workflow discards that VM and cannot admit a
passing report. The probe never reads protected bytes, stops the owner, injects
signals or enables ptrace `EXITKILL`. A permitted attach is a failure, not evidence
to be relabelled. These cases do not prove compositor integrity, authentication,
pointer/accessibility, power transitions or the entire security matrix.

`native_input.py` is a bounded private QMP hardware-input adapter for subsequent
native authentication/interaction cases. The shared VM launcher accepts an
optional `--qmp-socket` only inside a runner-owned mode-0700 directory, never TCP
or a reused socket. It adds a qualification-only USB tablet. The adapter exposes
only hardware key/pointer events and a narrowly bounded native-suspend wake;
no human-monitor command, shell, guest agent or arbitrary QMP operation. Wake
requires actual machine support and independently observed suspended state,
and never authorizes or initiates guest sleep. Component fake-server tests are
not execution evidence. These checks follow the official
[QMP wake contract](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-system-wakeup).
Command replies and asynchronous guest events share the QMP stream. The adapter
retains at most 32 pending events across replies, so a genuine guest termination
arriving before the final key acknowledgement remains available to the observer.
Overflow fails qualification. Retention changes neither the original deadlines
nor guest-origin checks; independent native recovery must still verify completion.

QMP input acknowledgement proves enqueueing, not guest consumption. Responses
use a fixed 50 ms interval between physical key strokes so the PC's bounded
PS/2 queue can drain before the next character and final Enter. This remains
inside the original native interaction deadline; dropped input, denial and
missing PAM completion cannot qualify. See the upstream
[PS/2 queue implementation](https://github.com/qemu/qemu/blob/v9.2.0/hw/input/ps2.c).

On failure the runner may retain a fixed read-only locker-service query, with
a three-second guest timeout and the existing shared output bound. Only known
state/result categories, bounded numeric exit facts and a comparison with the
requested owner invocation leave its parser. A separate three-second current-boot
journal query reads at most 64 entries under the same output bound, selecting
only process exit fields and fixed watchdog labels for that owner unit. Only
closed exit codes, numeric statuses and known watchdog stages survive decoding.
Watchdogs attempt one nonblocking, allocation-free journal-socket send before
the original exit 71; a full, closed or non-socket stderr cannot delay exit.
Their durations, admission points, cancellation and fail-closed behavior remain
unchanged. The native component test also fills the journal socket without
draining it and still requires the original bounded watchdog exit.
Six fixed Wayland milestones distinguish a marshalled request, the first
configured lock surface, the first frame successfully flushed to the owned
connection, all currently announced lock surfaces flushed, the actual locked
event and release acknowledgement. Each occurs at
most once per acquisition and uses one nonblocking send without retry. Only
these exact labels, in journal order, survive failure decoding. No input,
dimensions, peers or payload are retained. First-surface/frame progress cannot
prove all-output coverage or satisfy acceptance, and never changes a clock,
effect, verification or recovery decision. The wire regression checks the exact
two-acquisition trace and the original watchdog exit when no native events drain.
Raw journals, invocation identifiers, process
environments, daemon error text and account material are not retained. This
record is explicitly failure diagnostics; it cannot satisfy a
case, suppress the original error or skip relocking the ephemeral account.
Fixed three-second read-only compositor queries run under the disposable account
after a failure, explicitly selecting the first live instance because SSH has no
compositor instance environment. Only aggregate output counts and closed upstream
protocol/render
labels survive bounded decoding; raw logs, names, identifiers and dimensions do
not. Ambient instance discovery is context only, never original-invocation
attestation, coverage proof or recovery/acceptance evidence.

The native fixture enables Aquamarine-only scheduling trace and compositor
monitor-damage labels. General compositor tracing and Wayland wire/input tracing
remain disabled. The bounded failure decoder preserves event order and extracts
only fixed labels and the three boolean scheduler flags (frame needed, flip in
flight, frame event scheduled); raw device, framebuffer, input-event, clock and
object data are discarded. Atomic DRM remains selected normally. This is
diagnostic context and cannot replace native coverage or fix a failed operation.
The failure-only log query keeps only the final 12,000 bytes and 128 complete
lines before the existing 16 KiB transport bound; it discards a potentially
partial first line and preserves upstream pipeline failure. Trace volume cannot
increase the acceptance reader's limits.

The read-only AT-SPI probe separately classifies fixed no-reply/deadline,
departed-peer and disconnected transport errors. They remain hard failures,
never malformed-tree aliases or unsupported-API proof. Only those numeric exit
categories leave the fixture; remote text and metadata remain suppressed. All
500 ms call limits, the original eight-second probe bound, exact tree/owner
checks and remote input/relabel denials remain unchanged.

There are no retained positive PAM/power cases merely because this input channel
is implemented; those native cases and digest-bound retained reports remain
required before S17 acceptance.

`qualify-native-auth.py` extends that same lane with real hardware confirmation,
the unchanged distribution PAM/Polkit owner conversation, Control restart and
observe-only committed-lock recovery, explicit enable/revoke consent, superseded
consent history, native cancellation, one incorrect-response denial and exact
verified managed unlock. A timeout on the incorrect response proves only that it
did not complete unlock, not the PAM stack's specific rejection reason. It uses
fresh random responses through private stdin and QMP only. The fixed guest helper
refuses every non-disposable context and an initially usable account password;
it does not replace PAM, relax production checks or add a Polkit allow rule.
Cleanup locks the disposable account, including after ordinary failures. A forced
runner death cannot guarantee cleanup: discard that VM, never retain it.
It also independently locks the disposable account password and requires the
correct response not to complete unlock while that lock is present. The same
ephemeral response is restored only through private stdin before the positive
unlock. This proves noncompletion under the independently observed account
condition, not a particular PAM error message or full account-expiry coverage.
Account rejection may precede a prompt; that case alone accepts an actual early
exit-1 denial without sending input. SSH failure, timeout and exit-0 success
remain failures. Cancellation and wrong-response cases still require interaction.
The runner respects the native five-second failure cooldown between negative
conversations; it never restarts the owner, resets attempts or shortens that
production protection to obtain a later positive result.
After each elapsed denial cooldown and each successful consent, the runner also
requires the read-only protected presentation to return to the locked state.
A retired prompt or permanent denial screen cannot qualify as usable recovery.
The password-locked account case runs before the required successful consent
authentication. Cancellation and the incorrect response then precede the final
unlock on the same generation. Grouping all three denials consecutively can
legitimately trigger distribution PAM's three-failure lockout. The required real
consent authentication lets stock PAM process success between those groups;
the runner never clears a faillock tally or changes PAM policy. This follows
the upstream [PAM failure/success rules](https://github.com/linux-pam/linux-pam/blob/v1.7.1/modules/pam_faillock/pam_faillock.c).
Command stdout and stderr share a single bounded output budget. On failure the
runner reports only the exit status and fixed source-owned diagnostic categories;
authentication proof, executor dispatch, independent verification and native
generation acknowledgement have separate failure categories. Raw service
diagnostics never enter the report. An early exit still fails every
positive interaction case, including an exit-zero response or a recognizable
error category. Only the explicitly negative account-denial case can accept its
required early exit-one result.
Authentication and suspend reports retain the validated nonsecret managed
receipts, not just check booleans. Restart recovery must preserve every original
request/resource/transaction/effect field; valid-looking replacement digests fail.
Native release verification is deliberately one-shot: the first independent
postcondition changes the mechanism from Releasing to Released. The second
verification by reconciliation or observe-only restart recovery may read ONLY
the retained Released state for the identical current generation with fresh
independent unlocked compositor, clear native coverage, no secure request and
no active sleep fence. Ready, old generations, renewed coverage and failed
transport are never success. Durable committed-release acknowledgment alone
rotates the native generation; no guest qualification case or script was relaxed.
Consent history must preserve the approved record, and unlock history must name
the same committed transaction. Native assistive reports retain the exact owner
invocation/start identity and phase. No response bytes, account hashes, approval
seals or executor credentials enter these reports.

Reports are emitted only after all assertions and cleanup succeed, then bound to
bootstrap, exact-source binary identity and runner-source digests. They explicitly
do not qualify power, hotplug, compositor failure, native accessibility, physical
Q11 or complete S17. Component/mocked tests of this runner are not native evidence.
The new native cases have not yet been executed or retained as S17 acceptance.

The authentication runner also requires actual AT-SPI registry discovery of the
supervised native owner's locked and password-prompt presentations. The separate
`native-assistive-probe.cpp` client is built from exact source in the disposable
guest, with no product install target or authentication/input handles. A fixed
root guest wrapper validates immutable fixture ancestry, an unprivileged and
capability-free probe image, and the owner's PID, systemd invocation and process
start identity before and after each probe. The host binds that invocation to
the exact lock resource. Transport errors, owner replacement, unexpected report
fields and type aliases cannot become positive evidence.

Discovery starts from the registry's bounded application list and verifies the
supervised PID and exact application root. Multiple matching applications fail;
unrelated transport connections from that process are not applications. Only an
absent registration permits another read-only observation within the original
eight-second probe budget. Registry replacement, malformed replies, timeout and
ambiguous registration fail. Fixed probe-stage exit codes produce only categorical
failure diagnostics; raw service output remains suppressed.

These cases inspect the native registry's actual application/dialog/password
tree and require remote edit, action and relabel attempts to be rejected. Reports
and the built probe/source digests are retained with authentication evidence.
They remain **unexecuted** until that lane runs. They do not qualify Orca speech,
pointer interaction, scaling, hotplug or physical Q11, and never assert complete
accessibility or S17 support.

The owner's native sleep-unit probe uses bounded calls to the root-attested
systemd unique connection and the trusted system bus's requested-reply routing.
Newer Qt deliberately hides `service()` on reply/error messages; older Qt exposes
the sender, which must still match the pinned peer. The accessor is not portable
sender evidence. Two complete matching unit snapshots,
final owner revalidation, exact helper/launch/invocation checks and the original
two-second budget remain mandatory. Only repeated exact native `NoSuchUnit`
errors with unchanged owner establish absence. The isolated component CTest
`security-owner-sleep-supervisor-reply-boundary` exercises actual Qt/broker wire
replies, forged success/absence from another connection, malformed fields,
timeout, property reads and replacement. Its private same-UID bus is never
native root/systemd evidence or a substitute for the following suspend case.
That component test also uses an eight-request wire barrier: the fixture cannot
reply until every fixed property request has arrived. It verifies separate
changing samples and rejects duplicate/excessive admission, malformed/absent
members and late replies without returning a partial map. Production metadata
batches retain all original field comparisons and revalidation reads, the
500 ms per-call cap and each inspector's existing aggregate deadline.

The private `ObserveLock` operation composes fresh peer/session inspection and
independent compositor sampling. Like approval arm/consume, its reply uses only
the remainder of the original two-second probe, including discovery and final
identity/boot revalidation. Primitive metadata requests keep their 500 ms cap.
This avoids aborting a valid post-resume compound observation at a second,
unrelated primitive deadline. No clock restarts on reply, pending state cannot
become a boolean or envelope, and late/stale/substituted evidence still fails.

The native runtime now drains already available replies on its attested Wayland
connection between bounded metadata calls/waits. It does not run a nested Qt
event loop, retry a lock, cache an observation or renew a probe deadline.
Progress time consumes the original clock and all identity, scope, compositor
and final deadline checks remain. `security-owner-native-probe-progress` blocks
Qt event delivery across an unlock/re-lock cycle while the component server
withholds `locked` until a valid configured frame is committed. Native progress
must establish coverage inside the original five-second acquisition watchdog,
survive six seconds of successive reads, skip recursive pumping while painting,
and leave an ordinary queued Qt callback undelivered. Without progress, the
paired case must still exit 71 with zero unlock requests. This is component
coverage only; the exact-source native suspend and terminating cases remain
independently required. The batch fixture also rejects a progress callback that
exhausts the existing probe budget before sending any request.

`qualify-native-suspend.py` adds actual managed suspend/resume, independently
verified kernel-cycle/secure-coverage completion, Control restart with observe-only
transition recovery, then purpose-bound owner unlock. Its fixed guest helper
submits through production `linuractl` from a supervised service, after the SSH
login ends. Other-session predicates, inhibitors, native administrator PAM and
the protective gate are never bypassed. The helper cannot accept arbitrary
commands, native direct-suspend requests or response text. Authentication input is
not sent after a timing guess: a separate root-supervised qualification watcher
uses the existing read-only AT-SPI probe to require the exact purpose-bound
protected prompt and native focus, then writes bounded nonsecret prompt metadata
with a fresh token and sequence to the VM serial console. The host reads those
records from the already-open private QEMU log. For multiple eligible
administrators, it uses native Down/Enter keys to select the disposable account,
requiring a freshly attested menu state after each key. The original deadlines
remain shared across selection and password readiness. Only a focused password
prompt for that exact account permits the ephemeral response through QMP. The
serial token is synchronization only: it carries no credential, approval,
prepared binding, executor handle or completion claim, and cannot bypass any
product precondition. Private bounded records are not execution authority; a
queue receipt, prompt marker, transport failure, QMP wake reply or historical
transaction alone cannot qualify completion. The original queue identity and
exact lock/transition generation must survive every result check.
The watcher validates the exact phase and supervised owner invocation in the
read-only report before writing its marker. The host rejects a FIFO, substituted
or mutable log, excessive input, stale markers and incomplete or extended marker
lines. An eligible administrator may also be the session owner; UID inequality
cannot establish administrator authority. The pinned upstream
[administrator rule](https://github.com/polkit-org/polkit/blob/127/src/polkitbackend/50-default.rules.in)
selects a configured group, not a different UID. Official Polkit identity selection and
real PAM remain mandatory, including bounded multiple-identity handling.
Selection rejects absent owners, duplicate UIDs, changed counts, skipped or
repeated indices/sequences, and a changed supervised process identity. Zero
eligible administrators fail without sending a password. The fixture never
changes the eligible identities, sets another account's password, or resets PAM
failure state. The read-only probe still rejects remote input and relabel APIs.
The suspend worker also uses write-once submission admission, so service restart
cannot resubmit an uncertain effect. On failure, the host retains only fixed
worker stages, numeric exit statuses and source-owned diagnostic categories;
raw command output and exception text are never retained. These diagnostics
are explicitly failure-only and cannot qualify acceptance or bypass cleanup.
Terminating preparation also retains the existing bounded, closed owner-unit
state diagnostic when an initial lock fails before any worker can be queued.
Its failure preserves the original error and mandatory account cleanup; a
running owner or native success result cannot qualify the failed operation.
Session inventory uses bounded `loginctl --json=short` identities, then binds
fresh properties to each enumerated ID and UID. Each `loginctl` property has its
own `--property` option: unlike `systemctl`, this client treats a comma-separated list as one
literal name and can return an empty result with exit status zero. Property
selection is checked independently of subprocess acknowledgement. The
fixture follows the production classification: same-owner manager/background
sessions are not
other logins; foreign-owner service sessions and all other user, greeter and
lock-screen sessions block, including remote, inactive and closing logins.
Unknown classes, malformed/duplicate identities, changed generation and an
expired original twenty-second inventory deadline fail closed. No login is
terminated or hidden to clear that precondition. Logout recovery uses the same
machine inventory and matches the original UID and creation generation, so a
recycled session name is not mistaken for the original session. Failure records
retain closed inventory reason codes without account names or raw native data.
A refused inventory read discards the entire snapshot and repeats enumeration
within that same twenty-second deadline. This handles a departing SSH session
disappearing between listing and property lookup without declaring it absent.
Only a complete fresh inventory can admit submission; persistent refusal,
malformed state, identity drift and another login still prevent submission.
Failure records distinguish list refusal from property refusal without retaining
native diagnostic text.

`qualify-native-transition.py` adds logout, reboot and power-off cases. A fixed
root-supervised disposable-guest helper submits one production managed request
as the actual owner after other logins end. The same purpose-bound protected-prompt
synchronization replaces fixed-delay response injection for logout, reboot and
power-off. Its root-private write-once submission record prevents worker restart
from resubmitting; queued state is not authority
or evidence of dispatch. File and parent-directory synchronization retain the
exact request, purpose and original lock generation across orderly shutdown.

Reboot/power-off require a guest-originated QMP event, then an independently
different boot and production native postcondition verification. Host signals,
disconnects, acknowledgements and generic awake snapshots cannot pass. Logout
requires the original session to disappear on the same boot. All three require
two Control restarts with observe-only recovery of the SAME transaction/effect
and independently verified disposable-account relocking before any positive
report. An incomplete handoff explicitly requires cleanup; forced death or
cleanup failure invalidates the case and the private VM must be discarded.

The workflow boots only its freshly copied disposable disk with persistence,
never the prepared substrate/cache. After real power-off, it boots that SAME
private disk using the unchanged pinned topology and a new private QMP socket;
it does not resubmit the original request. Earlier shell-runtime evidence keeps
its original execution identity; terminating reports retain distinct original
and observed boot IDs, exact source, request, transaction and effect digests.
The [official QMP event contract](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#event-shutdown)
provides supporting event observations, not product execution authority.
The development runtime contract explicitly selects this disk mode for S17:
`guard-disposable-disk.py` independently rejects symlinks, hardlinks, public or
non-owned copies, excessive images, source/copy aliasing and initial digest drift.
It rechecks the original cached substrate digest after the destructive cases.
The gate admits exactly the two pinned private-copy launch commands; substituting
the prepared image, adding persistent boots or removing either guard fails.
The shared launcher still defaults to snapshot mode for every ordinary caller.
Disk guards alone are not execution or qualification evidence.

These suspend and terminating cases are wired into the same pinned lane but have
NOT run. Their mocked/component tests are not native evidence. Protective-consent
failure cases, multi-output, compositor failure and native accessibility remain
outstanding qualification work. S17 and Q11 are not promoted by these runners.
