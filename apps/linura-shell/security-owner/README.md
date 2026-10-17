# S17 native security owner (in progress)

This is separate from the ordinary shell bridge. Its native mechanisms implement
bounded exact-scope conversations, compositor transition tracking and native-only
password storage. Nothing here independently plans, authorizes, prepares or
recovers an external effect. Control owns those stages.

Authentication completion cannot mutate lock state. A conversation's confirmation
expires after two seconds and is consumed once for exactly the sealed request,
plan, principal, lock invocation/generation and three canonical digests. It is
not a reusable executor credential. Conversation timeout, cancellation, excessive
prompts, denial, rollback and native-owner loss fail closed. Password storage has
no QML/transport representation and refuses input when locked, non-dumpable,
non-inherited memory cannot be established.
Absent/throwing response callbacks wipe the entered text. A live response mapping
cannot be reopened for another prompt. Official helper next-prompt/completion
callbacks are deferred until the mapping is wiped, and native success requires
an actual protected submission. The official adapter compiles and its component
boundary tests pass in the repository's snapshot-pinned development builder;
real PAM/account and native session qualification remain unexecuted.

The private runtime additionally requires protected secure-exec startup,
whole-process memory residency before input, and bounded native connection
deadlines. The first Wayland socket may precede Hyprland's required control
socket, so one named compositor-readiness contract performs a race-safe
scan-watch-rescan over bounded Linux filesystem events. Only route-topology
events consume the event budget and cause complete strict route discovery;
unrelated runtime traffic is drained without granting readiness. Queue overflow,
excessive relevant churn, watcher failure, partial routes and a five-second
monotonic deadline all fail closed.
Events are availability hints, never identity or authority, and service-wide
restart remains disabled. Startup checks the kernel-established `AT_SECURE` marker; changing
dumpability after ordinary exec is insufficient. The privileged exec must begin
in Linux dumpability state 0 or root-only/safe-path state 2, both of which deny
unprivileged same-UID ptrace; the owner immediately forces and reads back state 0
before capability use, memory locking, native input or Qt initialization.
User-dumpable and unknown states fail closed. Saved user/group identity
escapes and unexpected privileges are rejected. Supervised native service identity uses UID, main PID, invocation and
the exact root-systemd launch record (fixed image/argv, no ignored launch failure,
same running PID, no extra executable);
ordinary local/root callers do not acquire that identity by claiming a name.
Startup binds the **actual** Wayland connection peer to a qualified native login
session leader. The owner's bootstrap also requires its running image's inode to
match the root-immutable packaged executable, the exact single systemd launch,
and fresh matching active session/service facts. These checks are implemented, but their positive operating-system
deployment/ptrace/memory/Wayland behavior is not proved by pure component tests.

The compositor mechanism distinguishes requested locking, native secure coverage,
requested release and independently observed release. Authentication success,
logind `LockedHint`, an unlock acknowledgement and shell window counts are not
postcondition evidence. Independently verified release retains the old resource
until trusted Control acknowledges its durable verified commit. This fence keeps
crash-before-commit verification/recovery addressable and blocks new effects in
the meantime. Only then does generation advance; authentication binding rotates
exactly once with no outstanding proof and no cooldown bypass. An unexpected
native-owner/coverage loss is terminal for that invocation.

`NativeLockProtocol` is a C++-only adapter for the private runtime's single
guarded lock backend. It rejects shadowed/aliased native properties, writable coverage,
pre-existing locks and cross-thread bindings. Native acquisition/release budgets
use suspend-inclusive time and a separate watchdog for blocked native calls.
Owner loss, reload, unrequested state, coverage loss and active destruction exit
without QObject/Wayland cleanup. Native release callbacks do not advance the
generation or substitute for independent verification and Control's commit.
Its compiled typed-backend fixture tests are component results, not Quickshell
or compositor qualification. Metadata is not object provenance. Production must
create the lock privately after process/session attestation, retain its native
handle outside presentation contexts, and supply the surface component from an
isolated presentation context that cannot address the lock object. Simply
watching an exposed QML `locked` property is unsafe: detection after a QML write
cannot undo an unauthenticated protocol release. The private native runtime now
creates and retains the backend after secure-exec and same-connection native
session attestation; it is not a shell/QML object. Production Control/executor
composition and native deployment still need completion and qualification.

Unmodified upstream Quickshell is explicitly rejected: its surface-creation
failure path can invoke `unlock()` independently of Control. A production native
backend implements the private C++ `NativeManagedLockBackend` contract and
check its installed gate **before every** protocol acquisition/release, including
error cleanup and hotplug. The gate permits one exact dispatch call frame and
rechecks suspend-inclusive expiry immediately before the effect; it is never
exposed through QML, a credential or a client API. Unexpected error-cleanup
release attempts terminate without sending release. `NativeWaylandLock` owns an
exclusive actual Wayland connection and generates client bindings from official
distribution XML in the build directory. It has one release-opcode site, gated
before transmission; surface failure, renderer failure, hotplug and destruction
have no release fallback. Opaque SHM storage has bounded dimensions, aggregate
memory and in-flight slots; presentation coalesces under buffer pressure. Native
`locked` and release-sync events track local protocol state only. The official
server API harness tests wire behavior, not actual compositor security. Runtime
attestation, production runtime composition and deployment remain required
within S17 before activation.

`NativeKeyboard` reads the owned connection's qualified keyboard seat directly.
Configured owned-surface focus and acknowledged secure coverage are separate
requirements. Held keys, duplicate presses and compositor repeat never submit a
response. Unicode layout/compose input uses xkbcommon and a fixed root-owned
system compose table, not user-selected imports. UTF-8 is validated atomically
into protected storage without an owning Qt string/key-event copy; the bounded
native temporary is wiped on normal and exceptional exits. Once bound, generic
Qt key events cannot edit, submit or cancel a native prompt. Focus/keymap/keyboard
loss cancels and wipes; no clipboard, IME or QML key queue receives response text.

The same native seat now handles pointer events on configured owned surfaces.
Only a fresh primary-button press/release on the same enabled fixed presentation
target and prompt/state revision within one BOOTTIME second can request intent,
submit a protected response or cancel. Drag-away, duplicate presses, unmatched
release, device/focus loss and changed prompts invalidate the click. Submission
also requires native keyboard focus and secure coverage. Generic Qt mouse events
cannot focus protected input, and QML buttons have no authentication handlers.
The fixed software cursor uses no user theme or additional surface. Per-output
hit testing uses that output's configure dimensions, not the last-painted screen.

`NativePresentation` embeds the actual first-party semantic UI component sources
and renders the fixed private scene through Qt's software render control into the
backend's opaque bounded buffers. Import routes are restricted to embedded
resources and distribution Qt modules; no source/user/network scene is selected.
Native authentication storage is not a context property. Different generated
response values with identical masked lengths render identically in component
checks. The Wayland harness also exercises input and rendering together. These
checks do not qualify visual appearance, native pointer interaction, screen-reader
discovery, PAM or real compositor coverage. Pre-lock confirmation now uses a fixed
private xdg-shell surface on the same owned connection, before native lock
acquisition. Its Enter/Escape interaction never decodes response text, consumes
held/repeated keys or dispatches an effect. Close, focus/keymap/keyboard loss,
cancellation and suspend-inclusive expiry deny the interaction. Complete native
interaction/accessibility qualification remains required.

The offscreen Qt factory is not a native screen-reader bridge. The private
`NativeAssistiveBridge` now exports a bounded standard AT-SPI application/dialog/
password-role tree using official GIO APIs. It connects only to the fixed own-UID
session bus and a strictly parsed own-runtime AT-SPI Unix socket, independently
checks kernel peer UID, and never accepts ambient bus/address overrides. These
peers are untrusted presentation readers, not policy, authentication or current
lock-state authorities. No second Wayland connection or private Qt header is used.

The projection contains only the actual first-party heading/explanation, typed
fixed prompt label and presentation focus/availability metadata. It never includes
response contents, length, cursor, selection or raw PAM questions. Text, value,
editable-text, action and component/geometry interfaces are absent; the only
standard writable field is an unused bounded registry application ID. Reading,
writing that bookkeeping ID or sending unsupported input methods cannot confirm,
authenticate, dispatch, unlock or change the native presentation. Native hardware
keyboard/pointer input remains the separate protected path.

Dedicated bounded worker dispatch keeps assistive readers off the native input
thread. Connection attempts cancel on an original two-second budget; registration
is asynchronous to service the standard registry handshake without deadlock.
Registry replacement or transport closure retires the export; bounded read-only
reconnection cannot restore approvals or replay effects. Metadata failure never
releases coverage. Component wire/projection tests are not retained real AT-SPI,
Orca, pointer or physical-workstation qualification; those remain required.

The independent Hyprland release probe performs one fixed `j/locked` request on
an actual connected socket whose kernel UID/PID match the compositor bound to
the actual Wayland connection. It has a 500ms total deadline and 64-byte response
bound; duplicate/unknown keys, coercion, trailing bytes and substituted routes
fail closed. Its parsed adapter-local result is not an observation envelope or
an executor credential. Native runtime composition must revalidate the original
session and emit canonical evidence; native positive execution is unqualified.

The default target builds a secure native executable and private
mechanism libraries, with component tests. The native-authentication target requires
the distribution's `polkit-agent-1` development package and uses the official
protected helper conversation. `NativeStartup` requires kernel-established
protection before Qt, removes toolkit/import/font/compose/bus overrides and
disables user QML disk caches. `NativeRuntime` privately composes the same owned
connection, session/bootstrap, protected renderer, authentication and gated native
backend. Its `org.linura.SecurityOwner1` adapter exports only on its canonical
system-bus unique connection, without a preclaimable per-user well-known name.
Each call freshly attests the received Control/executor sender and native session;
approval, independent observation, prepared dispatch and durable commit
acknowledgement remain separate methods. Compiled Qt metadata/wire signatures are
checked against the canonical XML. Ordinary exec and late dumpability changes
cannot start the runtime. These are component checks, not positive OS attestation.
The install target stages the executable, root-supervised system service/path,
fixed font policy and root `user@.service` activation dependency. The image's
fixed libcap transaction hook establishes the sole file capability after final
ownership. The ordinary host/build containers never run that installation hook.
Authority1 now composes managed lock/unlock, durable request retention and
observe-only recovery with the narrow root executor. SDK/CLI and the native
Enter interaction use that same authority path; a public reply never proves
authentication or native release. These implementations are not retained native
qualification evidence. Managed suspend/logout/reboot/power-off, typed SDK/CLI
and first-party session/power controls are implemented, including no-replay
recovery and native coverage fencing. Complete native inhibitor lifecycle,
pointer/accessibility qualification and adversarial Arch/Hyprland evidence remain
unfinished within S17. These are not production support claims.

Targeted component validation:

```sh
cmake -S apps/linura-shell/security-owner -B .artifacts/s17-security-owner -G Ninja
cmake --build .artifacts/s17-security-owner
ctest --test-dir .artifacts/s17-security-owner --output-on-failure
```

A prepared Qt development environment without native Polkit headers may explicitly
configure `-DLINURA_SECURITY_OWNER_NATIVE_AUTH=OFF` to run **only** mechanism/input
component tests. That is not an authentication build or native qualification.
