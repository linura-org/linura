# S17 native security owner: authentication and protected input

This component extends the #238-qualified native security-owner foundation with
authentication and protected-input boundary. It remains component-only: the
root-supervised runtime endpoint, managed sleep/power transition fences and final
workstation activation are introduced later.

The slice adds the official Polkit/PAM authentication adapter, exact Polkit daemon
identity attestation, protected secret storage, native keyboard/pointer handling,
the private Wayland lock client, fixed first-party presentation, and bounded
assistive metadata export. Authentication completion is never execution authority
and never directly releases compositor coverage.

Protected response bytes have no QML, clipboard, IME or public transport
representation. Same-UID presentation readers remain untrusted. Native input,
authentication state and lock/effect dispatch stay separate, fail-closed
boundaries.

When Polkit offers several administrator identities, the protected native field
shows each eligible numeric UID with bounded Up/Down navigation and explicit
Enter selection; the selected identity alone begins the official PAM exchange.
The candidate list is limited to eight unique Unix identities, expires under
the existing protected-input and approval deadlines, and is cleared on cancel,
focus loss, daemon cancellation, or owner loss. Session-owner authentication
still uses only the exact owner UID, never an alternative administrator.

Native Return unlock requests additionally require the currently displayed
first-party primary action to be enabled and geometrically valid. Error screens
and in-flight authentication deny duplicate keyboard retries, as does a missing
action observer. Pointer and keyboard paths recheck actionability at dispatch;
none of these presentation checks replace Control approval or PAM evidence.

The existing native identity, independently observed compositor state, exact
session scope, fail-closed acquisition/release and bounded readiness contracts
remain mandatory. Native authentication completion neither approves a Control
transaction nor authorizes privileged execution.

The trusted Unicode Compose table is the source-pinned X.Org `en_US.UTF-8` table
compiled into the native input component. Runtime filesystem ownership,
`XCOMPOSEFILE`, home/XDG paths, locale selection and recursive includes cannot
select or replace it. The bounded bytes must match the source-pinned SHA-256
before libxkbcommon compilation; missing, changed, oversized, NUL-containing or
include-referencing data remains a denied initialization. Source provenance,
digest and third-party license are recorded under `compose/`.

Canonical CI requires the official Polkit/PAM native-auth components and all
native CTests on the checked-out source, with authentication and testing both
explicitly enabled. This component-only evidence does not claim an activated
system service, physical protected input or workstation qualification.

## #240: managed transitions and supervised runtime

The private security-owner executable composes the existing protected input,
native lock, Polkit/PAM and independent compositor observation without handing
policy or execution authority to QML. The private SecurityOwner1 endpoint
freshly attests its Control and executor callers. A bounded pre-sleep fence
retains independent secure coverage for the exact systemd suspend job. A
separate transition fence binds the prepared managed effect to its transition
identity and rejects replay, competing transitions and unsafe unlocks.
Suspension success requires fresh kernel cycle evidence as well as current
secure compositor coverage. Missing/ambiguous results remain observe-only and
never trigger an automatic retry of a privileged effect.

The owner exports its private SecurityOwner1 object solely on a dynamic unique
system-bus name, not an ownable well-known service. The installed system-bus
policy denies other callers to the object path and admits only the
`linura-authority` and `root` Unix users on the exact private interface,
plus their exact read-only `Introspectable.Introspect` discovery operation.
Other metadata methods remain denied; introspection never grants authority.
Admission is not authority: each method independently reattests the actual
sender as the fixed supervised Control or session executor process. The policy
is installed at `/usr/share/dbus-1/system.d/org.linura.SecurityOwner1.conf`;
the interface XML alone does not authorize calls. CI checks this deployment
contract and rejects missing or broadened policy. The scoped real
systemd/PAM/Polkit native cases passed in [PR #241's Level A run](https://github.com/linura-org/linura/actions/runs/40141305916);
complete S17 and physical workstation qualification remain separate.

Deployment assets stage fixed root-supervised systemd service/path units,
an immutable D-Bus contract, fixed font configuration and an Arch package hook
for post-install capability establishment. CMake never grants a file capability
to a development build. Component-level composition and contract checks are supplemented by retained
Level A native evidence on implementation SHA
`a99511d5bd22afa5dcf7878a3fb9e0feca74c87f` for the declared real
session/PAM/systemd/power and bounded assistive-probe cases. Full accessibility,
additional native scenarios, complete S17 and physical Q11 are not qualified.
The merged Unicode Compose, native keyboard actionability and exact-owner
authentication semantics remain required.

Component validation:

```sh
cmake -S apps/linura-shell/security-owner -B .artifacts/s17-native-auth -G Ninja \
  -DLINURA_SECURITY_OWNER_NATIVE_AUTH=ON
cmake --build .artifacts/s17-native-auth
ctest --test-dir .artifacts/s17-native-auth --output-on-failure
```
