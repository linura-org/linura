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

Component validation:

```sh
cmake -S apps/linura-shell/security-owner -B .artifacts/s17-native-auth -G Ninja \
  -DLINURA_SECURITY_OWNER_NATIVE_AUTH=ON
cmake --build .artifacts/s17-native-auth
ctest --test-dir .artifacts/s17-native-auth --output-on-failure
```
