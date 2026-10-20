# S17 native authentication and protected input

This stacked slice extends the native security-owner foundation with the
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

The repository's pinned native-auth builder is development/component evidence
only. It is network-isolated at execution time and does not claim native
workstation qualification.

Component validation:

```sh
cmake -S apps/linura-shell/security-owner -B .artifacts/s17-native-auth -G Ninja \
  -DLINURA_SECURITY_OWNER_NATIVE_AUTH=ON
cmake --build .artifacts/s17-native-auth
ctest --test-dir .artifacts/s17-native-auth --output-on-failure
```
