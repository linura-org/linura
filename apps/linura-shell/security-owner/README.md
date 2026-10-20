# S17 native security-owner foundation

This stacked slice introduces only the fail-closed native identity and compositor
foundation for S17. It does not activate a security-owner service and does not
include native authentication, protected input, accessibility, suspend or power
transition behavior.

The foundation provides bounded secure-startup primitives, exact native session
binding, exact compositor peer/route observation, a race-safe Wayland/Hyprland
readiness contract, and the native lock state machine. Filesystem events and
socket publication are availability hints only; success still requires strict
route discovery and exact native peer/session identity.

No identity, request ID, digest, observation or lock state becomes execution
authority. Control remains the policy/orchestration authority and the privileged
session executor remains a separate bounded execution boundary.

Component validation:

```sh
cmake -S apps/linura-shell/security-owner -B .artifacts/s17-security-owner-foundation -G Ninja
cmake --build .artifacts/s17-security-owner-foundation
ctest --test-dir .artifacts/s17-security-owner-foundation --output-on-failure
```

This is component evidence only. It is not native authentication evidence,
workstation qualification, support promotion or a release claim.
