# VM acceptance task guide

- Use disposable qcow2 guests; never run destructive acceptance tests on a contributor workstation.
- Add scenarios under `tests/acceptance/` using the versioned scenario schema.
- Scenarios should verify externally observable results and recovery, not implementation details.
- Record the exact image digest used for evidence.
- Missing QEMU/KVM/SSH means the system test was not run.

- For the v0.10 workstation, preserve the A/B/C evidence split: automated VM evidence is not maintained-hardware evidence, and an interactive VM must consume the same exact-source substrate/runtime contract rather than a convenience image.
- Keep automated mode headless at the host transport while allowing in-guest Wayland capture; interactive host display backends must be opt-in and bounded.

- Level C must reject virtualization independently on every run and must bind a validated root-owned maintained-fixture contract. A fixture label, video, cloud VM or generic bare-metal server is not sufficient physical-workstation evidence.
- Keep the Level C runner unable to promote support: Q11 readiness is set only by the later digest-bound complete case matrix after real physical execution.
