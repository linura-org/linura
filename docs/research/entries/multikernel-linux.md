# Technology: Multikernel Linux

**Record ID:** `multikernel-linux`  
**Scope:** Possible future Linux kernel-instance execution substrate on compatible physical hosts.

The authoritative classification, owner, and review dates live in the [technology radar](../technology-radar.md). This entry does not approve implementation or a release target.

## Summary and motivation

The out-of-tree Multikernel Linux (mklinux) project explores running separately booted Linux kernels on one bare-metal host. Its stated approach assigns CPUs, memory, and devices to spawned kernel instances instead of hosting them under a conventional hardware-virtualization monitor. It could one day offer a different resource- and workload-isolation option for Linura; it is **not** a proposed replacement for KVM or existing container support.

## Evidence and source provenance

Sources reviewed on **2026-10-10**:

- **Primary upstream announcement (2026-08-25):** [mklinux v7.0-mk2](https://lkml.iu.edu/2608.3/04006.html) describes the first public tree release, x86_64-only support for that release, instance boot via `kexec_file_load()`, resource allocation through device trees/overlays, and developer-reported benchmarks. Those benchmarks are *upstream claims*, not independently reproduced Linura results; selected microbenchmarks are not evidence of overall workload superiority.
- **Source:** [multikernel/linux](https://github.com/multikernel/linux), upstream tag `v7.0-mk2` as identified in the announcement. The repository's presence does not establish mainline Linux availability, long-term maintenance, or a supported distribution profile.
- **Management component:** [multikernel/kerf](https://github.com/multikernel/kerf) documents resource pools, validation, instance lifecycle, and a CLI. Published documentation is not evidence of all capabilities working or of secure lifecycle recovery on Linura-supported hardware.
- **Primary design/security discussion (2025-09-20):** [kernel mailing-list thread](https://lists.openwall.net/linux-kernel/2025/09/20/558) explicitly characterizes isolation as **kernel-enforced**; the author acknowledges a malicious kernel could disrupt another. The 2026 release announcement reports fault-containment testing, but does not independently establish hostile-kernel isolation.

**Not verified by Linura:** independent performance, available device/CPU configurations, malicious-guest containment, DMA/interrupt/memory protection, management API stability, restart recovery, mainline acceptance, or supported hardware matrix.

## Benefits and architectural fit

Potential benefits to measure, not promises: lower overhead for some workloads than KVM, independent kernel behavior unlike shared-kernel containers, and explicit partitioning of hardware resources. If demonstrated, expose kernel-instance observation and narrowly typed lifecycle/resource effects through a future provider. Keep domain semantics and authority inside Linura Control; provider-specific kernel mechanisms remain adapters. No second policy plane, executor escape hatch, or competing lifecycle is permitted.

## Security and trust boundaries

- Kernel-enforced isolation is **not equivalent** to hardware-enforced guest isolation. Do not admit arbitrary or adversarial kernel images to production based on current claims.
- Treat spawned kernels as potentially hostile when threat-modeling cross-instance memory access, interrupts/IPIs, DMA/IOMMU, device ownership, host control channels, kernel-image signature, and boot/update supply chains.
- Require a bounded operation model with explicit resource ownership, positive and negative admission validation, revocation, crash containment, resource reclamation, idempotence, and truthful indeterminate outcomes.
- Observations and postconditions must be independently derived from trusted host/hardware sources; a spawned kernel's self-report or the management tool's success receipt is insufficient.
- Any privilege or consequential external effect remains under Linura's full managed-mutation authority, durable prepare/recovery, independent verify, audit, and reconciliation path.
- Conduct investigations only on explicitly disposable non-production systems, with crash/restart and corruption/failure-injection coverage.

## Alternatives and costs

Baselines: current Linura host execution and containers for shared-kernel workloads; KVM/QEMU with hardware virtualization for separate-guest-kernel workloads; no new substrate. An out-of-tree kernel may impose substantial maintenance, kernel upgrade, device support, reproducibility, and operational recovery costs.

## Investigation and acceptance gates

**Watch → Assess:** A maintainer defines a measurable unmet need or a falsifiable improvement hypothesis versus existing substrates, identifies an accountable evaluator and test hardware, surveys kernel/project maturity and licensing, and opens a scoped Issue with falsifiable hypotheses, KVM/container/native comparators, and a time/resource budget.

**Assess → Adopt (not scheduled):** Require reproducible pinned-source boot/stop/reboot and resource-allocation tests; stress, restart, rollback, reclamation and crash tests; isolation review with malicious-kernel, CPU/IPI, DMA and device-mapping attack cases; reliable independent observation/verification; representative performance/power benchmarks with variance and comparable isolation settings; portability, kernel tracking, licensing and support review. Stop or Hold on unacceptable isolation or unrecoverable resource-ownership failures. A future provider/trust-boundary proposal must go through Linura's RFC process and an ADR where it changes durable architectural decisions; release support still needs separate qualified evidence.

## Reassessment triggers

A materially improved upstream isolation design with credible independent security evaluation; independently reproducible benchmarks for a Linura-relevant workload; a stable resource-management interface; meaningful upstream acceptance/maintenance evidence; or a demonstrated use case that existing KVM/container options cannot satisfy.

## Links and decision log

- **2026-10-10:** Initial research entry recorded from the upstream release and kernel mailing-list evidence. No Linura benchmark, security qualification, RFC, ADR, implementation issue, or release milestone is claimed. Reassessment is governed by the radar.
