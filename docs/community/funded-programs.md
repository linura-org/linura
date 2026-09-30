# Sponsor-funded programs

Linura sponsorship should fund concrete engineering outcomes, not vague influence.

A funded program is a bounded workstream with a public purpose, named scope, evidence expectations, and an explicit authority boundary. Funding can accelerate work; it cannot lower the criteria by which that work is accepted.

## Program lifecycle

Every material funded program should follow the same lifecycle:

1. **Proposal** — define the problem, why it matters to Linura, and why sponsorship is appropriate.
2. **Scope** — name deliverables, exclusions, evidence, term, dependencies, and reporting expectations.
3. **Agreement** — identify the verified receiving party, sponsor, amount or in-kind commitment, recognition terms, and contract boundary.
4. **Execution** — perform work through normal Linura architecture, security, review, and release processes.
5. **Evidence** — publish appropriate qualification, documentation, release, or implementation evidence without exposing confidential material.
6. **Close** — report what shipped, what did not, remaining risk, and whether any follow-on work is proposed.

A sponsor may fund an outcome. Linura retains authority over implementation and acceptance.

## Initial 12-month programs

These are the first program shapes Linura can use in institutional sponsorship conversations. They are not promises that every item is currently scheduled.

### Agent Authority and Security

Purpose: harden the boundary between probabilistic agent proposals and authoritative machine mutation.

Potential outcomes:

- external review of privilege and policy boundaries;
- adversarial qualification of authorization and execution paths;
- capability and consequence classification hardening;
- audit/provenance integrity work;
- recovery and rollback validation;
- security documentation suitable for enterprise review.

Evidence may include threat models, qualified test cases, architecture records, security fixes, and independently reviewable acceptance evidence.

### Workstation and Platform Qualification

Purpose: expand from the current narrow reference environment toward explicitly supported workstation/platform profiles without making the core architecture distro-specific.

Potential outcomes:

- additional Linux platform profiles;
- reproducible qualification environments;
- compositor/session/network/audio/storage integration evidence;
- installer/bootstrap qualification;
- bounded support matrices and known-limit documentation.

### Hardware and GPU Qualification

Purpose: build trustworthy evidence across representative CPU, GPU, workstation, and server hardware.

Potential outcomes:

- AMD, Intel, NVIDIA, Arm, or other architecture/device matrices;
- GPU/driver and compute-stack observations;
- firmware and device compatibility evidence;
- real-hardware acceptance runners;
- sanitized hardware evidence suitable for regression tracking.

A hardware sponsor does not receive a favorable result by funding the program. Unsupported or failing configurations remain reported as such.

### Reproducible Acceptance and CI Infrastructure

Purpose: make Linura qualification repeatable across disposable environments and independent infrastructure.

Potential outcomes:

- VM/image acceptance expansion;
- architecture matrix coverage;
- deterministic release evidence;
- long-running reliability and failure-injection lanes;
- independent artifact verification;
- dedicated compute or CI capacity.

### Bootstrap, Installer, and Recovery

Purpose: make adoption, reinstall, ownership transfer, upgrade, rollback, and recovery dependable enough for real workstations and managed estates.

Potential outcomes:

- installer/bootstrap hardening;
- restart-safe provisioning;
- recovery media and rollback workflows;
- profile adoption and migration evidence;
- failure-safe ownership transfer;
- documented disaster-recovery paths.

### Fleet and Control-Plane Readiness

Purpose: extend single-machine authority semantics into managed multi-machine environments without introducing a second authority model.

Potential outcomes:

- fleet identity and policy boundaries;
- signed profile distribution;
- evidence aggregation without replacing machine truth;
- air-gap and controlled-network qualification;
- enterprise policy/provenance evidence packs;
- design-partner fleet pilots.

## Program record

For every material funded program, Linura should be able to produce a record containing at least:

```text
program_id
program_name
sponsor
relationship_type
term
scope
out_of_scope
status
recognition
reporting_cadence
disclosure_mode
evidence_links
decision_authority = Linura
```

The receiving entity, exact amount, invoice details, tax records, credentials, confidential contract terms, and other sensitive financial information belong in private accounting/contract systems rather than the public repository.

Internal prospect lists, sponsorship ask ranges, warm-introduction paths, negotiation notes, and sponsor-specific commercial strategy are also private operating data. They are not part of the public funded-program record unless Linura deliberately discloses a specific item.

## Acceptance boundary

Funded work is never accepted merely because it was paid for.

A funded change must satisfy the same architecture, security, testing, qualification, review, and release rules as other changes. If the work fails those requirements, the correct outcome may be a failed experiment, a documented incompatibility, a redesigned scope, or no merge at all.
