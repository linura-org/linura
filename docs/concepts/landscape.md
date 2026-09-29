# Landscape and architectural boundaries

> **Status:** Non-normative  
> **Last externally verified:** 2026-09-29

Linura does not exist in isolation.

Agent sandboxes, policy engines, configuration-management systems, declarative operating systems, container runtimes, and opinionated Linux desktops each solve parts of the broader problem of making computers safer, more reproducible, or easier to operate.

Linura overlaps with several of these categories, but is not defined by any one of them.

Its central architectural boundary is:

> **Probabilistic systems may propose changes. They do not become the authority that decides what machine state is true, what changes are allowed, or whether those changes completed successfully.**

Linura places an independent control and execution plane between intent and authoritative machine effects.

The intended authority path is:

`request/intent → observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile`

The source of intent may be a human, graphical interface, CLI, AI agent, automation, or another trusted system component. The authority model remains the same.

## Why this document exists

Landscape comparisons serve three purposes:

1. clarify which problems Linura is and is not trying to solve;
2. identify established systems whose techniques can strengthen Linura;
3. prevent architectural drift caused by treating a neighboring product as the definition of Linura.

These comparisons are descriptive, not rankings. External systems evolve quickly, so factual comparisons are dated and should be revalidated against upstream documentation.

Normative Linura architecture must never depend on a comparison remaining true.

## A useful maturity model

The following generations are a **Linura conceptual taxonomy**. They are not an established industry classification, and real systems may span more than one generation.

### Generation 1 — model and application guardrails

The primary safety boundary remains close to the probabilistic system.

Typical mechanisms include system prompts, model policies, tool allowlists, LLM-based judges, confirmation dialogs, application-level permission checks, and output validation.

These mechanisms remain useful, but the model or application is still responsible for a significant part of the trust decision.

A failure in reasoning, orchestration, prompting, or application logic may therefore cross directly into effects.

### Generation 2 — isolated execution

The primary safety boundary moves outside the model and around its execution environment.

Typical mechanisms include containers, microVMs, sandboxes, isolated filesystems, network allowlists, credential brokers, restricted tool gateways, and disposable environments.

This is a major improvement. The agent can be given substantial freedom inside a bounded environment without receiving equivalent authority over the host.

The central question becomes:

> **Where may this workload execute, and what resources may cross its sandbox boundary?**

Modern systems in this category may also contain capabilities that resemble Generation 3. The generations are architectural tendencies, not mutually exclusive product labels.

### Generation 3 — independent deterministic authority

The critical authority decision moves into an independent control plane.

The proposing system no longer determines by itself:

- whether an action is authorized;
- what exact authority is required;
- how an effect reaches the managed system;
- whether the intended state was actually reached;
- whether the result remains valid;
- whether recovery or reconciliation is required.

The central question becomes:

> **What state transition is being requested, is it authorized, what effects are permitted, what state actually resulted, and what should happen if reality diverges from intended state?**

This is the architectural family Linura belongs to. It is not unique to Linura.

Modern agent runtimes such as NVIDIA OpenShell already contain a distinct control plane, independent runtime enforcement, declarative policy, and policy verification. Linura's distinction is the **scope and object of authority**: the managed machine state itself rather than an AI-agent sandbox as the primary object.

## Architectural maturity matrix

| Dimension | Generation 1 — model/application guardrails | Generation 2 — isolated execution | Generation 3 — independent deterministic authority |
| --- | --- | --- | --- |
| Primary boundary | Model or application | Sandbox / container / VM | Independent control and execution plane |
| Primary question | Should the model do this? | What can this workload access? | What state transition is authorized? |
| Authority | Application- or model-mediated | Environment-scoped | Explicitly resolved outside the proposer |
| Execution | Tools called relatively directly | Execution inside isolated runtime | Authorized effects executed or delegated through controlled interfaces |
| Verification | Tool results, application checks, model interpretation | Runtime results and sandbox policy enforcement | Independent observation of authoritative post-state |
| Failure handling | Application-specific | Reset, snapshot, teardown, retry | Rollback, compensation, reconciliation, or explicit degraded state where supported |
| Long-lived state | Usually application-owned | Usually environment/session-owned | State is part of the managed-system model |
| Audit | Conversation/tool traces | Sandbox/runtime logs | Intent, authorization, effects, observations, and verification can be bound into one lifecycle |
| Proposer trust | Often relatively high | Reduced through isolation | Proposer is explicitly non-authoritative |
| Typical object | Agent/application interaction | Agent workload | Managed state transition |

## Where Linura fits

Linura's model can be summarized as:

> **Many interfaces. One machine model. One authority path.**

An AI agent is therefore not a privileged architectural category. It is one possible producer of intent.

A human using a GUI, a CLI command, an automation rule, and an AI agent should ultimately cross the same authority boundary when requesting equivalent machine effects.

The model is intended to span Linux host state, system services, user-session state, applications, devices, containers, virtual machines, agents, managed configuration, and workflows composed from those capabilities.

This does **not** imply that every environment is already release-qualified.

### Architectural

The behavior or abstraction Linura is designed to support.

### Implemented

The behavior exists in the codebase.

### Release-qualified

The behavior has passed the required qualification contract for a declared platform/profile and release.

A landscape comparison describes the **architectural model** unless it explicitly says otherwise.

## What Linura is not

### Linura is not an LLM safety layer

Prompt controls, model policies, and agent reasoning may participate in a workflow, but they are not the final machine authority.

Linura should remain useful even when the proposer is treated as untrusted.

### Linura is not merely an agent sandbox

Sandboxing is valuable and may be one execution mechanism beneath Linura, but isolation answers a different question from machine-state authority.

A sandbox can constrain an agent while still knowing nothing about whether a host service should remain enabled, a particular audio sink should have a requested volume, a device should be mounted, two requested system changes conflict, or observed machine state still matches intended state.

### Linura is not a container runtime

Linura may control or coordinate container operations. It should not replace the isolation, image, namespace, storage, or scheduling machinery already provided by container runtimes and orchestrators.

### Linura is not simply configuration management

Configuration-management systems are important precedents for desired-state reasoning and reconciliation.

Linura's intended scope additionally includes interactive state transitions, per-effect authorization, human and agent intent, runtime observations, desktop/session state, evidence-bound verification, capability composition, and immediate user-facing effects.

### Linura is not a desktop distribution

Linura has a desktop experience, but the desktop is a surface over the system model.

A desktop distribution can decide what packages, themes, applications, and defaults make a good workstation. Linura instead asks how those state changes become authorized, observed, verified, and maintained.

## Comparison principles

### Compare scope before features

Two systems may expose similar features while solving different problems.

### Do not use better as an architectural category

Prefer strength, tradeoff, scope, authority boundary, integration opportunity, and different goal.

### Give neighboring systems credit for their strongest properties

Linura does not become stronger by understating other systems.

### State Linura's own tradeoffs

An independent machine control plane introduces additional architectural complexity, adapters for platform-specific semantics, a larger correctness burden around observers and executors, versioned authority contracts, lifecycle and recovery semantics, qualification work across supported platforms, and careful handling of partial failure.

Those costs are justified only where stronger machine-state guarantees are valuable.

### Separate present reality from intended architecture

Never describe an architectural target as release-qualified merely because it exists in the design.

## The boundary in one sentence

Agent sandboxes primarily constrain **where computation may act**.

Configuration systems primarily describe **what configuration should exist**.

Desktop distributions primarily define **what the workstation should contain and feel like**.

Linura is intended to govern **how intent becomes authoritative machine state and remains consistent with that authority**.

## Related landscape documents

- [Agent runtimes and execution sandboxes](landscape/agent-runtimes.md)
- [Configuration management and declarative systems](landscape/configuration-management.md)
- [Linux desktops and Omarchy](landscape/linux-desktops.md)

## Maintenance policy

All documents in `docs/concepts/landscape/` are non-normative.

External projects may be added when they clarify an architectural boundary, but they must not become dependencies of Linura's conceptual definition merely because they are used as examples.

Each comparison should include the date it was last externally verified, the external system's stated primary purpose, factual architectural characteristics, overlap with Linura, differences in scope, strengths, tradeoffs, and potential composition points where relevant.

Avoid winner/loser language, marketing superlatives, claims that Linura invented established systems concepts, claims that another project lacks a capability without checking current upstream documentation, and treating the current Linura implementation as equivalent to the complete intended architecture.

When an external project changes substantially, update the landscape document. Do not redesign Linura merely to preserve an old comparison.

> **External systems explain the landscape. They do not define the architecture.**
