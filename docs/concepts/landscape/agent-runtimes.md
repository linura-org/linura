# Agent runtimes and execution sandboxes

> **Status:** Non-normative  
> **Last externally verified:** 2026-09-29

AI agents increasingly need meaningful machine access. They read repositories, execute commands, install dependencies, call external services, access credentials, and produce persistent effects.

Giving an unconstrained probabilistic process direct authority over a developer workstation or production environment creates an obvious security problem.

Agent runtimes address this by placing deterministic boundaries outside the model.

Linura shares this premise. The primary difference is **what the control system considers its managed object**.

## NVIDIA OpenShell

NVIDIA OpenShell is an agent runtime built around three stable components:

- a user-facing CLI / SDK / TUI;
- a **Gateway**, documented as the control plane;
- a **Supervisor** running inside each sandbox workload.

The Gateway owns durable platform state including sandbox lifecycle, authorization, policy and settings delivery, provider configuration, and runtime coordination.

The Supervisor launches the agent as a restricted child process and enforces sandbox-local controls including process identity, filesystem access, network egress, credential injection, inference routing, security logging, and lifecycle logging.

OpenShell can target local Docker, Podman, or VM-backed runtimes and remote Kubernetes while retaining the same gateway/sandbox model.

Its policy system independently constrains filesystem, process, network, credential, and related runtime behavior.

OpenShell also provides a policy prover using an SMT solver. The prover can test whether the authority represented by a candidate policy remains inside an operator-defined boundary for the policy domains it models.

OpenShell's own documentation is careful about the guarantee: a passing boundary check proves containment only for modeled policy behavior. It does not establish that the policy is least-privilege, semantically safe for a particular task, or actually enforced by a particular running sandbox.

### OpenShell and Linura

OpenShell and Linura share several architectural ideas.

Both reject the assumption that a probabilistic agent should itself be the security authority.

Both move authority into deterministic software outside the model.

Both value declarative policy, explicit authorization, fail-closed behavior, controlled execution, durable state, auditability, and stable semantics above platform-specific adapters.

The primary difference is the managed object.

#### OpenShell

The primary object is an **agent workload running inside a governed sandbox**.

A representative question is:

> What may this agent process access, and under what sandbox policy may it execute?

#### Linura

The primary object is an **authorized transition in managed machine state**.

A representative question is:

> What machine change is being requested, is that transition authorized, how should it be executed, what authoritative state resulted, and should that state remain true?

An agent may initiate such a request, but the agent is not the center of the Linura model.

### Comparison

| Dimension | OpenShell | Linura |
| --- | --- | --- |
| Primary object | Agent sandbox/workload | Managed machine state |
| Primary proposer | Autonomous agent workload | Human, agent, GUI, CLI, automation, or system component |
| Control plane | Gateway | Linura control/authority plane |
| Runtime enforcement | Supervisor + runtime isolation/policy | Capability-specific authorized executors plus underlying OS/runtime controls |
| Isolation | Core architectural capability | Execution mechanism used where appropriate |
| Policy | Sandbox filesystem/process/network/credential policy | Authority and capability policy around requested machine effects |
| Policy verification | SMT-based containment prover for modeled policy domains | Deterministic authorization and verification are architectural requirements; proof mechanisms are capability/domain specific |
| Postcondition verification | Security/policy/lifecycle domain rather than a general host-state abstraction | Intended first-class part of a managed state transition |
| Desired machine state | Not the primary abstraction | Central architectural abstraction |
| Reconciliation | Gateway delivers desired sandbox configuration; supervisor maintains runtime relationship | Intended to reconcile managed machine state against authoritative desired state |
| Desktop/session state | Outside primary purpose | First-class intended domain |
| Agent-specific infrastructure | Strong | Agent is one proposer among several |
| Kubernetes/container integration | Native execution targets | Managed environments and possible execution targets |
| Machine-wide authority | Not its primary object | Intended scope |

### Strengths of OpenShell

#### Purpose-built agent isolation

Its security model is specifically designed around running autonomous code with meaningful permissions while constraining filesystem, network, identity, and credentials.

#### Explicit control-plane split

The Gateway/Supervisor architecture clearly separates durable control-plane authority from sandbox-local enforcement.

#### Multiple compute backends

The common abstraction can target local container/VM runtimes and Kubernetes.

#### Credential mediation

Agent processes need not receive raw provider credentials directly.

#### Policy proving

The SMT-based policy prover demonstrates that parts of an agent-control authority model can be mechanically checked rather than relying exclusively on conventional tests.

### Tradeoffs and different goals

These are not defects. They reflect the problem OpenShell is designed to solve.

#### Agent-centric abstraction

OpenShell's sandbox is the center of its architecture. Linura intends the machine-state transition to be the center.

#### Security-policy verification is not machine-state verification

Proving that a candidate policy grants no authority beyond a boundary is different from proving:

> The requested machine state now exists.

Both forms of verification are valuable. They answer different questions.

#### Isolation does not replace semantic state observation

A correctly isolated process can still produce an incorrect result inside authority it legitimately received.

Machine-state verification therefore remains relevant even when the executing workload is strongly sandboxed.

### Where OpenShell and Linura could compose

The systems need not be competitors.

An OpenShell sandbox could eventually be an execution environment controlled by or interacting with Linura:

`agent reasoning → OpenShell-governed runtime → Linura intent boundary → Linura authorization → controlled host/container/VM effect → authoritative observation → verification → commit / rollback / reconciliation`

In that composition:

- OpenShell constrains the agent workload;
- Linura constrains and verifies the machine transition.

These are complementary boundaries.

### Upstream sources

- [OpenShell: How it works](https://docs.nvidia.com/openshell/about/how-it-works)
- [OpenShell: Policy prover](https://docs.nvidia.com/openshell/latest/how-it-works/policies/prover)
- [OpenShell developer guide](https://docs.nvidia.com/openshell/home)

## Docker Sandboxes

Docker Sandboxes provides isolated environments for AI coding agents.

For local sandboxes, Docker documents the microVM as the primary trust boundary. The agent has full control inside that VM, including sudo access, package installation, a private Docker Engine, and read/write access to the in-sandbox filesystem.

The VM boundary protects the host except for explicitly shared resources.

Docker additionally provides controls around workspace sharing, credential isolation, network access, MCP access, and sandbox lifecycle.

Outbound TCP traffic is blocked unless an explicit rule allows the destination under the default local security posture. Credentials can be injected by a host-side proxy instead of exposing raw credential values to the sandbox.

### Docker Sandboxes and Linura

The clearest distinction is:

> **Docker Sandboxes gives an agent a safe place in which to have broad freedom.**

Linura intends to give a proposer a controlled path through which to request specific authoritative changes.

Those models can coexist. A sandboxed agent could request a Linura capability without receiving direct host authority.

### Comparison

| Dimension | Docker Sandboxes | Linura |
| --- | --- | --- |
| Main goal | Isolated AI-agent execution | Authorized and verified machine-state transitions |
| Main trust boundary | MicroVM | Intent/effect authority boundary |
| Agent privilege | Broad inside sandbox | Only authority represented by accepted capability/effect |
| Host access | Explicitly shared resources | Explicitly authorized effects |
| Network policy | Deny-by-default local posture with explicit allow rules | Capability/policy dependent |
| Credential handling | Host-side mediation available | Capability/executor dependent |
| Recovery | Sandbox lifecycle/reset/removal | State-aware rollback, compensation, or reconciliation where supported |
| Semantic post-state verification | Not primary abstraction | Core architectural requirement |
| Long-lived host state | Deliberately outside sandbox in many cases | Central managed object |

### Strengths of Docker Sandboxes

- strong VM-backed isolation;
- familiar developer workflow;
- disposable or bounded environments;
- broad freedom inside a constrained boundary;
- private Docker Engine;
- controlled workspace exposure;
- credential isolation;
- explicit network policy.

These characteristics are especially useful for coding agents performing exploratory work.

### Tradeoffs relative to the Linura problem

A sandbox boundary does not itself determine whether a requested host state is correct.

Giving an agent broad freedom inside an isolated VM is excellent when the desired result is an artifact produced inside that environment.

It is a different problem when the desired result is to change a host service, alter persistent device state, update a system policy, modify desktop/session state, maintain configuration over time, or coordinate effects spanning multiple system domains.

That second category is where Linura's machine-state model becomes relevant.

### Upstream sources

- [Docker Sandboxes security model](https://docs.docker.com/ai/sandboxes/security/)
- [Docker Sandboxes default security posture](https://docs.docker.com/ai/sandboxes/security/defaults/)
- [Docker Sandboxes credential handling](https://docs.docker.com/ai/sandboxes/configuration/credentials/)

## Architectural conclusion

OpenShell demonstrates that independent deterministic control planes are already emerging for AI execution.

Docker demonstrates how much useful agent freedom can be recovered by moving execution behind a strong isolation boundary.

Linura should incorporate these lessons rather than positioning itself as an alternative to isolation.

> **Isolation controls the execution environment. Linura controls the authority of the requested state transition.**

Both may be required in a complete system.
