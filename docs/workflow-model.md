# Workflow model

Linura can compose workflows from typed capabilities. Example:

```text
Super+Shift+S
 → capture region
 → annotate
 → upload through selected storage capability
 → copy URL
 → notify
```

Workflows are declarative graphs of typed triggers/actions. They do not embed arbitrary privileged shell text.

## Current maturity

A general user-facing workflow runtime is **not a v0.9 supported product claim**. Workflow definitions and future derived surfaces remain bounded by their component/milestone activation contracts.

When workflow execution is activated:

- each node resolves to a registered typed capability/operation or an explicitly non-authoritative local transformation;
- the workflow graph itself carries no executor, policy or approval authority;
- each external effect is classified from trusted registered semantics, not from workflow metadata;
- equivalent operations use the same Control path as CLI, GUI, config or accepted agent input;
- failure/cancellation semantics are explicit rather than silently skipping required downstream verification;
- durable desired effects use the managed lifecycle, while only operations satisfying the complete bounded transient contract may use `TransientExternalEffect`;
- resources, permissions and causal ownership participate in the same system graph, provenance and retirement analysis as other managed capabilities.

A workflow engine must never become a generic shell runner or a way to bundle several low-level effects into one opaque authority grant.
