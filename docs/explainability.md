# Explainability contract

`Explain` is a core protocol operation, not model-generated storytelling.

## Evidence rule

An explanation may render only structured facts that Linura can bind to authoritative observation, deterministic planning, durable intent/Library state, provenance, policy or audit evidence. Missing evidence produces an explicit unknown/incomplete answer; an agent may improve wording but cannot manufacture the why-chain.

The released lineage already exposes bounded graph/explanation evidence for observed resources, and v0.7 adds durable intent/Setup/MachineProfile lineage and causal ownership/removal-impact evidence. Not every target question is implemented for every domain yet.

As the product surface expands, `Explain` should answer, where the required evidence exists:

- Why does this exist?
- Which intent/requirement/capability caused it?
- What depends on it?
- What does it depend on?
- Is it shared by other active intents or profiles?
- What would be affected if I retire/remove it?
- What changed it most recently?
- Does fresh observed state match desired state?
- Which trusted operation/risk/policy decision constrained an effect?
- Which plan, authority record, verification and audit evidence support the displayed outcome?

All clients—CLI, Control Center, First Boot and proposal-only agent surfaces—render the same structured evidence model rather than maintaining private explanation truth.
