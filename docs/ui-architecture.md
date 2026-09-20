# UI architecture

Linura has four principal local UX surfaces: Linura First Boot, Linura Agent, Linura Control Center and Linura Shell. All are clients of the same versioned protocol.

## Rules
- no distro/provider-specific backend logic in UI;
- every `ManagedExternalEffect` is plan-first and shows material effects, risk, and the actual policy/approval state;
- a qualified `TransientExternalEffect` may use the bounded Control-mediated transient lifecycle without fabricating a durable plan or unconditional approval prompt; the UI must still show material user-visible effect/risk when relevant, preserve trusted classification, honor policy authorization, and surface verification/audit outcome;
- Linura-owned local state and ephemeral experience actions use their own typed class-specific paths rather than being disguised as managed external mutations;
- `Explain` renders structured provenance/dependency evidence;
- intent retirement shows shared resources and cleanup impact;
- agent suggestions are visually distinguishable from approved desired state;
- unsupported capabilities are explicit, never silently hidden as success;
- offline/no-model control remains available;
- generated capability UI uses constrained derived surfaces or isolated extensions.

The signature first-boot prompt is a product surface, not a privilege boundary.
