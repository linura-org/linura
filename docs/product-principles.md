# Product principles

1. **Intent before implementation.** Preserve what the user wants separately from how the current platform satisfies it.
2. **Agents propose; Linura authorizes.** Model confidence never expands authority.
3. **Agent-native, not agent-dependent.** Deterministic control, explanation and recovery work offline without a model provider.
4. **Linux-native, not Linux-obscuring.** Prefer stable upstream APIs and preserve administrator interoperability.
5. **One model, many interfaces.** Intent, declarative configuration, First Boot, Linura Agent, Control Center, bounded Shell/desktop surfaces, command palette/shortcuts, CLI and Linura SDK share the same typed machine model and contracts.
6. **Observed truth beats cached UI state.** Providers prove current system state.
7. **Desired state is derived and explainable.** Every managed resource retains an intent/requirement/capability origin.
8. **Plan before privilege.** Users/policies inspect material effects before execution.
9. **Verification defines success.** A successful API/process return is insufficient without authoritative postcondition evidence.
10. **Safe retirement is a product feature.** Removing intent performs dependency/shared-ownership impact analysis.
11. **Profiles before vague portability.** Support precise platform profiles while keeping core contracts provider-neutral.
12. **Capabilities are composable.** Users ask for outcomes; blueprints resolve dependencies/conflicts into supported providers/resources.
13. **Generated UX is constrained.** Derived surfaces bind to typed resources/actions; arbitrary custom code is isolated.
14. **Security and operations are features.** Updates, migrations, recovery, provenance, audit, diagnostics and supply-chain evidence are part of the product.
15. **Enterprise is an extension of local trust.** Fleet/cloud features never become the source of truth required to operate a local machine.
16. **Many inputs, one authority architecture.** GUI, config, keyboard, quick settings, CLI, automation and agents may differ in interaction and risk-appropriate ceremony, but Linura-managed durable external mutations converge on the same typed Control-owned authority semantics and canonical lifecycle. Lighter non-durable interactions may use proportionate typed paths; no interface becomes a privilege bypass.
