# Plugin and extension model

Extensions are not loaded as arbitrary native code inside `linurad` or privileged executors.

## Current maturity

This is a **future extension architecture contract**, not a supported v0.9 plugin system. No plugin, extension manifest or WASM component gains Linura authority merely because this document or scaffold exists.

When an extension runtime is activated, the preferred models are:

1. out-of-process extension communicating over a capability-limited IPC contract;
2. WASM component runtime with explicit host capabilities where feasible.

## Capability examples

```text
system.network.read
system.audio.read
notification.send
ui.panel.register
```

A weather widget does not receive filesystem, process, network-control, policy-admin, executor or root capabilities unless the separately defined extension contract explicitly grants the required non-authority capability.

Effectful extension requests must resolve to registered typed Linura operations. An extension cannot self-declare a weaker operation class, lower trusted risk, fabricate approval, inject shell text into an executor path or create an alternate provider/policy/authority plane.

## Supply chain

An activated extension contract should require:

- manifest with ID/version/publisher;
- declared capabilities;
- content digest;
- signature/attestation where the support contract requires it;
- explicit enablement;
- update policy and rollback path;
- bounded resource/runtime permissions.

An update cannot silently expand capabilities. Capability expansion requires explicit reauthorization under the extension policy and cannot inherit prior grants merely because publisher identity or package name stayed the same.
