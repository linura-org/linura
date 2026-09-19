# Provider task guide

Providers observe and plan against a Linux subsystem; they do not become ambient root helpers.

**Providers expose bounded mechanisms; Linura owns orchestration.**

- Fail closed on unknown/ambiguous state.
- Prefer native D-Bus/netlink/library APIs over parsing human CLI output.
- Keep D-Bus objects, Unix file descriptors, sockets, process handles and other transport-specific values inside the provider boundary; expose typed Linura resource/capability/observation contracts instead.
- Treat one observation call as a bounded probe. Do not hide unbounded polling, retries, fan-out, cache lifetime or background work inside a provider.
- When a query contract supplies a deadline, cancellation signal, freshness requirement or resource budget, honor it and never silently widen it. Cross-provider scheduling/coalescing/backpressure belongs to Linura Control.
- Emit capability support with a reason/evidence level.
- Do not own or downgrade `OperationClass`. A provider may expose typed facts such as privilege/reversibility/postconditions, but trusted operation registration + Control choose the authority path. Any privileged provider effect is `ManagedExternalEffect`, never transient.
- Make observations deterministic enough for sanitized fixtures.
- Preserve provider/resource/capability identity and authoritative freshness in observation evidence; retrieved/model confidence never substitutes for required authoritative state.
- Provider tests must cover unavailable service, malformed state, unsupported feature, stale observation, timeout/cancellation where supported, and budget exhaustion where applicable.

Read `docs/provider-model.md` and ADR 0017 before introducing a new observation/provider transport or cross-provider query behavior.
