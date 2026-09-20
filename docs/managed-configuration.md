# Managed configuration and drift

Linux configuration has multiple legitimate owners. Linura must not treat every file difference as permission to overwrite the user.

`linura-config` defines six ownership classes:

- package-owned;
- user-owned;
- Linura-managed;
- externally-managed;
- generated;
- ephemeral.

## Current maturity

The ownership/drift model exists in source, but `linura-config` remains a **v0.10 roadmap scaffold**, not a supported v0.9 declarative-configuration product surface. The v0.10 implementation must activate it through the same typed machine model and Control authority boundaries used by other interfaces.

A configuration file is declarative input only. It cannot contain arbitrary privileged shell, approval evidence, policy overrides, executor permits or a caller-selected `OperationClass`. Any external effect derived from configuration must be freshly observed/planned and resolved through the trusted operation registry and the same class-specific Control path as an equivalent CLI or GUI request.

## Drift behavior

Linura-managed drift requires explicit reconciliation policy rather than a silent overwrite. Policy may choose report-only behavior, deterministic reconciliation, or approval when the trusted operation/risk requires it. User-owned and externally-managed drift is reported, generated state may be reconciled deterministically, and ephemeral state may be ignored.

Package-manager side files such as Arch `.pacnew` and `.pacsave` are reconciliation inputs. Linura must surface and classify them before claiming an update is healthy.

Ownership and desired/observed digests form part of the system graph so `explain` can answer who owns a resource and why a particular state is expected.
