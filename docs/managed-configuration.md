# Managed configuration and drift

Linux configuration has multiple legitimate owners. Linura must not treat every file difference as permission to overwrite the user.

`linura-config` defines six ownership classes:

- package-owned;
- user-owned;
- Linura-managed;
- externally-managed;
- generated;
- ephemeral.

## Drift behavior

Linura-managed drift requires explicit reconciliation policy rather than a silent overwrite. Policy may choose report-only behavior, deterministic reconciliation, or approval when the trusted operation/risk requires it. User-owned and externally-managed drift is reported, generated state may be reconciled deterministically, and ephemeral state may be ignored.

Package-manager side files such as Arch `.pacnew` and `.pacsave` are reconciliation inputs. Linura must surface and classify them before claiming an update is healthy.

Ownership and desired/observed digests form part of the system graph so `explain` can answer who owns a resource and why a particular state is expected.
