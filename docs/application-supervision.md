# Application supervision

The desktop compositor is not Linura's process supervisor.

Desktop applications and long-lived helpers should be launched into systemd user scopes/units when practical so resource accounting, restart policy, logs, and OOM isolation remain observable independently of the shell.

The shell is a client of the system authority and a presentation surface. Crashing or restarting the shell must not implicitly terminate unrelated managed applications or invalidate system state.

## Current maturity

Application supervision is a **design contract for v0.10+**, not a v0.9 supported product surface. The current release does not claim a general application supervisor, arbitrary process launcher, or shell-owned service manager.

When supervision is activated, it must expose typed fields for resource limits, restart behavior, lifetime, ownership, and user-visible failure state rather than embedding arbitrary shell launch commands into UI metadata.

Operation semantics are determined by the registered operation, not by the shell widget that invoked it. A session-local unprivileged effect may qualify for the bounded `TransientExternalEffect` path only when it satisfies that class's complete contract; durable desired application state, privileged supervision, or ambiguity-sensitive recovery requires `ManagedExternalEffect` semantics or remains unsupported.
