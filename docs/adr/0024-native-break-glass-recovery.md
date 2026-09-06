# ADR 0024: Native break-glass recovery is an invariant

- Status: accepted

## Context

A system control plane that prevents recovery when its own daemon, UI, update coordinator, or model provider fails creates an unacceptable circular dependency.

## Decision

Linura OS profiles must retain a documented native shell/package-manager recovery path. Coordinated update guards may prevent accidental bypass during normal operation, but an explicit administrator break-glass mechanism must remain available and testable.

The agent/model layer is never required for recovery.

## Consequences

Recovery paths receive acceptance coverage and security review. Break-glass use is exceptional, visible, and should be auditable after Linura health is restored.
