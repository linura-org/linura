# ADR 0044: Explicit native development preparation across Ubuntu and Arch

- Status: Proposed
- Refines: ADR 0022, ADR 0043

## Context

Read-only readiness diagnostics identify missing tools but cannot prepare every
development profile. Requiring a container to fill these gaps would confuse the
primary host, an optional isolated instance and qualification infrastructure.
Implicit installation during ordinary task checks would also undermine the
repository's pinned preparation and source-integrity rules.

## Decision

Keep the existing Ubuntu host as the primary development environment. Provide
one explicit preparation command and strict native package mappings for Linux
x86_64 on Ubuntu 24.04/26.04 and Arch Linux. Expand the existing seven readiness
profiles through declared dependencies. ArchISO requires a native Arch builder.
The optional development container and independent qualification machines retain
their distinct purposes.

Separate read-only planning/doctor/preflight from explicit prepare/maintenance.
Resolve native versions and dependencies, bind source/preparation inputs, user,
host, repositories and installed/manual-owner state, and rederive before effects.
Saved plans are short-lived developer data, never product ReconciliationPlans,
credentials or executable command lists. Native administrator authorization
remains necessary, and Python never runs as root. Only fixed native package-manager
entrypoints receive elevation. No Linura runtime/provider/agent surface is added.

Reuse canonical pinned bootstrap for existing language tools and bindings. Build
a digest-pinned private Python and install digest-pinned Node/locked Pyright into
private generations. Verify cached file manifests before running cached programs.
Do not replace system Python, unmanaged user tools, native trust configuration,
services, permissions, storage or hardware access.

Verify package postconditions and preserve shared dependency ownership. Serialize
preparation, retain private phase receipts/history, and refuse automatic replay
after an interrupted package transaction changes state. Explicit operator review
and a new observation may accept that state; no guessed rollback or package-database
recovery occurs. Arch full-system maintenance remains separate: never synchronize
its databases alone or silently upgrade an active development host.

## Consequences

Supported development hosts have explicit profile preparation without making two
OS installations mandatory. Native package-manager configuration and administrator
maintenance remain trusted host inputs. Plans cannot make native package
transactions atomic against another administrator. Installed package versions
differ legitimately across distributions while repository language pins and checks
remain shared.

Readiness, source alignment, component tests, VM/interactive evidence and physical
qualification remain separate claims. Platform installation validation must run
on each actual distribution; fake package-manager tests do not establish it.
This decision adds developer tooling and leaves application authority, accepted
qualification evidence and the sealed release toolchain unchanged.

See [native preparation](../native-development.md) for commands and failure paths.
