# ADR 0022: Repository-owned development and system-proof pipeline

- Status: accepted

## Context

Linura changes operating-system state. Correctness cannot depend on undocumented maintainer commands or a CI path that contributors cannot reproduce.

## Decision

The repository owns a canonical `cargo xtask` entry point, structured acceptance/image/visual harnesses, task-specific agent guides, and machine-readable evidence formats. CI should invoke the same repository-owned validation path used locally.

Missing external tooling such as QEMU, KVM, mkarchiso, or ImageMagick is reported as missing evidence rather than silently treated as success.

## Consequences

Development infrastructure becomes versioned product infrastructure. Changes to system-proof semantics require review like other architecture changes.
