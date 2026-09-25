# Linura

**The intelligent system layer for Linux.**

This is the canonical top-level Rust crate for the
[Linura](https://linura.org) project.

Linura turns human and agent intent into declarative, policy-controlled,
verified machine state. The project separates probabilistic proposal from
deterministic authority: agents may propose changes, while Linura observes,
plans, validates, authorizes, executes, verifies, commits, audits, and
reconciles supported effects.

## Status

The top-level Rust integration surface is intentionally minimal while its
long-term public API is being stabilized. The production project and current
public non-privileged SDK live in the
[Linura repository](https://github.com/linura-org/linura).

Publishing this crate establishes the canonical Rust package identity without
prematurely exposing Linura's internal authority, provider, executor, or
persistence implementation as public compatibility contracts.

## Links

- [Website](https://linura.org)
- [Source](https://github.com/linura-org/linura)
- [License](https://github.com/linura-org/linura/blob/main/LICENSE)

## License

Apache-2.0.
