# Release documents

Linura deliberately separates **frozen release contracts** from **terminal publication state**.

Versioned files named `vX.Y.Z.md` in this directory are release contracts frozen before publication. They define the exact claim boundary, required evidence, non-goals, compatibility boundary, and supply-chain requirements that the proof-first/tag-last release lifecycle is allowed to publish. Once a release is immutable, those contract bytes must not be rewritten merely to make their pre-publication wording look current.

A frozen contract is therefore **not the live release-status authority**. For a completed release, use the terminal publication record and qualification evidence linked below, together with `contracts/roadmap.toml`.

## Current release

| Version | Live status | Frozen contract | Terminal release record | Terminal evidence |
| --- | --- | --- | --- | --- |
| `v0.6.0` | **Released — Experimental; independently verified** | [`v0.6.0.md`](v0.6.0.md) | [`published-v0.6.0.md`](published-v0.6.0.md) | [`../qualification/v0.6.0-publication.md`](../qualification/v0.6.0-publication.md) |

The immutable GitHub Release for `v0.6.0` was created from the exact frozen contract and therefore permanently contains historical pre-publication phrases such as “release candidate” and “publication evidence remains pending.” That wording describes the contract at release authorization time; it does **not** describe the current state. The terminal record and publication-evidence dossier above are the current state authorities.

## Publication-stable contracts from v0.7 onward

Starting with `v0.7.0`, release contracts must use **publication-stable lifecycle wording**. A contract may state immutable scope, evidence requirements, and the fact that publication/verification are externally recorded, but it must not encode temporary live-state assertions such as:

- “release candidate” in the `Status` field;
- “publication pending”;
- “publication evidence remains pending”;
- “not yet released” or equivalent live-state wording.

This matters because the sealed `RELEASE_NOTES.md` and the immutable GitHub Release body are derived from the frozen contract. Publication-stable language ensures the same bytes remain truthful before publication, at publication, and after independent verification.

`tests/tooling/test_release_publication_stability.py` permanently enforces this rule for `v0.7.0` and later contracts.
