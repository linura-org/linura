# Envelope-bound qualification evidence

Qualification evidence is accepted only after a reviewed, lane-specific semantic verifier independently re-derives the qualification result from retained transcripts, structured runner results, exact repository contracts, environment identity, and the execution envelope that produced them. A workflow-generated JSON field saying `result=passed` is consistency data, never sufficient authority.

The execution-envelope layer remains environment identity only. This layer owns
evidence acceptance only; it cannot mutate execution envelopes, grant
publication authority, or grant release authority.

## Admission chain

1. Verify the execution envelope against the exact checked-out source/tree.
2. Select the evidence profile from the envelope lane; reviewed test IDs,
   contract IDs, artifact inventory and verifier identity are contract-owned
   and callers cannot supply or override them.
3. Require every artifact declared by that reviewed profile and reject missing,
   symlinked, escaped, renamed, or duplicate artifacts.
4. Run the reviewed verifier adapter for that lane. The adapter must semantically inspect the retained proof material and derive its own `result`, `independent`, `environment_verified`, verified-claim inventory, test IDs, and contract IDs. Those values are verifier conclusions rather than binder constants.
5. Recursively inventory every retained regular file. Required profile files
   keep their reviewed semantic roles; every additional file is bound as
   non-claiming auxiliary evidence. Only the envelope/verifier/binding control
   files are excluded because they are independently verified.
6. Canonicalize role, relative path, kind, required flag, SHA-256 and size for
   that complete retained-file inventory and hash it.
7. Emit `verifier-result.json` binding source/tree, lane, execution-envelope digest, artifact-set digest, the semantic-adapter identity and digest, binder identity, verified claims, and the independently derived test/contract conclusions.
8. Create `evidence-binding.json` only if a second verifier process can reproduce the same semantic conclusion over the same bytes, then reverify the completed binding.
9. Deterministically encode the completed bundle as `qualification-evidence.tar` with canonical paths and metadata, structurally verify that tar against the binding, and upload that exact tar from inside the admission action. No caller-controlled success upload step exists.

This prevents the substitution class where a verifier passes artifact set A
and a later binder silently accepts artifact set B.

The admission action itself is part of the reviewed contract. Static validation
parses its concrete composite-action steps and requires the exact sequence
attest -> bind -> semantic reverify -> deterministic seal -> upload. The upload
has no `always()` override and its path must be exactly the seal step output.
The action then downloads the stored artifact in the same run and requires its
SHA-256 to equal the pre-upload sealed-object digest before reporting accepted
evidence identity.
Caller workflows cannot upload accepted mutable directories at all; any direct
upload in an evidence-producing job is failure-only, explicitly `unqualified`,
and diagnostic.

For v0.4 durability, semantic verification separately binds the reviewed probe
source and a single-link retained copy of the built host executable, then
requires the independent guest re-observation witness to prove that the
installed probe bytes match that exact retained executable. For real-ENOSPC recovery, the retained qualification witness proves
physical reserve allocation and actual pre-retirement exhaustion, while a
separate re-observation proves the terminal state survives remount and that the
recovery reserve reconciles to zero after the final nonterminal transaction is
retired.

## Reviewed inventory, not caller inventory

Each evidence-bearing lane declares its required retained artifacts in
contracts/qualification-evidence-binding.toml. missing_artifact_allowed=false
therefore has concrete meaning: a caller cannot satisfy admission by supplying
one arbitrary file.

Native CI, RustSec, CodeQL, Codex environment, v0.9 internal adversarial
assembly, the v0.10 workstation contract, trusted release proof itself, and the
not-yet-complete maintained-hardware Q11 lane are explicitly non-evidence.
They remain gates, execution context, release machinery, or incomplete physical
qualification rather than being promoted by a self-declared receipt.

## Observation evidence

The v0.10 shell runtime is observational rather than byte-reproducible. Its
verifier provenance also binds the reviewed shell-runtime observation policy
digest and requires the recording plus its metadata as retained artifacts.
Physical Q11 is deliberately not admitted until the real maintained hardware
evidence path is complete.

## Publication and release boundaries

Bindings default private. Physical recording publication still requires the
existing explicit approval/redaction policy. This layer does not publish data.

Trusted release proof remains separate release authority. Where release proof
consumes qualification artifacts, it verifies their evidence bindings before
treating them as accepted qualification input; the release proof itself is not
reclassified as ordinary qualification evidence.


## Complete retained-byte coverage

Admission is not limited to the minimum profile artifacts. Files such as
diagnostic logs, checksum sidecars, execution-component manifests and other
retained outputs are recursively included in the canonical artifact-set digest.
They are marked auxiliary rather than interpreted as qualification claims.
Symlinked or non-regular retained paths fail closed. This ensures the uploaded
bundle cannot carry unbound mutable bytes beside an otherwise valid binding.


## Final retained-bundle seal

Cleanup and diagnostic capture complete before evidence admission. The evidence action itself performs semantic attestation, binding, semantic re-verification, deterministic tar sealing, sealed-tar verification, and the accepted upload. The repository validator requires the matching execution envelope earlier in the same job, requires an explicit accepted artifact name, and rejects any caller-controlled success upload after admission. Failure diagnostics may be uploaded only through an explicitly `failure()`-gated `unqualified` artifact name.

Downstream consumers first unseal and structurally verify `qualification-evidence.tar`; trusted release proof does not reinterpret this as release authority. The mutable producer directory is never the accepted object.

Control filenames are reserved at the bundle root. A nested lookalike such as
`nested/verifier-result.json` is rejected rather than silently treated as
auxiliary evidence.

For bounded graphical evidence, verifier metadata includes a contract-owned
observation identity: the reviewed observation-policy digest plus selected
fields from the primary result that identify the target profile, runtime and
substrate contracts, archive snapshot, rendering backend, recording, authority
scope, and explicit non-promotion boundary.


## Stable file identity

Evidence bytes are read through no-follow file descriptors. Admission requires a
regular file with one link, hashes or decodes it from the opened descriptor,
checks descriptor identity before and after the read, and then confirms the
bundle path still names that same inode. Symlink swaps, hard-link aliases, path
replacement, and concurrent mutation therefore fail closed instead of creating
a check-then-open evidence gap.
