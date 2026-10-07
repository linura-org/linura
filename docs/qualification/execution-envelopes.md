# Qualification execution envelopes

Linura qualification must identify the environment that executed a test without
pretending every hosted or physical observation is bit-reproducible.

`contracts/qualification-execution-envelopes.toml` is the reviewed lane inventory
for execution-envelope identity. `tools/qualification_envelope.py` creates and
verifies schema-versioned envelopes.

The contract carries a machine-checked `authority_boundary`: this layer is
execution-context-only and is forbidden from accepting qualification evidence,
writing pass receipts, binding verifier results, or binding accepted artifacts.
The validator also scans the core execution implementation for evidence-binding
entry points so those responsibilities cannot drift back into this layer.

An envelope is **not a pass receipt**. It describes the inputs and execution
context that a separate test or evidence verifier may later accept. Every
declared hosted lane invokes the repo-owned qualification-envelope action, which
creates and immediately verifies the envelope, copies it into the lane evidence
directory when one exists, and retains it as a dedicated workflow artifact. The
maintained-hardware entrypoint performs the corresponding create/verify boundary
only after Q11 candidate finalization succeeds.

## Bound identity

Every envelope binds:

- an explicit execution subject: the orchestrating runner itself, a typed VM guest, or an aggregate of independently verified component envelopes;
- the exact Git commit and tree;
- the execution-envelope contract, the lane's actual workflow/physical
  entrypoint, and every repository-controlled input declared for the lane;
- the orchestrating runner kind, architecture, kernel, `/etc/os-release` digest, installed-package manifest digest/count, virtualization state, and for GitHub-hosted lanes the published runner image OS/version identity; the reviewed runner profile fixes the native package manager (`dpkg` for hosted Ubuntu and `pacman` for the maintained Arch workstation), so an installed foreign package tool cannot redirect manifest identity;
- for guest-executed lanes, the guest architecture, kernel, OS-release digest, distribution identity/version, package manager, package manifest digest/count, virtualization identity, reviewed acceleration mode, and the complete qualified image-digest chain (for example base plus prepared substrate), cross-bound to lane package/image identities;
- the repository toolchain and lockfile digests;
- lane-specific immutable digests such as a VM base image, prepared guest image,
  fixture, or package manifest;
- independently byte-verified cache content when a lane explicitly permits a
  cache;
- explicitly declared variable observations that must not be confused with
  deterministic inputs; observation fields ending in `_sha256` are typed and
  validated as lowercase SHA-256 digests.

The canonical envelope digest is SHA-256 over sorted compact UTF-8 JSON before
the `envelope_sha256` field is added. A sibling `.sha256` file binds the
serialized envelope filename to that digest. This digest is **content identity,
not authenticity**: anyone able to replace both files can recompute it.
Workflow integration validation is scoped to the actual
`qualification-envelope` action step. A matching lane string in a downstream
evidence consumer, comment, or unrelated shell body cannot satisfy the
execution-context integration contract. This keeps stacked evidence work from
silently masking a disconnected execution-envelope producer. Delegated reusable
workflow lanes are checked inside the concrete job block as well, so matching
text in comments or unrelated jobs cannot satisfy delegation.

Accepted qualification evidence must therefore bind the envelope digest through
its own trusted provenance/acceptance path.

Creation and verification both require the repository checkout to be at the
declared source commit **and require every tracked worktree/index byte to match
that commit**. The verifier compares the declared Git tree directly with stage-0
index entries and hashes raw worktree bytes itself; clean filters, EOL
normalization, assume-unchanged, and skip-worktree cannot turn a byte-different
checkout into a clean envelope. Untracked and ignored source-like paths are also rejected; only bounded generated-output/cache roots such as `target/` and Python/tool caches may coexist with final envelope creation, so an injected `build.rs`, `.env`, or similar ambient build input cannot be hidden from the source claim. Repository-controlled envelope inputs are additionally compared
byte-for-byte by SHA-256 with their Git blobs at that commit. A modification to
tracked code outside a lane's explicit envelope-input list therefore cannot
produce or verify a clean-source envelope.

## Cache boundary

A cache key is never qualification evidence. Cache hits may improve performance,
but accepted cache content must be content-addressed and independently verified
before its digest enters an envelope. Cached qualification evidence and cached
Linura build outputs are forbidden by this contract.

The v0.10 prepared Arch substrate is the model: the guest image is checked
against an independently recomputed digest and substrate verifier before its
digest can be used. Cargo registry caches remain performance-only; Cargo.lock
and package checksums remain the authority for dependency identity.

## Execution subjects

Host-only and maintained-hardware lanes use a `runner` execution subject whose identity digest is derived from the independently measured runner record. VM-backed lanes use a `guest` subject captured from inside the guest over the qualification-only SSH transport; the host runner remains recorded separately as the orchestrator. Aggregate lanes never pretend the aggregation runner executed the underlying qualification: they bind a canonical SHA-256 over the exact component-envelope set.

The v0.9 adversarial matrix creates one guest-executed envelope per shard on the same matrix runner that performed that shard. The exact eight-shard inventory and boundary ranges are reviewed schema data in the execution-envelope contract, and regex-valid but unreviewed shard IDs fail closed. The assembler verifies every shard envelope, canonicalizes the component set by shard identity, cross-checks each envelope against the same qualification-environment identity as the shard evidence, and writes a separate `qualification-execution-components.json` execution-context manifest. It does **not** add envelope acceptance fields to the adversarial evidence receipt. The v0.9 contract job has its own runner-subject component envelope; its audit artifact remains attempt-specific, while a separate immutable-source hand-off artifact has a stable name so rerunning only failed downstream jobs cannot disconnect them from a successful upstream contract component. Full qualification independently recomputes the canonical eight-shard component-envelope digest from that execution-context manifest, requires it to equal the adversarial aggregate execution subject, then combines that aggregate with the contract component and offline VM envelope to produce the final aggregate execution subject. The bounded regression route similarly derives its aggregate execution subject from the contract component without creating a new pass receipt. Accepted evidence remains the responsibility of the evidence-binding layer. Aggregate-only envelopes do not redundantly claim a base image they did not execute; image identity remains bound by the guest component envelopes that actually used it.

## Variable observations

Fresh security data intentionally remains variable. The Security lane records
the RustSec advisory database identity and retrieval time as observations. The
identity is schema-checked as a full lowercase Git SHA and the retrieval time as
UTC RFC3339 seconds during both creation and verification. The producer also verifies the advisory checkout is a non-symlink repository whose local `origin` is the canonical RustSec advisory database, using an isolated Git configuration and pinned system Git. Those values are not
frozen merely to make repeated scans produce the same result.

Graphical and physical lanes likewise record machine/runtime observations while
binding immutable fixtures and configuration by digest. Physical envelope
creation rejects GitHub-hosted image identity and fails when a fixed, reviewed system `systemd-detect-virt` binary reports virtualization. Git, package-manager identity, virtualization, and physical provider-version probes use reviewed absolute executable paths with a minimal command environment rather than caller-controlled `PATH` resolution. The physical envelope publication process is itself launched under an empty, explicitly reconstructed environment, preventing loader/Python/Git environment injection from reaching the identity boundary; the maintained-hardware
kernel/virtualization observations must agree with the executing runner. An
execution envelope still does not upgrade an unexecuted lane into evidence.

## CLI

Validate the contract:

```bash
python3 tools/qualification_envelope.py validate
```

Create an envelope only from the exact checked-out source:

```bash
python3 tools/qualification_envelope.py create \
  --lane vm-acceptance \
  --source-sha "$SOURCE_SHA" \
  --digest base_image_sha256="$BASE_IMAGE_SHA256" \
  --observation guest_package_manifest_sha256="$GUEST_PACKAGE_MANIFEST_SHA256" \
  --output "$RUNNER_TEMP/qualification-envelope.json"
```

For a cache, the CLI requires `NAME=PATH@SHA256` and recomputes the bytes before
recording the digest. Verification recomputes the canonical envelope digest, requires the exact source
checkout, validates the runner/package binding schema, and rechecks the source
tree, execution target, contract, and repository-controlled input digests
against Git.

The evidence layer may consume the envelope digest, but it must independently
verify the actual test result and evidence artifacts.
