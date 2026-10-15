# Tracked-format contract

Issue #217 is closed only after source inventory, non-mutating validation, exact-head
qualification, and default-branch evidence are all complete.

## Boundaries

Every Git-tracked regular file is inventoried using Git's stage/mode metadata.
A symlink, missing input, unmerged index stage, unsupported new extension, or
malformed inventory is a hard failure. Files are not selected by filesystem
glob, ignored by .gitignore, silently excluded because their extension is
unknown, or rewritten in CI.

The canonical formatter step runs both:
- python3 tools/check_multilanguage_formatting.py (Rust/Python are checked by
  the canonical cargo xtask and locked Ruff gates; C++, QML, Lua, JS/TS and
  shell are checked by their own pinned tools)
- python3 -m tools.check_tracked_formats (complete tracked inventory, framing,
  structured validation, and protected-source digest verification).

The second checker uses the **same pinned Prettier 3.6.2** installed outside the
checkout in canonical CI. Markdown is parsed without mass rewriting human prose,
YAML/CITATION.cff/.clang-format are parsed, and polkit JS rules are parsed
with Babel; none of these transformations are written to disk. Markdown also
receives existing repository-link checks. Structured JSON and TOML use Python
3.12's JSON/tomllib parsers. JSON also rejects duplicate object keys and
non-standard NaN/Infinity literals. XML/SVG/polkit policy and XML-shaped D-Bus conf
use the standard XML parser. INI/desktop/systemd units and editorconfig require assignments.
Arch hooks permit only the explicitly reviewed bare AbortOnFail directive;
Indented valueless continuations and duplicate INI assignments are rejected;
systemd units explicitly permit repeated `Environment=` and `LoadCredential=`
in the `[Service]` section without allowing arbitrary duplicate keys.
pacman.conf alone permits its documented valueless flags. None are rewritten
or reordered. The toolchain environment contract is **data, never executable shell**. The
isolated standard-library loader (`tools/check_toolchain_env.py --values PATH`)
parses all twelve exact keys and narrow pin grammars before emitting one fixed-order,
whitespace-separated record. Shell consumers capture the command's exit status
before using Bash `read -r` for the validated atomic record. Every field is
also checked for a nonempty value before use; consumers do not `source` or
`eval` the PR-controlled contract. Invalid content produces no values and
fails the consumer closed. The required CI governance checker requires the
exact loader and read sequence inside each reviewed executable step, rejects
returning to raw contract sourcing, and fails on unreviewed consumers. Every
path-scoped qualification workflow that consumes this file also selects changes
to the validator and its tests; these selections are bound to the
qualification-gate matrix. The Arch package list has its own validator.
The reviewed sysusers.d user declaration has a dedicated parser, distinct from INI, and the three polkit rules (product and v0.5/v0.6 qualification) are explicitly identified as Babel-validated JavaScript. An unreviewed `.conf` or `.rules` file fails closed until its semantics and provenance are classified.

Tracked Rust, Python, C/C++, JS/TS, QML, Lua and shell sources are delegated to
their established pinned formatters, syntax gates and CI. CMakeLists are compiled
by the canonical shell build and scrutinized by repository checks. Makefile,
licenses, .gitignore/.gitattributes/CODEOWNERS, and integrity-locked pip
requirements are tracked, UTF-8/LF checked, and retained without unsafe
normalization. The original 16 audited exact-byte exceptions are verified
against their SHA-256 digests by BOTH the old language gate and the inventory
contract. Their justification and removal process remain in
docs/source-formatting.md.

This is an explicitly **heterogeneous contract**: parser-valid does not mean
prettier-formatted. Markdown, YAML and other human/authority documents are
parse-only because normalizing entire historical documents or workflow/evidence
bodies may change significant text or invalidate separate source-bound proofs.
Formatter-only groups and parser-only groups must be accurately documented,
not advertised as interchangeable. Introducing a new file format requires an
explicit classification, integrity-pinned validator and negative test.

The release publisher and Rust xtask read pinned versions using the isolated
strict toolchain validator. Codex diagnostic and editor checks call the same
schema validator rather than maintaining separate parsers.

All repository-local Bash entrypoints and composite action definitions are also
inventoried, including helpers reached through other scripts. New sourcing and
shell evaluation are denied until explicitly reviewed. The known Codex setup, preflight, and workstation consumers also load only
validated data through the same isolated parser. Workflow checks retain their
adversarial defenses against dynamic sourcing, nested shell execution, and
unreviewed local helpers; no contract-executing exception remains.

Expanded executable names and nested shell interpreters in local shell inputs
are denied conservatively after shell word tokenization, including assignments,
builtin wrappers, arrays, command substitutions and continued commands. A nested
shell requires review regardless of whether its input is a script, redirected
stdin, a pipeline, a descriptor, a here-string or a here-document; `-c` is not a
special security boundary. Existing development tool and qualification launchers
are reviewed by the full-file SHA-256 entries in `REVIEWED_SHELL_EXECUTION` in
`tools/check_validation_gates.py`. These are separate
from formatting exceptions: changing any variable definition or command in one
of these files invalidates its execution review and requires a new review of
the entire file before updating the digest. An unchanged invocation line or a
familiar variable name alone does not preserve review. The adversarial tests run
before expensive CI and Codex environment bootstrap steps.

The complete pre-validation shell bootstrap closure is also content-bound:
setup, preflight, maintenance and the source-state library must retain their
reviewed complete bytes. Missing or symlinked bootstrap inputs fail closed.
The source-state library intentionally runs before validation to detect source
changes even when validation fails; its protection is preserved rather than
moving unreviewed code across that boundary. Hashing the complete closure makes
this prerequisite independent of shell syntax or an embedded helper's language.

The v0.10 Arch substrate builder parses its TOML contract into an explicitly
validated four-field data record and never evaluates Python-produced shell
assignments. The output is restricted to safe URLs, a bounded disk size, and
allowlisted package atoms before being passed into remote guest commands.

The workflow security checks enforce reviewed data-loading sequences, not a
general Bash interpreter. Dynamic source paths, shell startup hooks and
unreviewed shell evaluation remain denied in workflow YAML. This static gate does
not confer independent authority on PR-controlled workflows or replace trusted
publisher/source-provenance verification. The exact-head native qualification
matrix remains mandatory.

Every executable job in a workflow that consumes the toolchain contract must
validate it before running unreviewed code, regardless of interpreter or file
extension. The gate checks each job's structural step prefix, rather than
trying to infer whether a Python, Node, native or composite-action helper might
execute configuration. Normally the loader immediately follows the pinned
checkout. The only reviewed prerequisites are the exact pinned Python setup
action and canonical CI's complete source-attested publisher/bootstrap prefix;
the latter is SHA-256 bound and retains its existing provenance-before-code
boundary. Added steps, modified checkout properties, changed prerequisite
bodies, and added jobs without a validated load fail closed. A successful load
in one job cannot qualify another job's execution order.

The approval-strength mutation checker uses an isolated temporary worktree for
both final and intermediate Cargo artifacts. Explicit build-directory overrides
prevent inherited caller environment or Cargo configuration from leaving
deliberately weakened policy builds in a normal development cache. Mutation
tests retain the locked dependency graph and still require every protected
approval regression to fail for the intended reason.

## Adoption and verification

The required GitHub canonical-check runs on pull requests and every main push.
It installs locked tools outside the checkout, runs the check-only inventories,
the build and runtime gates, and the adversarial tooling tests. A developer
can reproduce it on the supported Ubuntu 24.04 x86-64 substrate using the
versions in tools/codex/versions.env and the pinned installations in
.github/workflows/ci.yml. The second check requires Prettier to be on PATH;
no implicit global formatter fallback is permitted.

After a follow-up PR merges, inspect the exact new main commit's canonical CI,
security/CodeQL, applicable qualification, and trusted publisher evidence.
Only close #217 after those complete and all source exceptions, documentation,
editor settings and negative tests have been checked on main.
