# Acceptance scenarios

Each JSON file is an experimental disposable-machine scenario validated against `schemas/acceptance-scenario.v1.schema.json`. Its numerical filename is a **scenario index**, not a release version. Historical qualification and workstation suites are linked in the [qualification index](../../qualification/README.md).

Every scenario declares an explicit `execution_status`: `executable` allows running its named steps on a suitable guest, but does **not** assert they passed; `reserved` means an incomplete development contract or weak legacy scaffold, which the runner refuses to execute. Reserved scenarios must provide a `reservation_reason` explaining what is unproven.

Use `python3 tools/acceptance.py list` for human discovery, or `python3 tools/acceptance.py list --json` for a machine-readable inventory. The general VM workflow executes **one selected executable scenario**, not every milestone's qualification.

The original bootstrap-resume, intent-retirement, update-interruption and native-recovery placeholders remain reserved because presence checks do not verify the named behavior. Existing version-specific Rust, Python, adversarial guest and hardware qualification remain separate and authoritative; see the root qualification index.

A dry run is a preview, not qualification evidence: `--dry-run` and `--result-file` are incompatible. Real result files require an exact source SHA and real guest execution. Release qualification additionally requires the relevant independent evidence bindings, verification, environment identity and inherited gates. An executable scenario or a saved JSON file is never release-readiness proof by itself.

A scenario must assert user/system-observable behavior and failure/recovery properties. Do not add passing placeholders for unimplemented features.
