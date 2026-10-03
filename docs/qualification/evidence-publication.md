# Qualification evidence publication and private R2 archive

**Status:** controlled Level A publisher; other lanes intentionally not enabled.
**Contract:** `contracts/evidence-publication.toml`; **implementation:** `tools/evidence_publication.py`.

The archive retains selected evidence, not every CI artifact. Qualification and publication are independent decisions: the deterministic checks establish pass/fail; a video only records what was visible during the test. An R2 object or publication index does not promote release support, certify a workstation or override the canonical qualification dossier.

## Storage and retention

The private Cloudflare R2 bucket `linura-qualification-evidence` must have no r2.dev access or public custom domain. The publisher runs only in the protected GitHub `qualification-archive` environment. Put `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY` in **environment secrets**, and `R2_BUCKET`, `R2_ENDPOINT` and `AWS_DEFAULT_REGION=auto` in **environment variables**. Use the EU S3 endpoint only if the bucket actually has an EU jurisdiction restriction. Use bucket-scoped Object Read & Write credentials, not account administration.

Restrict the environment to `main`, require an explicit reviewer, and disable administrator bypass. A solo maintainer can approve their own dispatch only when GitHub's prevent-self-review setting is disabled. Protect changes to the publisher's workflow and code through branch protection and code review: a GitHub environment does not by itself restrict which workflow file can request its credentials.

| Prefix | Retention | Admission |
| --- | --- | --- |
| `baselines/` | R2 lifecycle: 180 days | Selected, successful Level A main-branch run |
| `regressions/` | R2 lifecycle: 90 days | Specifically selected, successful Level A reproduction |
| `releases/` | Release lifetime plus approved audit period | Disabled until independent release proof and retention enforcement exist |
| `physical/` | Per-record owner approval | Disabled in CI; originals remain in restricted local custody |
| `interactive/` | Per-record owner approval | Disabled in CI; originals remain local until reviewed |
| `index/` | Administrative index retention | Private completion records, periodically reconciled with lifecycle deletion |

An admitted Level A bundle includes every general `artifacts` binding plus the separately `workstation_recording`-bound MKV, metadata and digest sidecars, and the checked manifest/manifest digest. The publisher verifies the video independently against its metadata, including dimensions, duration, codec, container, source SHA, size and SHA-256. Unbound CI diagnostic logs are never published by this workflow. They require explicit sanitization and a new verified manifest binding before long-term retention. Especially valuable *failed* runs need a separately reviewed failed-evidence category; this publisher deliberately refuses failure evidence rather than mislabeling it as passing.

Evidence keys are `<category>/<source-sha>/<run-id>/<attempt>/<filename>`. After every object is conditionally uploaded and read back, the publisher writes the final commit marker to `index/<category>/<source-sha>/<run-id>/<attempt>/<manifest-sha256>.json`. Without the index, an interrupted upload is not a completed publication. An index is an inventory record, not an access grant or a promise that an object has not subsequently expired. A pre-squash PR recording must never be relabeled as evidence for a distinct squash-merge SHA.

## Publishing selected Level A evidence

1. Finish the applicable PR. After squash merge, run `.github/workflows/v010-shell-runtime-qualification.yml` manually on **main** for its exact source commit. Only select a fully successful run/attempt with the 30-day `linura-v010-shell-runtime-<source-sha>` GitHub Actions artifact.
2. On **main**, manually dispatch **Publish approved qualification evidence to private R2**. Specify the exact source SHA, run ID, attempt, category (`baselines` or `regressions`), and a meaningful selection reason. Neither ordinary CI nor PR jobs receive R2 credentials.
3. Inspect the origin run, evidence selection, and privacy classification. A permitted reviewer approves the pending `qualification-archive` environment deployment. The reviewer may be different from the workflow dispatcher; the publication index records both the selector and the reviewer, the evidence-admission timestamp, and the publication workflow's GitHub run ID, attempt and exact publisher-code SHA so the original environment approval can be independently located. GitHub records the approval independently of the downloaded artifact.
4. On an isolated **GitHub-hosted** runner, the workflow retrieves the authoritative source-run record from GitHub, verifies main-branch workflow dispatch and its successful exact run attempt, verifies recorded environment approval, and independently checks the complete manifest-bound bundle, video structure and digests.
5. The publisher uses `If-None-Match: *` for each R2 put and independently downloads the object to verify SHA-256. An existing object is reusable only if its complete bytes match. The index is written last; the publisher never requests public ACLs or deletes objects. An approved retry after a completed publication retains the first index and its original approval audit, provided its source, evidence, category, retention, privacy and object bindings match exactly.

Publication stays manually triggered; selected baseline auto-promotion would require a separate approved policy. Only the R2 publish step receives the secrets. The publisher can be merged after its own CI and code reviews pass, but it must not be declared operationally qualified until the protected environment, actual Cloudflare R2 privacy/lifecycle configuration and a first approved end-to-end upload have been independently checked. That live upload requires PR #189's exact-source Level A lane on main; it cannot be completed merely by merging this publisher PR.

## Level B/C privacy and public demos

No raw Level B or C capture is uploaded to GitHub Actions or R2 by this PR. A future local intake must enforce a separately authenticated owner/reviewer approval identifying the exact source, machine/fixture, run, allowed files and digests, privacy class, purpose, expiration and recipients. Review all recording frames and diagnostic logs; sanitized monitor identifiers alone are not sufficient to remove secrets, on-screen content, terminals, user names or network addresses.

An original and an approved redacted derivative must have **different checksums**, with explicit provenance from the derivative to the original. Public demo videos need a separate publication decision, different access rules and cannot expose private archive URLs. The `physical/`, `interactive/` and `releases/` prefixes are reserved but fail closed until their dedicated intake and retention authorizers exist.

## Recovery, expiration, deletion and rotation

**Interrupted upload:** a missing index denotes incomplete publication. Retry the exact source/run/attempt after reapproval; the publisher verifies all preexisting bytes on R2 before reuse. If the index already exists, an approved retry verifies its recorded object set and retains the initial approval audit rather than overwriting it. An administrator may clean up abandoned unindexed objects after investigating the run and ensuring no concurrent publisher is active. Do not give CI automated delete permissions.

**Expiration and missing evidence:** Cloudflare lifecycle removes baselines after 180 days and regressions after 90 days measured from **object creation**; deletion can occur after the stated timestamp. Index records remain until administrative reconciliation. If an index exists without its referenced object, show the object as unavailable in any future qualification platform, and investigate expiry, deletion and corruption. Do not treat an index as proof of continued availability.

**Privacy deletion:** immediately suspend access; an authorized administrator deletes the applicable objects and records a restricted deletion/tombstone record, including derivative and index disposition as appropriate. Check backups and any configured bucket locks: locks override lifecycle and can delay deletion. This PR deliberately configures no bucket locks.

**Credential rotation:** every 90 days, review credential age. Provision a new bucket-scoped token, update both GitHub environment secrets, validate a controlled publication, then revoke the old token. Never print credentials or copy them into source control, logs, chat, issue attachments or PR descriptions.

The later graphical qualification platform consumes the private index using its own **read-only credential**. It can issue short-lived read-only URLs only after its authenticated server authorizes the specific item. The index is not a replacement for access control.

## Tests

Run `python3 -m unittest -v tests.tooling.test_evidence_publication`. The dedicated PR workflow exercises source, attempt, integrity and approval mismatches; failures and support promotion; symlink/hardlink/traversal; modified recording and invalid media; unauthorized categories; conditional puts and remote readback corruption. These local tests do **not** prove that the real R2 bucket, endpoint, lifecycle configuration, credentials and GitHub approval settings are correct. Confirm those with a separately approved end-to-end publication.
