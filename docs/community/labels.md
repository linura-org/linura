# Issue and contribution labels

Labels are routing metadata, not a substitute for issue content or release evidence.

## Contributor entry labels

- `good first issue` — narrowly scoped work with enough context for a first contribution and no hidden trust-boundary prerequisite.
- `help wanted` — maintainer-approved work where external contribution is specifically welcome.

An issue should not receive `good first issue` merely because it is small; it should be safe to approach without undocumented project knowledge.

## Work-type labels

- `rfc` — tracked design work following the RFC process.
- `compatibility` — host, platform, provider, or environment compatibility work.

## Area labels

- `area:rust` — Rust implementation or public Rust API work.
- `area:linux` — Linux/system integration work.
- `area:docs` — documentation and contributor-facing content.
- `area:security` — public security-hardening work, threat-model maintenance, or security tooling.

## Security label rule

Do **not** label a newly reported vulnerability in public. Vulnerabilities are reported privately under `SECURITY.md`.

`area:security` is only for work that is already safe to discuss publicly, such as hardening, threat-model improvements, or remediation after coordinated disclosure.

## Label governance

Maintainers create and retire labels deliberately. New label families should have a documented meaning and should not duplicate an existing routing concept.

Labels do not expand supported platform claims, change priority guarantees, or confer maintainer authority.
