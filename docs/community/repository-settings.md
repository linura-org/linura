# Repository community settings

This runbook records the GitHub-side state required for Linura's public contributor/community surface. Repository files are CI-validated; GitHub administrative settings must be verified separately because ordinary repository CI must not require administration credentials.

## Required repository state

For `linura-org/linura`:

- Issues: enabled.
- Discussions: enabled.
- Wiki: disabled.
- Private vulnerability reporting: enabled.
- Dependency graph: enabled.
- Dependabot alerts/security updates: enabled where available.
- Secret scanning and push protection: enabled where available.
- Code scanning/CodeQL: enabled.
- Default branch: `main`.
- Existing `main` ruleset and mechanically constrained release-handoff design: preserved unless changed through a focused governance/release-control decision.

Do not add a blanket approval requirement that accidentally blocks Linura's accepted post-readiness machine release handoffs. Independent review for ordinary or security-sensitive human changes should be introduced with rules that preserve the release-control architecture.

## Discussions categories

Create and retain these categories:

- Announcements
- Q&A
- Architecture & RFCs
- Ideas
- Show and tell
- General

Issues remain the system of record for actionable work. Discussions are the durable conversation surface.

## Required labels

Create and retain:

- `good first issue`
- `help wanted`
- `rfc`
- `compatibility`
- `area:rust`
- `area:linux`
- `area:docs`
- `area:security`

Meanings and security handling are defined in [`labels.md`](labels.md).

## Private reporting channels

Before merging documentation that advertises them:

- confirm GitHub Private Vulnerability Reporting is enabled;
- confirm `security@linura.org` reaches a monitored private mailbox or group;
- confirm `conduct@linura.org` reaches a monitored private mailbox or group.

If a role address is not operational, do not publish it as a reporting route.

## Funding

`.github/FUNDING.yml` is the canonical native GitHub Sponsor-button configuration.

The institutional sponsorship program may be publicly described at <https://linura.org/sponsors> while native payment destinations remain inactive. A public sponsorship page is not, by itself, proof that a payment rail or legal recipient is ready.

While [`sponsorship.md`](sponsorship.md) says `Status: inactive`, `FUNDING.yml` must contain no active funding destination. Activate the sponsorship status, the machine-readable funding contract, and `FUNDING.yml` together in one reviewed change only after the destination can actually receive funding and its ownership is verified.

For the planned corporate path, activation additionally requires:

- the legal entity to actually exist;
- the authorized signatory/corporate authority to be established;
- EIN/tax/accounting requirements needed for the selected payment channel to be complete;
- a verified bank, fiscal-host, or payout account;
- the GitHub Sponsors organization profile or other selected funding endpoint to be approved and controlled by Linura;
- public language to avoid representing ordinary corporate sponsorship as a tax-deductible charitable donation.

A monthly funding goal is not, by itself, sufficient reason to bypass these activation requirements.

## Organization community profile

Create the public repository `linura-org/.github` when organization-profile administration is available.

At minimum it should contain:

```text
profile/README.md
```

The profile should link to the canonical `linura-org/linura` repository, `https://linura.org`, documentation, Discussions, security policy, and releases without duplicating detailed governance or architecture text.

Organization-wide default community-health files may be added only where they do not override repository-specific Linura policy. The `linura` repository remains authoritative for Linura governance, security, contribution, and support rules.

## Periodic audit

Before broad community promotion and at least at major release boundaries, verify:

1. documented channels resolve and are monitored;
2. Discussions categories and label taxonomy still match repository documentation;
3. Wiki remains disabled unless an explicit decision establishes it as authoritative;
4. private vulnerability reporting remains enabled;
5. funding destinations, if any, remain owned and policy-compliant;
6. CODEOWNERS and maintainer roles still match governance;
7. repository rules still enforce the intended required checks without creating hidden release gates.
