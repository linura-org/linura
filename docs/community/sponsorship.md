# Sponsorship charter and policy

Status: inactive pending a verified funding destination.

Linura may accept sponsorship, grants, donations, in-kind infrastructure, or other project funding to support open-source development. Linura's funding model is designed for infrastructure software: institutional sponsorship can fund meaningful engineering outcomes, while technical and governance authority remains independent of money.

This charter defines what sponsorship may support, what recognition a sponsor may receive, and what funding can never purchase.

## Public identity and contacts

The public sponsorship identity is **Linura**.

- Institutional sponsorship: `sponsors@linura.org`
- Strategic and technical partnerships: `partners@linura.org` (`partnerships@linura.org` is an alias)
- Equity and investment conversations: `investors@linura.org`
- Maintainer correspondence: `ehsan@linura.org`

A human maintainer or a legal entity may appear as the contractual signatory when required, but that does not change the public identity or technical authority of the open-source project.

## Funding model

Linura's intended funding model has four distinct lanes:

- **Institutional sponsorship** — the primary sponsorship lane for organizations whose work intersects with Linux, AI infrastructure, cloud platforms, hardware, security, runtimes, or developer infrastructure.
- **Public sponsorship** — a low-friction channel for individuals and smaller organizations once a verified public funding destination is active.
- **Grants and foundations** — project funding for work such as security, open-source infrastructure, research, accessibility, compatibility, or hardware qualification.
- **Commercial relationships** — future support, qualification, integration, certification, or managed-service work governed separately from sponsorship and project governance.

Sponsorship, partnership, investment, commercial contracts, and governance are separate relationships. One does not imply another. Partnership boundaries are defined in [`partnerships.md`](partnerships.md).

## What funding may support

Project funding may be used for:

- implementation and maintenance;
- CI, release, hosting, and other project infrastructure;
- hardware qualification and test equipment;
- security review and remediation;
- documentation and contributor/community work;
- accessibility and compatibility work;
- travel or fees directly related to project representation;
- professional services needed to operate the project responsibly.

The first institutional programs are defined in [`funded-programs.md`](funded-programs.md). A sponsor may fund one or more programs, but program funding never changes the acceptance criteria for project work.

When practical, Linura should describe material project-funded work publicly without exposing private financial, contractual, security, or personal information.

## Sponsorship classes

Linura recognizes a small number of sponsorship classes without attaching project authority to them:

- **Founding Sponsor** — an organization that materially supports Linura during its formative pre-1.0 period. The designation is available only for agreements executed before the first stable v1.0 release. It records early support; it does not confer founder, owner, board, or governance status.
- **Strategic Sponsor** — an organization providing meaningful recurring or annual financial support for the open-source project.
- **Infrastructure Sponsor** — an organization contributing substantial hardware, cloud capacity, CI resources, test environments, engineering resources, or other in-kind infrastructure.
- **Community Sponsor** — an individual or organization supporting the project through a verified public sponsorship channel at a smaller scale.

A scoped funded program is an engagement model, not a fifth governance class. Founding or Strategic Sponsors may fund a program, and a program-specific sponsorship may be agreed independently when appropriate.

Specific amounts and negotiated benefits remain part of individual sponsorship proposals and agreements rather than this governance document.

## What sponsors may receive

Depending on the sponsorship agreement, Linura may provide:

- name or logo recognition on the project website;
- acknowledgement in project or release communications;
- periodic project briefings;
- public or sponsor-specific summaries of funded work;
- clearly scoped engineering deliverables or qualification work;
- reasonable coordination around donated infrastructure or test resources.

Sponsor briefings do not include confidential vulnerability reports, private conduct reports, credentials, embargoed security information, or other access that would bypass normal project policy.

Recognition is not guaranteed forever. Linura may remove or revise recognition after an agreement ends, when a sponsor changes identity, or when continued recognition would create a legal, ethical, security, independence, or reputation risk.

## What funding does not grant

Funding does **not** grant:

- architectural decision authority;
- security-policy exceptions;
- roadmap vetoes or guaranteed prioritization;
- merge, maintainer, repository-admin, or release authority;
- privileged technical access;
- access to confidential vulnerability or conduct reports;
- undisclosed product influence;
- a private fork or private version of the open-source project by default;
- a private support SLA or commercial-support entitlement.

Technical and governance authority follows [GOVERNANCE.md](../../GOVERNANCE.md), regardless of funding source.

A sponsor may fund work toward a concrete outcome, but funded code and architecture must pass the same design, security, testing, compatibility, review, and release requirements as any other contribution. Funding is not evidence that a change is correct, safe, or acceptable for merge.

## Conflicts and disclosure

Maintainers must disclose a material sponsor or vendor relationship when it could reasonably affect a project decision.

Material funded work should identify its sponsorship when doing so is practical and does not violate legitimate confidentiality obligations. Linura should avoid agreements that require hidden technical influence, undisclosed preferential treatment, or exceptions to published project controls.

The reporting and disclosure baseline is defined in [`sponsor-reporting.md`](sponsor-reporting.md).

## Recognition and endorsement

Sponsor acknowledgment is recognition only. It does not imply that Linura endorses a sponsor's products, policies, claims, or services, and sponsorship does not grant endorsement rights over Linura.

Linura may decline or return funding when accepting it would create a legal, ethical, security, independence, or reputation risk.

## Standard agreement boundary

The public baseline for sponsorship agreements is defined in [`sponsorship-standard-terms.md`](sponsorship-standard-terms.md). Those terms are policy guidance, not an executable contract. A real agreement must identify the verified receiving party and be reviewed for the applicable jurisdiction, tax, accounting, sanctions, and other legal requirements.

## Commercial relationships

Future paid qualification, enterprise support, integration, certification, managed offerings, or other commercial work must be described and contracted separately from sponsorship.

Commercial work may fund project development, but it does not silently change open-source governance, technical authority, security policy, licensing, or release requirements.

## Legal and payment activation

Before Linura accepts material sponsorship, the receiving party or fiscal host must be clearly identified and capable of handling the applicable agreement, invoicing, tax, accounting, and payment requirements.

The long-term intent is to use a dedicated legal entity for institutional sponsorship, investment, employment, and commercial relationships. A fiscal host may be used as a temporary bridge for open-source sponsorship if needed, but it must not silently become the owner of Linura governance or technical authority.

The repository contains `.github/FUNDING.yml` as the canonical GitHub funding configuration. It remains inactive until a real funding endpoint is verified and this status is changed in the same reviewed change.

The public sponsorship program may be described at <https://linura.org/sponsors> before a payment destination is active. That page must not imply that Linura can accept funds through a channel that has not been verified.

Do not point the Sponsor button at a placeholder URL, an unverified account, or a general project homepage that cannot actually receive funding.
