# ADR 0049 — Separate implementation acceptance from deferred workstation qualification

- Status: Accepted
- Date: 2026-11-21
- Scope: v0.10 implementation-slice acceptance and future B/C qualification
- Refines: ADR 0045 and ADR 0048 acceptance sequencing; authority and recovery rules remain unchanged

## Context

The workstation acceptance contract makes exact-source Level A a required
development gate, Level B an optional interactive VM lane and Level C the
maintained physical Q11 release boundary. Earlier implementation slices landed
without claiming B/C execution or release-qualified workstation support. S17's
recorded native Level A evidence likewise leaves B/C and complete release
qualification outstanding.

Later S21 recovery notes grouped real Level A/B acceptance together. Treating
those references as a new mandatory B merge gate conflicts with the existing
optional Level B contract and prevents implementation completion solely because
no operator or virtualization host is available. Physical Q11 already belongs
to S30. The owner has explicitly chosen to execute unavailable B/C qualification
in later slices while completing the current implementation work.

## Decision

Implementation acceptance and runtime/release qualification are separate claims.
For PR #259, the source scope remains the complete S21-2 display implementation,
including Stage 5 replacement-invocation adoption, shared-reference retirement
and bounded artifact cleanup. Retained history cannot replace fresh live
authorization, an independently completed new native/Root lifetime or full
authenticated ownership analysis.

Before final review and merge, complete all in-scope source, the full real
exact-source Level A display mutation/recovery matrix, applicable inherited
native/security/evidence gates and independent whole-PR review. Component tests,
builds, bootstrap sessions, recordings and a serialized diagnostic cannot replace
those gates. Original freshness/deadline bounds and the required concurrent
qualification remain unchanged.

Level B/C execution is not a prerequisite for this implementation merge. Keep
both explicitly unrun until suitable infrastructure, authenticated access,
operators and independent evidence are available. For a future claimed B pass,
all applicable cases, variants, source identities, postconditions and recovery
oracles remain mandatory. For C, the full independently physical Q11 matrix
remains mandatory before release qualification. There is no placeholder pass,
waiver, simulated physical evidence or substitution of A for B/C.

Track deferred work through the existing sequencing:

| Work | Owning later scope | Required completion evidence |
| --- | --- | --- |
| Interactive S21 domain integration and operator exercises | S21-7 and S29 experience/input/accessibility qualification | Same exact-source candidate, owner and executor; complete interactive cases, authenticated operator and independent recovery/verifier evidence |
| Maintained physical workstation execution | S30 / Q11 | Complete physical case set, independently nonvirtual machine/source/provider identities and retained execution provenance |
| Workstation recovery, power-loss and security qualification | S31 / Q12–Q13 | Applicable real fault/security cases and independent exact-source evidence |
| Inherited qualification, support promotion and release closure | S32 / Q14–Q15 | Complete applicable release evidence and the protected support-promotion path |

S21-7 is the existing S21 integration sub-slice, not a new top-level slice. The
32-slice dependency ledger, S17 prerequisite and merged-PR evidence obligations
stay intact. Completing S21-2 does not mark all of S21 complete.

The deferred qualification record must retain its case inventory and missing
prerequisites. At present Level B is **Blocked — environment/operator not
provisioned**, and Level C lacks a maintained physical workstation. A source
change requires fresh evidence for that source; later runs cannot inherit a
pass from a prior implementation revision.

## Production and compatibility boundary

This decision changes no operation class, policy rule, executor admission,
public interface, durable schema or recovery semantics. The canonical managed
pipeline, source pinning, no-replay behavior and independent observations remain
required. Production Authority1 display mutations stay unsupported until a
separate reviewed activation decision and all of its applicable gates pass.

Do not alter profile/support/readiness flags or frozen released claims on the
basis of source completion or this decision. The existing machine contract stays
authoritative: Level A is required, Level B remains optional and Level C remains
required for Q11 release qualification. References to Level A/B in older S21
implementation notes must be read with this acceptance distinction.
