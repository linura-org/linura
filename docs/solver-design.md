# Dependency and conflict solver design

Linura needs an explainable deterministic solver, not model intuition.

## Current maturity

v0.2.0 established bounded dependency closure, conflict detection and deterministic desired-state compilation over ordered typed inputs. That solver lineage remains part of the current system; v0.7 adds durable intent/Library state and shared causal ownership, while richer alternatives and general constraint solving remain future work.

The solver is **not an authority engine**. It produces selected capabilities/desired state and, after authoritative observation, a non-executable canonical `ReconciliationPlan`. v0.10 operation classification and policy authorization consume that trusted plan downstream; they do not let a UI, provider or model rewrite solver output into authority.

## Inputs

- active intent requirements/constraints/preferences;
- available platform/provider capabilities within the candidate/support boundary;
- blueprint relations (`requires/provides/conflicts/replaces/recommends/optional`);
- typed declarative resource contributions;
- already managed/shared causal ownership from durable Library state;
- user-selected alternatives/pins once alternative selection is implemented.

Authorization policy is not an implicit solver tie-breaker. If future policy constraints participate in solution eligibility, they must be explicit typed inputs with deterministic semantics and must remain distinct from execution authorization.

## Outputs

- selected capability/provider set;
- normalized desired resources;
- explicit conflicts and unsatisfied requirements;
- rejected alternatives with reasons when alternative solving exists;
- deterministic explanation/trace suitable for provenance;
- an observation-bound non-executable plan preview once desired state is compared with current authoritative evidence.

## Required properties

- deterministic result for equivalent normalized inputs;
- cycle-safe, bounded resolution;
- fail closed on unresolved hard conflicts;
- fail closed when selected capabilities demand contradictory values for the same desired resource attribute;
- distinguish hard constraints from preferences as the solver matures;
- support alternatives without silently changing security posture;
- produce an unsatisfied/conflict explanation rather than guessing;
- preserve causal origins/shared ownership needed for safe retirement;
- version solver semantics so replay is auditable;
- never use a model, shell output, provider side effect or executor behavior as an implicit tie-breaker.

## Historical v0.2 boundary

The initial deterministic planner resolves required capabilities, rejects declared conflicts and missing capabilities, merges typed desired-resource contributions in ordered collections, preserves semantic origins, and compares desired attributes with a validated current observation projection.

A missing observed attribute is a blocker rather than evidence that the desired value is absent. A stale or future observation cannot be used as current planning truth. Plan previews carry prospective risk but always report that execution is unauthorized.

The implementation may eventually use SAT/SMT/constraint techniques if complexity warrants it, but the public model must not depend on a particular solver library.
