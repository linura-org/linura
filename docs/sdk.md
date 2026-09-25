# Linura SDK

`linura-sdk` is the public, non-privileged Rust façade for Linura clients and integrations.

## Purpose

Applications should not need to depend directly on internal authority, provider or executor crates merely to understand Linura's system model. The SDK therefore re-exports the stable client-facing concepts required to inspect and request Linura state:

- typed IDs and actors, including `SetupId` and `ProfileId`;
- intents, requirements, reusable setups and machine profiles;
- portable setup/profile export and adoption request/response contracts;
- system graph and removal-impact types;
- capability blueprints and resolution results;
- protocol requests/responses;
- explainability and semantic provenance types.

`linuractl` consumes this façade as an architectural proof that ordinary clients do not need authority internals.

A client may save, inspect, export or request adoption of reusable setups through public contracts, but adoption still occurs behind Linura Control. The SDK does not turn a setup/profile into execution authority.

## Python package

`bindings/python` owns the canonical PyPI distribution and import namespace, both named
`linura`. Its initial `0.0.1` surface is deliberately narrower than `linura-sdk`:
canonical project metadata, Experimental `Control1` identifiers, and non-executing
local `linuractl` discovery.

It contains no authority, policy, provider, executor, verifier, or persistence
implementation, does not connect to D-Bus, and does not invoke `linuractl`. A future
Python transport client must consume the same versioned public contracts and preserve
the same authority boundaries rather than introducing a parallel control path.

PyPI is also downstream of Linura's canonical release authority. Trusted Release
Proof constructs and independently reproduces the Python wheel under an exact Python
patch release and fully pinned PEP 517 build requirements. Release preflights the
sealed artifact without OIDC, then a minimal `pypi` GitHub Environment job with no
repository checkout receives the only PyPI OIDC publication authority. Release
Verification freshly downloads the PyPI file and compares its digest. A
package-specific tag or standalone rebuild is not publication authority.

## Explicit exclusions

The SDK does **not** expose:

- `linura-control` internals;
- policy-engine implementation details;
- provider registration/runtime internals;
- privileged executors;
- direct root/system mutation handles;
- model-provider credentials or model execution as authority;
- secret values inside portable setup/profile structures.

Future transports may add an SDK client implementation around D-Bus or a separately authenticated remote gateway. The domain types remain transport-neutral.
