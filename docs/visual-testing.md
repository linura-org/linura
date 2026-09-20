# Visual and interaction testing

Linura intends to be beautiful, but visual quality must be qualified through reproducible evidence rather than screenshots attached informally to pull requests.

`design/tokens.json` defines the initial semantic design-token vocabulary. `visual/baselines/manifest.json` is the canonical v0.10 reviewed-baseline manifest.

## v0.10 evidence contract

The v0.10 workstation contract requires reviewed non-null baselines for the required surfaces, representative resolution/scale coverage, passing captures for every reviewed baseline, at least one retained reviewed failed comparison/diff, and digest-verified interaction/accessibility reports.

Required visual/accessibility surfaces currently include:

- `linura-firstboot`;
- `linura-control-center`;
- command palette;
- quick settings;
- bounded desktop-shell integration;
- notifications/OSD.

The qualification manifest binds `visual/baselines/manifest.json` by SHA-256. Baseline, capture, failed-capture, diff and accessibility/interaction report artifacts are path-bounded and digest-bound; unrelated files or hand-authored booleans cannot substitute for executed evidence.

## Image verification

`tools/visual.py` remains a local visual helper, but release readiness is enforced by `tools/check_v010_workstation_qualification.py`.

The v0.10 checker:

- bounds PNG file size, dimensions, pixel count, compressed data and decompression;
- rejects unsupported/ambiguous PNG critical and color-management semantics rather than comparing bytes under an unknown rendering model;
- includes transparency in rendered RGBA equivalence;
- verifies exact baseline/capture pixel equivalence for passing comparisons;
- requires retained failure evidence to identify and SHA-256-bind the reviewed baseline, an actually different failed capture and the retained diff;
- verifies retained diff pixels against the canonical failed-pair delta.

A `null`/placeholder baseline or missing digest remains **not qualified**.

## Interaction/accessibility evidence

Visual similarity alone is insufficient. Required surfaces need executed retained reports covering the contract's interaction/accessibility expectations, including keyboard/pointer behavior, semantic/screen-reader accessibility, focus/navigation, reduced motion, representative display scaling, offline/error states and reconnect behavior.

The design-system and visual-testing contracts therefore prove both **what the interface looks like** and **how the supported interaction behaves**.
