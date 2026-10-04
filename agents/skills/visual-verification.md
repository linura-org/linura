# Visual verification task guide

- Update `visual/baselines/manifest.json` only with reviewed surfaces.
- A null baseline means not qualified, not passing.
- Capture representative resolution/scale states.
- Preserve failed-comparison evidence as a retained baseline/capture/diff tuple: identify the reviewed baseline, retain the failed capture and diff, SHA-256 bind every artifact, and retain the domain-separated binding over those digests. An unrelated reviewed screenshot is not a failure diff.
- Pair visual comparison with interaction/accessibility tests; pixel equality alone is insufficient.
- Interaction/accessibility readiness requires retained digest-verified runner reports for every qualified surface, including runner identity and explicit per-check results. Hand-authored manifest booleans are not execution evidence.
- Evidence readers must remain bounded before and during decoding; a small compressed artifact must not be able to force unbounded memory expansion.

- Workstation video is supporting evidence, not a pixel/accessibility oracle. Capture Level A/B/C sessions inside the Wayland session, verify bounded container/codec/dimensions/duration and SHA-256 metadata, and never infer physical-hardware support from VM video.

- A recorder that exits early or fails during requested finalization invalidates the recording even if a parseable partial Matroska file exists. Preserve and verify the recorder's final exit status before accepting visual evidence.
