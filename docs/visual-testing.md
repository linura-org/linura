# Visual and interaction testing

The v0.10 tray input gate uses a qualification-only native Wayland keyboard
built from the exact archived source in the pinned Arch guest. One device and
keymap remain connected across the popup lifecycle. Short taps queue their
press and release before compositor synchronization; command exit or producer
acknowledgement alone is never proof of delivery. The retained atomic receiver
snapshots require exactly one non-repeat press, release, click and popup open.
Five short taps exercise cancellation, activation and repeated reopening; a
deliberate held key is released only after observed Qt auto-repeat events, with
no click or popup before release and no extra clicks afterward. Native Escape
must dismiss and restore opener focus. Popup cancellation is handled by the
focused native action row, including shortcut override, rather than inferred
from a declared top-level window shortcut. Panel window shortcuts must bind to
a native content item. Merely declaring an Escape binding cannot prove it works. Opener
focus acquisition is idempotent and waits for settled native/item focus before
sending input, including after popup dismissal; focus readiness retries must
never resend activation events. Native
mapping, keyboard focus and retention assertions remain independent. Reports
and producer receipts are digest-bound with the source/image evidence.

Source-contract mutation checks supplement executable producer tests and real
graphical behavior; they cannot certify input timing or focus. After an
intermittent failure, require independent fresh-guest runs of the same final
source and substrate and retain every failure. Repeating until one run passes
does not establish stability. Physical Q11 evidence remains a separate gate.

Linura intends to be beautiful, but visual quality must be qualified through reproducible evidence rather than screenshots attached informally to pull requests.

`design/tokens.json` defines the initial semantic design-token vocabulary. `visual/baselines/manifest.json` is the canonical v0.10 reviewed-baseline manifest.

## v0.10 evidence contract

The v0.10 workstation contract requires reviewed non-null baselines for the required surfaces, representative resolution/scale coverage, passing captures for every reviewed baseline, at least one retained reviewed failed comparison/diff, and digest-verified interaction/accessibility reports. A structurally valid PNG is not sufficient: reviewed baselines and passing captures must contain representative non-uniform rendered content, and each surface report must include its exact domain-specific workflow observations in addition to generic input/accessibility checks.

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

## Automated and live workstation video

Video complements, but never replaces, deterministic visual and interaction evidence. The v0.10 acceptance contract captures the automated Level A Wayland session directly inside the guest with `wf-recorder`; it does not scrape a host VNC/GTK window. Level B interactive VM sessions and Level C maintained-hardware sessions use the same recorder and verifier when recording is requested.

Recordings are bounded Matroska/FFV1 artifacts with exactly one video stream and no audio. `tools/workstation_acceptance.py verify-recording` independently checks container, codec, dimensions, duration and file-size bounds with `ffprobe`, rejects unsafe/symlink inputs, computes SHA-256, and writes source-bound metadata. CI re-verifies the guest-generated Level A video on the host before binding it into the exact-source runtime evidence manifest.

A passing video means “this exact automated/live session was captured and structurally verified.” It does **not** mean pixels were approved, accessibility passed, or hardware support was established. Reviewed screenshots/diffs, interaction/accessibility reports and Level C fixture evidence retain those separate responsibilities.

Manual Level B/Level C recordings can contain whatever is visibly rendered in the session. Use controlled qualification fixtures/accounts, avoid displaying secrets or unrelated personal data, and review artifacts before sharing them outside the intended evidence store. The recorder intentionally captures no audio, but that does not make visible content non-sensitive.
