# Linura Control Center

Planned graphical management client for observed and desired state, intents, system graph, capability resolution, approvals, drift, provenance, audit, explainability and recovery.

Linura Control Center is a client of the versioned Linura protocol. It must contain no distro-specific backend logic and receives no privileged executor handle.

## Canonical desktop identity

The primary Linura graphical application owns the stable reverse-DNS identity
`org.linura.Linura`. The Control Center remains an unprivileged client of the versioned
Linura protocol; this identity does not move `linurad`, policy, authority,
executors, or verifiers into the desktop sandbox.

Upstream desktop metadata lives in `data/`:

- `org.linura.Linura.metainfo.xml`
- `org.linura.Linura.desktop`
- `icons/hicolor/scalable/apps/org.linura.Linura.svg`

The application icon is copied byte-for-byte from the canonical blue transparent
square brand asset in `linura-platform`:
`public/brand/blue/exports/icons/pwa-icon-512x512-transparent.svg`.
The canonical gate pins its Git blob ID
`b3bf10b29762d605ad0818dfb081d86fe03e0a98`, so changes to paint, CSS, embedded content, or the
transparent canvas fail closed instead of relying on SVG-shape heuristics.

This is a pre-Flathub identity contract, not a placeholder publication. A
Flathub submission remains blocked until the graphical client is executable and
has real release metadata, application screenshots, a buildable offline Flatpak
manifest, and a sandbox-safe protocol path to the host-side Linura services.
