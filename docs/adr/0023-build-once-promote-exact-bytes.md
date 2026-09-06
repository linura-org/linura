# ADR 0023: Build once, promote exact release bytes

- Status: accepted

## Context

Rebuilding during publication can produce bytes different from the candidate that passed CI/security checks.

## Decision

A tagged exact source SHA produces one candidate artifact set with source identity, checksums, SPDX SBOM, and provenance. Publication is a separate promotion step that verifies the successful candidate run and publishes those same bytes without rebuilding. Published assets are then redownloaded and independently verified.

## Consequences

Release promotion depends on preserved candidate artifacts and exact source/tag identity. A successful publication workflow is not sufficient if candidate proof or post-publication verification fails.
