# AGENTS

## Reporting constraints

- For project technical reports, progress summaries, weekly reports, and acceptance summaries, focus on the project itself:
  - implemented features
  - technical design and rule logic
  - code, tests, validation, reports, and user-visible results
- Do not include unrelated environment or ops details by default, including:
  - PVE host or VM management
  - WireGuard, NAT, routing, underlay/uplink paths
  - snapshots, old VM cleanup, host resource housekeeping
- Only mention those environment details when the user explicitly asks for deployment/runtime troubleshooting context.

## Structured assessment invariants

- Treat `SourceDescriptor`, collection/processing runs, quality results, lineage, and asset graphs as persisted evidence contracts; do not replace them with display-only summaries.
- Missing evidence is `UNKNOWN` with an explicit reason. Never infer secure configuration from absent manifests, logs, certificates, or runtime metrics.
- Secret, token, private-key, and certificate material is sanitized at collection boundaries and remains redacted in normalization actions, conflicts, graphs, APIs, and dashboard output.
- Preserve partial pipeline results and step-level warnings/errors when one adapter or processing step fails.
- Resource/API/UI changes must keep source references and reverse lineage queryable; update focused behavior tests for changed contracts.
