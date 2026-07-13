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
