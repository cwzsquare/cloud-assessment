# Kind Demo

This optional flow creates a local kind cluster, applies the reusable good/bad
fixtures, and runs the Python assessment through kubeconfig mode.

Requirements:

- `kind`
- `kubectl`
- Python dependencies from `apps/api/requirements.txt`

Run:

```bash
deploy/kind-demo/run-kind-demo.sh
```

Outputs:

- `artifacts/reports/all-tools-kind.json`
- `artifacts/reports/all-tools-kind.md`
- `artifacts/reports/all-tools-kind.html`
- `artifacts/assessment.sqlite3`

The PVE lab remains the primary demonstration target. This script is only for a
lighter local demo path when nested PVE is unavailable.
