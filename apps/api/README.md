# Cloud Native Security API Prototype

This package contains the first Python implementation of the cloud-native
assessment rules described in `doc/云原生安全评估原型系统工程文档-vibe-coding-v0.2.md`.

Run an offline manifest scan with the full prototype profile:

```bash
PYTHONPATH=apps/api python3 -m cloudnative_security.cli \
  --manifest ops/cnsec-lab/manifests \
  --profile all_tools_demo \
  --task-id local-all-tools \
  --output artifacts/reports/all-tools-local.json \
  --markdown-output artifacts/reports/all-tools-local.md \
  --html-output artifacts/reports/all-tools-local.html \
  --sqlite artifacts/assessment.sqlite3
```

Run tests:

```bash
PYTHONPATH=apps/api python3 -m unittest discover -s apps/api/tests
```

Run the fixture E2E smoke path:

```bash
PYTHONPATH=apps/api python3 -m unittest apps.api.tests.test_e2e_smoke -v
```

Start the API/Web dashboard with Docker Compose from the repository root:

```bash
docker compose up
```

Scan the current PVE lab through SSH:

```bash
PYTHONPATH=apps/api python3 -m cloudnative_security.cli \
  --pve-ssh cloudnative-env \
  --profile all_tools_demo \
  --task-id pve-all-tools \
  --output artifacts/reports/all-tools-pve.json \
  --markdown-output artifacts/reports/all-tools-pve.md \
  --html-output artifacts/reports/all-tools-pve.html \
  --sqlite artifacts/assessment.sqlite3
```

Start the minimal JSON API over the persisted SQLite store:

```bash
PYTHONPATH=apps/api python3 -m cloudnative_security.cli \
  --serve \
  --host 127.0.0.1 \
  --port 18080 \
  --sqlite artifacts/assessment.sqlite3
```

Available endpoints:

- `GET /api/health`
- `GET /api/schema` and `GET /api/schema/Finding`
- `POST /api/targets`
- `GET /api/targets`
- `GET /api/targets/{target_id}`
- `DELETE /api/targets/{target_id}`
- `GET /api/assessments`
- `GET /api/assessments/{task_id}/events`
- `GET /api/assessments/{task_id}/progress`
- `POST /api/assessments/{task_id}/cancel`
- `GET /api/checkpoints`
- `POST /api/checkpoints`
- `PATCH /api/checkpoints/{checkpoint_id}/weight`
- `GET /api/findings?task_id=pve-all-tools`
- `GET /api/findings/{finding_id}`
- `GET /api/raw-snapshots?task_id=pve-all-tools`
- `GET /api/dashboard-data?task_id=pve-all-tools` — frontend render payload containing checkpoints, findings, report, raw snapshots, RBAC matrix, task events, and integration pipeline data.
- `GET /api/reports/pve-all-tools`
- `GET /api/reports/pve-all-tools.md`
- `GET /api/reports/pve-all-tools.html`
- `POST /api/reports/pve-all-tools/recalculate`
- `POST /api/assessments`

Open the dashboard served by the same process:

```text
http://127.0.0.1:18080/
```

Reusable demo fixtures:

- `fixtures/k8s-good`
- `fixtures/k8s-bad`
- `fixtures/logs/falco_events.jsonl`
- `fixtures/logs/authlog_ssh_bruteforce.log`
