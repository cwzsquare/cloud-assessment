# Cloud Native Security Assessment Prototype

This repository implements the cloud-native security assessment prototype from
`doc/云原生安全评估原型系统工程文档-vibe-coding-v0.2.md`.

Primary entry points:

- `apps/api/README.md`: Python assessment CLI, API server, tests, and report export.
- `apps/web/static/`: static dashboard served by the API server.
- `deploy/pve-lab/README.md`: PVE nested Kubernetes lab delivery guide.
- `deploy/kind-demo/run-kind-demo.sh`: optional local kind demo flow.
- `fixtures/`: reusable good/bad Kubernetes manifests and log fixtures.
- `ops/cnsec-lab/`: executable PVE/Kubernetes bootstrap scripts and good/bad manifests.
- `artifacts/reports/`: generated demo JSON, Markdown, and HTML reports.

Start the API/Web dashboard with Docker Compose:

```bash
docker compose up
```

Then open `http://127.0.0.1:18080/`.

Run the current PVE lab assessment:

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

Run tests:

```bash
PYTHONPATH=apps/api python3 -m unittest discover -s apps/api/tests -v
```
