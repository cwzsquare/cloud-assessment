from __future__ import annotations

import json
import mimetypes
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .adapters import AssessmentRequest
from .orchestrator import AssessmentOrchestrator
from .report_renderer import render_html_report, render_markdown_report
from .schemas import schema_bundle
from .storage import AssessmentStore


class ApiHandler(BaseHTTPRequestHandler):
    store: AssessmentStore
    orchestrator: AssessmentOrchestrator
    static_dir = Path(__file__).resolve().parents[2] / "web" / "static"

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length) or b"{}")

    def _text(self, text: str, content_type: str, status: int = 200) -> None:
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _static(self, path: str) -> bool:
        if path == "/":
            rel = "index.html"
        elif path.startswith("/static/"):
            rel = path.removeprefix("/static/")
        elif path in {"/index.html", "/app.js", "/styles.css"}:
            rel = path.removeprefix("/")
        else:
            return False
        candidate = (self.static_dir / rel).resolve()
        if not str(candidate).startswith(str(self.static_dir.resolve())) or not candidate.is_file():
            self._json({"error": "not found"}, 404)
            return True
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self._text(candidate.read_text(), content_type)
        return True

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not parsed.path.startswith("/api/"):
            if self._static(parsed.path):
                return
            self._json({"error": "not found"}, 404)
            return
        if parsed.path == "/api/health":
            self._json({"status": "ok", "adapters": self.orchestrator.registry.healthcheck()})
            return
        if parsed.path == "/api/schema":
            self._json(schema_bundle())
            return
        if parsed.path.startswith("/api/schema/"):
            schema_name = parsed.path.rsplit("/", 1)[-1]
            bundle = schema_bundle()
            schema = bundle.get("$defs", {}).get(schema_name)
            self._json(schema if schema else {"error": "not found"}, 200 if schema else 404)
            return
        if parsed.path == "/api/checkpoints":
            self._json(self.store.list_checkpoints())
            return
        if parsed.path == "/api/dashboard-data":
            task_id = query.get("task_id", [None])[0]
            report = self.store.get_report(task_id) if task_id else None
            if not report:
                self._json({"error": "not found"}, 404)
                return
            summary = report.get("summary", {})
            self._json(
                {
                    "schema_version": "dashboard-data/v1",
                    "task_id": task_id,
                    "generated_at": report.get("generated_at"),
                    "checkpoints": self.store.list_checkpoints(),
                    "findings": self._query_findings(query, task_id),
                    "report": report,
                    "raw_snapshots": self.store.list_raw_snapshots(task_id),
                    "rbac_matrix": self.store.query_rbac_matrix(task_id),
                    "task_events": self.store.list_task_events(task_id),
                    "integration_pipeline": summary.get("integration_pipeline"),
                }
            )
            return
        if parsed.path == "/api/integration":
            task_id = query.get("task_id", [None])[0]
            report = self.store.get_report(task_id) if task_id else None
            pipeline = report.get("summary", {}).get("integration_pipeline") if report else None
            self._json(pipeline if pipeline else {"error": "not found"}, 200 if pipeline else 404)
            return
        if parsed.path == "/api/targets":
            self._json(self.store.list_targets())
            return
        if parsed.path.startswith("/api/targets/"):
            target_id = unquote(parsed.path.rsplit("/", 1)[-1])
            target = self.store.get_target(target_id)
            self._json(target if target else {"error": "not found"}, 200 if target else 404)
            return
        if parsed.path == "/api/assessments":
            self._json(self.store.list_tasks())
            return
        if parsed.path.startswith("/api/assessments/"):
            parts = parsed.path.split("/")
            task_id = unquote(parts[3]) if len(parts) > 3 else ""
            if len(parts) == 4:
                task = self.store.get_task(task_id)
                self._json(task if task else {"error": "not found"}, 200 if task else 404)
                return
            if len(parts) == 5 and parts[4] == "events":
                self._json(self.store.list_task_events(task_id))
                return
            if len(parts) == 5 and parts[4] == "progress":
                events = self.store.list_task_events(task_id)
                latest = events[-1] if events else None
                self._json({"task_id": task_id, "latest": latest, "events": events}, 200)
                return
            if len(parts) == 5 and parts[4] == "findings":
                self._json(self._query_findings(query, task_id))
                return
            if len(parts) == 5 and parts[4] == "summary":
                report = self.store.get_report(task_id)
                self._json(report.get("summary", {}) if report else {"error": "not found"}, 200 if report else 404)
                return
            if len(parts) == 5 and parts[4] == "report":
                report = self.store.get_report(task_id)
                self._json(report if report else {"error": "not found"}, 200 if report else 404)
                return
            if len(parts) == 5 and parts[4] == "rbac-matrix":
                limit_value = query.get("limit", [None])[0]
                try:
                    limit = int(limit_value) if limit_value not in {None, ""} else None
                except ValueError:
                    limit = None
                dangerous_only = query.get("dangerous_only", [""])[0].lower() in {"1", "true", "yes", "on"}
                matrix = self.store.query_rbac_matrix(
                    task_id,
                    subject=query.get("subject", [None])[0],
                    resource=query.get("resource", [None])[0],
                    verb=query.get("verb", [None])[0],
                    scope=query.get("scope", [None])[0],
                    role=query.get("role", [None])[0],
                    binding=query.get("binding", [None])[0],
                    dangerous_only=dangerous_only,
                    limit=limit,
                )
                self._json(matrix if matrix else {"error": "not found"}, 200 if matrix else 404)
                return
        if parsed.path == "/api/findings":
            self._json(self._query_findings(query))
            return
        if parsed.path.startswith("/api/findings/"):
            finding = self.store.get_finding(unquote(parsed.path.rsplit("/", 1)[-1]))
            self._json(finding if finding else {"error": "not found"}, 200 if finding else 404)
            return
        if parsed.path == "/api/raw-snapshots":
            self._json(self.store.list_raw_snapshots(query.get("task_id", [None])[0]))
            return
        if parsed.path.startswith("/api/reports/"):
            task_id = unquote(parsed.path.rsplit("/", 1)[-1])
            if task_id.endswith(".html"):
                task_id = task_id[:-5]
                report = self.store.get_report(task_id)
                self._text(render_html_report(report), "text/html; charset=utf-8", 200 if report else 404)
                return
            if task_id.endswith(".md"):
                task_id = task_id[:-3]
                report = self.store.get_report(task_id)
                self._text(render_markdown_report(report), "text/markdown; charset=utf-8", 200 if report else 404)
                return
            report = self.store.get_report(task_id)
            self._json(report if report else {"error": "not found"}, 200 if report else 404)
            return
        self._json({"error": "not found"}, 404)

    def _query_findings(self, query: dict[str, list[str]], task_id: str | None = None) -> list[dict[str, object]]:
        return self.store.list_findings(
            task_id=task_id or query.get("task_id", [None])[0],
            tool_id=query.get("tool_id", [None])[0],
            checkpoint_id=query.get("checkpoint_id", [None])[0],
            severity=query.get("severity", [None])[0],
            status=query.get("status", [None])[0],
            namespace=query.get("namespace", [None])[0],
            kind=query.get("kind", [None])[0],
            keyword=query.get("keyword", [None])[0],
        )

    @classmethod
    def _execute_assessment(cls, request: AssessmentRequest) -> None:
        try:
            cls.store.replace_task_events(
                request.task_id,
                [
                    {"stage": "queued", "status": "running", "message": "任务已提交，开始评估", "progress": 5, "detail": {"profile": request.profile}},
                    {"stage": "running", "status": "running", "message": "后台执行评估工具", "progress": 10, "detail": {"profile": request.profile}},
                ],
            )
            cls.store.conn.commit()
            result = cls.orchestrator.run(request)
            cls.store.save_result(result)
        except Exception as exc:
            cls.store.save_task(request.task_id, request.profile, request.__dict__, "failed")
            cls.store.append_task_event(request.task_id, "failed", "failed", f"评估任务失败: {exc}", 100)
            cls.store.conn.commit()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler naming
        parsed = urlparse(self.path)
        if parsed.path == "/api/checkpoints":
            try:
                checkpoint = self.store.upsert_checkpoint(self._read_json())
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
            self._json(checkpoint, 201)
            return
        if parsed.path == "/api/targets":
            target = self.store.create_target(self._read_json())
            self._json(target, 201)
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/recalculate"):
            self._read_json()
            task_id = unquote(parsed.path.split("/")[-2])
            report = self.store.recalculate_report_weights(task_id)
            self._json(report if report else {"error": "not found"}, 200 if report else 404)
            return
        if parsed.path.startswith("/api/assessments/") and parsed.path.endswith("/cancel"):
            self._read_json()
            task_id = unquote(parsed.path.split("/")[-2])
            task = self.store.cancel_task(task_id)
            self._json(task if task else {"error": "not found"}, 200 if task else 404)
            return
        if parsed.path != "/api/assessments":
            self._json({"error": "not found"}, 404)
            return
        payload = self._read_json()
        target = self.store.get_target(str(payload.get("target_id"))) if payload.get("target_id") else None
        if payload.get("target_id") and not target:
            self._json({"error": "target not found"}, 404)
            return
        merged = (target or {}) | payload
        request = AssessmentRequest(
            task_id=merged.get("task_id", "api-task"),
            profile=merged.get("profile", "all_tools_demo"),
            target_id=merged.get("target_id"),
            manifest=merged.get("manifest"),
            kubeconfig=merged.get("kubeconfig"),
            pve_ssh=merged.get("pve_ssh"),
            control_plane_ip=merged.get("control_plane_ip", "10.20.0.11"),
            ssh_key=merged.get("ssh_key", "/root/.ssh/agent_lab"),
            ssh_user=merged.get("ssh_user", "agent"),
            options=merged.get("options", {}),
        )
        self.store.save_task(request.task_id, request.profile, request.__dict__, "running")
        self.store.replace_task_events(
            request.task_id,
            [{"stage": "queued", "status": "running", "message": "任务已提交，开始评估", "progress": 5, "detail": {"profile": request.profile}}],
        )
        self.store.conn.commit()
        threading.Thread(target=type(self)._execute_assessment, args=(request,), daemon=True).start()
        self._json({"task_id": request.task_id, "status": "running", "request": request.__dict__}, 202)

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler naming
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/targets/"):
            target_id = unquote(parsed.path.rsplit("/", 1)[-1])
            deleted = self.store.delete_target(target_id)
            self._json({"deleted": deleted}, 200 if deleted else 404)
            return
        self._json({"error": "not found"}, 404)

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler naming
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/checkpoints/"):
            self._json({"error": "not found"}, 404)
            return
        parts = parsed.path.split("/")
        checkpoint_id = unquote(parts[3]) if len(parts) > 3 else ""
        payload = self._read_json()
        if len(parts) == 5 and parts[4] == "weight":
            try:
                weight = float(payload.get("weight"))
            except (TypeError, ValueError):
                self._json({"error": "weight must be numeric"}, 400)
                return
            try:
                checkpoint = self.store.set_checkpoint_weight(checkpoint_id, weight)
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
        else:
            try:
                checkpoint = self.store.patch_checkpoint(checkpoint_id, payload)
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
        self._json(checkpoint if checkpoint else {"error": "not found"}, 200 if checkpoint else 404)

def run_server(host: str = "127.0.0.1", port: int = 8000, db_path: str = "artifacts/assessment.sqlite3") -> None:
    handler = ApiHandler
    handler.store = AssessmentStore(db_path)
    handler.orchestrator = AssessmentOrchestrator()
    server = ThreadingHTTPServer((host, port), handler)
    print(f"serving http://{host}:{port}")
    server.serve_forever()
