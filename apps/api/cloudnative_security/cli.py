from __future__ import annotations

import argparse
import json
from pathlib import Path

from .orchestrator import AssessmentOrchestrator
from .adapters import AssessmentRequest
from .structured_analysis import StructuredProcessingConfig
from .report_renderer import write_html_report
from .server import run_server
from .storage import AssessmentStore, export_markdown_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run cloud native security assessment.")
    parser.add_argument("--serve", action="store_true", help="Start the minimal JSON API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--manifest", help="Manifest file or directory to scan.")
    source.add_argument("--kubeconfig", help="Kubeconfig path for kubectl-based collection.")
    source.add_argument("--pve-ssh", help="SSH alias for the PVE host; collector runs kubectl on the control-plane VM through it.")
    parser.add_argument("--control-plane-ip", default="10.20.0.11")
    parser.add_argument("--ssh-key", default="/root/.ssh/agent_lab")
    parser.add_argument("--ssh-user", default="agent")
    parser.add_argument("--task-id", default="task-local")
    parser.add_argument("--profile", default="cloud_native_full", choices=["cloud_native_full", "all_tools_demo"])
    parser.add_argument("--extra-manifest", action="append", default=[], help="Additional manifest/log/jsonl path to merge into the collected evidence.")
    parser.add_argument("--output", help="Write JSON report to this path.")
    parser.add_argument("--markdown-output", help="Write Markdown report to this path.")
    parser.add_argument("--html-output", help="Write HTML report to this path.")
    parser.add_argument("--sqlite", help="Persist assessment results to SQLite.")
    parser.add_argument("--processing-config", help="JSON structured processing configuration path.")
    args = parser.parse_args()

    if args.serve:
        run_server(args.host, args.port, args.sqlite or "artifacts/assessment.sqlite3")
        return 0
    if not (args.manifest or args.kubeconfig or args.pve_ssh):
        parser.error("one of --manifest, --kubeconfig, or --pve-ssh is required unless --serve is used")
    processing: dict[str, object] | None = None
    if args.processing_config:
        config_path = Path(args.processing_config)
        try:
            loaded = json.loads(config_path.read_text())
            if not isinstance(loaded, dict):
                raise ValueError("processing configuration must be a JSON object")
            StructuredProcessingConfig.from_mapping(loaded)
            processing = loaded
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            parser.error(f"invalid --processing-config: {exc}")


    request = AssessmentRequest(
        task_id=args.task_id,
        profile=args.profile,
        manifest=args.manifest,
        kubeconfig=args.kubeconfig,
        pve_ssh=args.pve_ssh,
        control_plane_ip=args.control_plane_ip,
        ssh_key=args.ssh_key,
        ssh_user=args.ssh_user,
        extra_manifests=args.extra_manifest,
        options={"processing": processing} if processing is not None else {},
    )
    result = AssessmentOrchestrator().run(request)
    report_for_export = result.report
    if args.sqlite:
        with AssessmentStore(args.sqlite) as store:
            report_for_export = store.save_result(result)
    if args.markdown_output:
        export_markdown_report(report_for_export, args.markdown_output)
    if args.html_output:
        write_html_report(report_for_export, args.html_output)
    payload = result.to_dict()
    payload["report"] = report_for_export.to_dict()
    payload["summary"] = payload["report"]["summary"]
    text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
