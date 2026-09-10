from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .checkpoints import ASSESSMENT_CHECKPOINTS
from .models import AssetRef, AssessmentReport, Checkpoint, Evidence, Finding
from .report_renderer import write_markdown_report
from .scoring import build_report


SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
  id TEXT PRIMARY KEY,
  tender_no INTEGER NOT NULL,
  name TEXT NOT NULL,
  rule_group TEXT NOT NULL,
  domain TEXT NOT NULL,
  weight REAL NOT NULL,
  dimensions_json TEXT NOT NULL,
  data_sources_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  applicability_json TEXT NOT NULL DEFAULT '{}',
  rule_enabled_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS assessment_tasks (
  id TEXT PRIMARY KEY,
  profile TEXT NOT NULL,
  request_json TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  connection_mode TEXT NOT NULL,
  manifest TEXT,
  kubeconfig TEXT,
  pve_ssh TEXT,
  control_plane_ip TEXT,
  ssh_key TEXT,
  ssh_user TEXT,
  labels_json TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assessment_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT NOT NULL,
  progress INTEGER NOT NULL,
  detail_json TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS raw_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  content_hash TEXT NOT NULL DEFAULT '',
  summary_json TEXT NOT NULL,
  warning_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  tool_id TEXT NOT NULL,
  checkpoint_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  score REAL NOT NULL,
  asset_json TEXT,
  evidence_json TEXT NOT NULL,
  remediation TEXT NOT NULL,
  fingerprint TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
  task_id TEXT PRIMARY KEY,
  schema_version TEXT NOT NULL,
  generated_at TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  checkpoint_scores_json TEXT NOT NULL,
  report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metric_weights (
  checkpoint_id TEXT PRIMARY KEY,
  weight REAL NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS source_descriptors (
  source_id TEXT PRIMARY KEY,
  source_type TEXT NOT NULL,
  display_name TEXT NOT NULL,
  connection_mode TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  schema_name TEXT NOT NULL,
  schema_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collection_runs (
  run_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  object_count INTEGER NOT NULL DEFAULT 0,
  byte_count INTEGER NOT NULL DEFAULT 0,
  warning_count INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  content_hash TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS collection_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  error_code TEXT,
  error_message TEXT
);
CREATE TABLE IF NOT EXISTS processing_runs (
  processing_run_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  source_run_ids_json TEXT NOT NULL,
  pipeline_version TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS processing_step_runs (
  step_id TEXT PRIMARY KEY,
  processing_run_id TEXT NOT NULL,
  step_type TEXT NOT NULL,
  step_order INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  input_count INTEGER NOT NULL DEFAULT 0,
  output_count INTEGER NOT NULL DEFAULT 0,
  drop_count INTEGER NOT NULL DEFAULT 0,
  warning_count INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  duration_ms REAL NOT NULL DEFAULT 0,
  summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS field_mapping_rules (
  mapping_id TEXT PRIMARY KEY,
  source_schema TEXT NOT NULL,
  target_schema TEXT NOT NULL,
  source_path TEXT NOT NULL,
  target_path TEXT NOT NULL,
  transform TEXT NOT NULL,
  required INTEGER NOT NULL DEFAULT 0,
  default_value_json TEXT
);
CREATE TABLE IF NOT EXISTS cleaning_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  field_path TEXT NOT NULL,
  action_type TEXT NOT NULL,
  before_value TEXT,
  after_value TEXT,
  reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS data_conflicts (
  conflict_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  field_path TEXT NOT NULL,
  candidate_values_json TEXT NOT NULL,
  selected_source TEXT,
  resolution_reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS data_quality_rules (
  rule_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  dimension TEXT NOT NULL,
  target_scope TEXT NOT NULL,
  threshold REAL NOT NULL,
  severity TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS data_quality_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  status TEXT NOT NULL,
  score REAL NOT NULL,
  total_count INTEGER NOT NULL,
  failed_count INTEGER NOT NULL,
  examples_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lineage_nodes (
  node_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  node_type TEXT NOT NULL,
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lineage_edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  source_node TEXT NOT NULL,
  target_node TEXT NOT NULL,
  relation TEXT NOT NULL,
  UNIQUE(task_id, source_node, target_node, relation)
);
CREATE TABLE IF NOT EXISTS normalized_assets (
  asset_key TEXT NOT NULL,
  task_id TEXT NOT NULL,
  asset_json TEXT NOT NULL,
  PRIMARY KEY(task_id, asset_key)
);
CREATE TABLE IF NOT EXISTS asset_edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  source_node TEXT NOT NULL,
  target_node TEXT NOT NULL,
  relation TEXT NOT NULL,
  UNIQUE(task_id, source_node, target_node, relation)
);
CREATE TABLE IF NOT EXISTS authentication_profiles (
  task_id TEXT PRIMARY KEY,
  profile_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  identity_key TEXT NOT NULL,
  profile_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_account_token_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  identity_key TEXT NOT NULL,
  profile_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificate_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  certificate_key TEXT NOT NULL,
  profile_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mtls_coverage_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  workload_key TEXT NOT NULL,
  result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS etcd_node_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  node_name TEXT NOT NULL,
  profile_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS apiserver_etcd_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  server_name TEXT NOT NULL,
  profile_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS encryption_resource_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  resource_key TEXT NOT NULL,
  rule_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kms_provider_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  provider_name TEXT NOT NULL,
  profile_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config_consistency_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  category TEXT NOT NULL,
  result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS task_comparisons (
  comparison_id TEXT PRIMARY KEY,
  baseline_task_id TEXT NOT NULL,
  current_task_id TEXT NOT NULL,
  comparison_json TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id);
CREATE INDEX IF NOT EXISTS idx_findings_filter ON findings(task_id, tool_id, checkpoint_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_raw_snapshots_task ON raw_snapshots(task_id);
CREATE INDEX IF NOT EXISTS idx_assessment_events_task ON assessment_events(task_id, id);
CREATE INDEX IF NOT EXISTS idx_processing_runs_task ON processing_runs(task_id);
CREATE INDEX IF NOT EXISTS idx_quality_results_task ON data_quality_results(task_id);
CREATE INDEX IF NOT EXISTS idx_lineage_nodes_task ON lineage_nodes(task_id);
CREATE INDEX IF NOT EXISTS idx_asset_nodes_task ON normalized_assets(task_id);
CREATE INDEX IF NOT EXISTS idx_task_comparison_tasks ON task_comparisons(baseline_task_id, current_task_id);
"""


class AssessmentStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.migrate_schema()
            self.seed_checkpoints()
            self.fill_checkpoint_metadata_defaults()
            self.fill_raw_snapshot_hashes()
            self.conn.commit()

    def migrate_schema(self) -> None:
        checkpoint_columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(checkpoints)").fetchall()}
        migrations = {
            "enabled": "ALTER TABLE checkpoints ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
            "applicability_json": "ALTER TABLE checkpoints ADD COLUMN applicability_json TEXT NOT NULL DEFAULT '{}'",
            "rule_enabled_json": "ALTER TABLE checkpoints ADD COLUMN rule_enabled_json TEXT NOT NULL DEFAULT '{}'",
        }
        for column, statement in migrations.items():
            if column not in checkpoint_columns:
                self.conn.execute(statement)
        raw_snapshot_columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(raw_snapshots)").fetchall()}
        if "content_hash" not in raw_snapshot_columns:
            self.conn.execute("ALTER TABLE raw_snapshots ADD COLUMN content_hash TEXT NOT NULL DEFAULT ''")

    def fill_checkpoint_metadata_defaults(self) -> None:
        for checkpoint in ASSESSMENT_CHECKPOINTS:
            self.conn.execute(
                """
                UPDATE checkpoints
                SET applicability_json = ?
                WHERE id = ? AND (applicability_json IS NULL OR applicability_json = '{}')
                """,
                (json.dumps({"scope": "all", "managed_cluster": True}, ensure_ascii=False), checkpoint.id),
            )
            self.conn.execute(
                """
                UPDATE checkpoints
                SET rule_enabled_json = ?
                WHERE id = ? AND (rule_enabled_json IS NULL OR rule_enabled_json = '{}')
                """,
                (json.dumps({checkpoint.rule_group: True}, ensure_ascii=False), checkpoint.id),
            )

    def fill_raw_snapshot_hashes(self) -> None:
        rows = self.conn.execute(
            "SELECT id, summary_json FROM raw_snapshots WHERE content_hash IS NULL OR content_hash = ''"
        ).fetchall()
        for row in rows:
            self.conn.execute(
                "UPDATE raw_snapshots SET content_hash = ? WHERE id = ?",
                (self._stable_hash_json(json.loads(row["summary_json"])), row["id"]),
            )

    def seed_checkpoints(self) -> None:
        with self.lock:
            for checkpoint in ASSESSMENT_CHECKPOINTS:
                self.conn.execute(
                    """
                    INSERT INTO checkpoints
                    (id, tender_no, name, rule_group, domain, weight, dimensions_json, data_sources_json, enabled, applicability_json, rule_enabled_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      tender_no = excluded.tender_no,
                      name = excluded.name,
                      rule_group = excluded.rule_group,
                      domain = excluded.domain,
                      weight = excluded.weight,
                      dimensions_json = excluded.dimensions_json,
                      data_sources_json = excluded.data_sources_json
                    """,
                    (
                        checkpoint.id,
                        checkpoint.tender_no,
                        checkpoint.name,
                        checkpoint.rule_group,
                        checkpoint.domain,
                        checkpoint.weight,
                        json.dumps(checkpoint.dimensions, ensure_ascii=False),
                        json.dumps(checkpoint.data_sources, ensure_ascii=False),
                        1,
                        json.dumps({"scope": "all", "managed_cluster": True}, ensure_ascii=False),
                        json.dumps({checkpoint.rule_group: True}, ensure_ascii=False),
                    ),
                )
    @staticmethod
    def _jsonable(value: Any) -> Any:
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if hasattr(value, "__dataclass_fields__"):
            return asdict(value)
        return value

    def save_structured_payload(self, task_id: str, payload: dict[str, Any] | None) -> None:
        """Persist structured processing and module data without flattening snapshots."""
        payload = payload or {}
        with self.lock:
            for source in payload.get("sources", []) or []:
                item = self._jsonable(source)
                if isinstance(item, dict) and item.get("source_id"):
                    self.conn.execute(
                        """
                        INSERT OR REPLACE INTO source_descriptors
                        (source_id, source_type, display_name, connection_mode, capabilities_json, schema_name, schema_version)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(item["source_id"]), str(item.get("source_type", "unknown")),
                            str(item.get("name") or item.get("display_name") or item["source_id"]),
                            str(item.get("metadata", {}).get("mode", "unknown")),
                            json.dumps(item.get("metadata", {}).get("capabilities", []), ensure_ascii=False),
                            str(item.get("source_type", "unknown")),
                            str(item.get("version") or "unknown"),
                        ),
                    )
            for collection in payload.get("collection_runs", []) or []:
                item = self._jsonable(collection)
                if isinstance(item, dict) and item.get("run_id"):
                    source = item.get("source") or {}
                    self.conn.execute(
                        """
                        INSERT OR REPLACE INTO collection_runs
                        (run_id, task_id, source_id, started_at, finished_at, status, object_count, byte_count, warning_count, error_count, content_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(item["run_id"]), task_id, str(source.get("source_id", "unknown")),
                            str(item.get("started_at", "")), item.get("completed_at"),
                            str(item.get("status", "SUCCESS")), int(item.get("output_count", item.get("input_count", 0))),
                            int(item.get("byte_count", 0)), len(item.get("warnings", []) or []),
                            len(item.get("errors", []) or []), str(item.get("content_hash", "")),
                        ),
                    )
            processing = self._jsonable(payload.get("processing_run"))
            processing_id = str(processing.get("run_id") or processing.get("processing_run_id")) if isinstance(processing, dict) and (processing.get("run_id") or processing.get("processing_run_id")) else ""
            if isinstance(processing, dict) and processing_id:
                self.conn.execute("DELETE FROM processing_step_runs WHERE processing_run_id = ?", (processing_id,))
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO processing_runs
                    (processing_run_id, task_id, source_run_ids_json, pipeline_version, started_at, finished_at, status, summary_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        processing_id, task_id,
                        json.dumps([item.get("run_id") for item in payload.get("collection_runs", []) if isinstance(item, dict)], ensure_ascii=False),
                        "structured/v1", str(processing.get("started_at", "")), processing.get("completed_at"),
                        str(processing.get("status", "SUCCESS")), json.dumps(processing.get("summary", {}), ensure_ascii=False, default=str),
                    ),
                )
                for order, step in enumerate(payload.get("processing_steps", []) or processing.get("steps", []) or [], start=1):
                    item = self._jsonable(step)
                    if not isinstance(item, dict) or not item.get("step_id"):
                        continue
                    self.conn.execute(
                        """
                        INSERT OR REPLACE INTO processing_step_runs
                        (step_id, processing_run_id, step_type, step_order, started_at, finished_at, status,
                         input_count, output_count, drop_count, warning_count, error_count, duration_ms, summary_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(item["step_id"]), processing_id, str(item.get("step_name", item.get("step_type", "unknown"))),
                            int(item.get("step_order", order)), str(item.get("started_at", "")),
                            item.get("completed_at", item.get("finished_at")), str(item.get("status", "SUCCESS")),
                            int(item.get("input_count", 0)), int(item.get("output_count", 0)),
                            int(item.get("drop_count", 0)), len(item.get("warnings", []) or []),
                            len(item.get("errors", []) or []), float(item.get("duration_ms", 0)),
                            json.dumps(item.get("summary", {}), ensure_ascii=False, default=str),
                        ),
                    )

            self.conn.execute("DELETE FROM data_quality_results WHERE task_id = ?", (task_id,))
            for result in payload.get("data_quality_results", []) or []:
                item = self._jsonable(result)
                if isinstance(item, dict) and item.get("rule_id"):
                    self.conn.execute(
                        """
                        INSERT INTO data_quality_results
                        (task_id, rule_id, status, score, total_count, failed_count, examples_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            task_id, str(item["rule_id"]), str(item.get("status", "UNKNOWN")),
                            float(item.get("score") if item.get("score") is not None else 0),
                            int(item.get("total_count", 0)),
                            int(item.get("failed_count", 0)),
                            json.dumps(item.get("examples", []), ensure_ascii=False, default=str),
                        ),
                    )

            for rule in payload.get("field_mapping_rules", []) or []:
                item = self._jsonable(rule)
                if isinstance(item, dict) and item.get("mapping_id"):
                    self.conn.execute(
                        """
                        INSERT OR REPLACE INTO field_mapping_rules
                        (mapping_id, source_schema, target_schema, source_path, target_path, transform, required, default_value_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(item["mapping_id"]), str(item.get("source_schema", "")), str(item.get("target_schema", "")),
                            str(item.get("source_path", "")), str(item.get("target_path", "")), str(item.get("transform", "identity")),
                            int(bool(item.get("required"))), json.dumps(item.get("default_value"), ensure_ascii=False, default=str),
                        ),
                    )
            self.conn.execute("DELETE FROM cleaning_actions WHERE task_id = ?", (task_id,))
            for action in payload.get("cleaning_actions", []) or []:
                item = self._jsonable(action)
                if isinstance(item, dict):
                    self.conn.execute(
                        """
                        INSERT INTO cleaning_actions
                        (task_id, source_id, object_key, field_path, action_type, before_value, after_value, reason)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            task_id, str(item.get("source_id", "")), str(item.get("object_key", "")),
                            str(item.get("field_path", "")), str(item.get("action_type", item.get("action", ""))),
                            json.dumps(item.get("before_value"), ensure_ascii=False, default=str),
                            json.dumps(item.get("after_value"), ensure_ascii=False, default=str),
                            str(item.get("reason", "")),
                        ),
                    )
            self.conn.execute("DELETE FROM data_conflicts WHERE task_id = ?", (task_id,))
            for conflict in payload.get("data_conflicts", []) or []:
                item = self._jsonable(conflict)
                if isinstance(item, dict) and item.get("conflict_id"):
                    self.conn.execute(
                        """
                        INSERT OR REPLACE INTO data_conflicts
                        (conflict_id, task_id, object_key, field_path, candidate_values_json, selected_source, resolution_reason)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(item["conflict_id"]), task_id, str(item.get("object_key", "")), str(item.get("field_path", "")),
                            json.dumps(item.get("candidate_values", item.get("candidates", [])), ensure_ascii=False, default=str),
                            item.get("selected_source"), str(item.get("resolution_reason", "")),
                        ),
                    )

            lineage = payload.get("lineage") or {}
            self.conn.execute("DELETE FROM lineage_nodes WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM lineage_edges WHERE task_id = ?", (task_id,))
            for node in lineage.get("nodes", []) or []:
                item = self._jsonable(node)
                if isinstance(item, dict) and item.get("node_id"):
                    self.conn.execute(
                        "INSERT OR REPLACE INTO lineage_nodes(node_id, task_id, node_type, name) VALUES (?, ?, ?, ?)",
                        (str(item["node_id"]), task_id, str(item.get("node_type", "unknown")), str(item.get("name", item["node_id"]))),
                    )
            for edge in lineage.get("edges", []) or []:
                item = self._jsonable(edge)
                source = item.get("source_node", item.get("source")) if isinstance(item, dict) else None
                target = item.get("target_node", item.get("target")) if isinstance(item, dict) else None
                if source and target:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO lineage_edges(task_id, source_node, target_node, relation) VALUES (?, ?, ?, ?)",
                        (task_id, str(source), str(target), str(item.get("relation", "related"))),
                    )

            graph = payload.get("asset_graph") or {}
            self.conn.execute("DELETE FROM normalized_assets WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM asset_edges WHERE task_id = ?", (task_id,))
            for node in graph.get("nodes", []) or []:
                item = self._jsonable(node)
                key = item.get("key", item.get("id")) if isinstance(item, dict) else None
                if key:
                    self.conn.execute(
                        "INSERT OR REPLACE INTO normalized_assets(asset_key, task_id, asset_json) VALUES (?, ?, ?)",
                        (str(key), task_id, json.dumps(item, ensure_ascii=False, default=str)),
                    )
            for edge in graph.get("edges", []) or []:
                item = self._jsonable(edge)
                source = item.get("source") if isinstance(item, dict) else None
                target = item.get("target") if isinstance(item, dict) else None
                if source and target:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO asset_edges(task_id, source_node, target_node, relation) VALUES (?, ?, ?, ?)",
                        (task_id, str(source), str(target), str(item.get("relation", "related"))),
                    )
            self._save_profile(task_id, "authentication", payload.get("authentication"))
            self._save_profile(task_id, "identities", payload.get("identities"))
            self._save_profile(task_id, "service_account_tokens", payload.get("service_account_tokens"))
            self._save_profile(task_id, "etcd", payload.get("etcd"))
            self._save_profile(task_id, "apiserver_etcd", payload.get("apiserver_etcd"))
            self._save_profile(task_id, "encryption", payload.get("encryption"))
            self._save_profile(task_id, "mtls", payload.get("mtls"))
            self.conn.execute("DELETE FROM certificate_profiles WHERE task_id = ?", (task_id,))
            for index, certificate in enumerate(payload.get("certificates", []) or []):
                item = self._jsonable(certificate)
                if isinstance(item, dict):
                    key = str(item.get("source") or item.get("serial_number") or f"certificate-{index}")
                    self.conn.execute(
                        "INSERT INTO certificate_profiles(task_id, certificate_key, profile_json) VALUES (?, ?, ?)",
                        (task_id, key, json.dumps(item, ensure_ascii=False, default=str)),
                    )
            self.conn.execute("DELETE FROM config_consistency_results WHERE task_id = ?", (task_id,))
            consistency = self._jsonable(payload.get("config_consistency"))
            if isinstance(consistency, dict):
                self.conn.execute(
                    "INSERT INTO config_consistency_results(task_id, category, result_json) VALUES (?, ?, ?)",
                    (task_id, "etcd", json.dumps(consistency, ensure_ascii=False, default=str)),
                )
            self.conn.commit()

    def _save_profile(self, task_id: str, category: str, value: Any) -> None:
        if value is None:
            return
        payload = self._jsonable(value)
        if category == "authentication":
            self.conn.execute(
                "INSERT OR REPLACE INTO authentication_profiles(task_id, profile_json) VALUES (?, ?)",
                (task_id, json.dumps(payload, ensure_ascii=False, default=str)),
            )
            return
        config = {
            "identities": ("identity_profiles", "identity_key"),
            "service_account_tokens": ("service_account_token_profiles", "identity_key"),
            "etcd": ("etcd_node_profiles", "node_name"),
            "apiserver_etcd": ("apiserver_etcd_profiles", "server_name"),
            "encryption": ("encryption_resource_rules", "resource_key"),
            "mtls": ("mtls_coverage_results", "workload_key"),
        }.get(category)
        if not config:
            return
        table, key_name = config
        self.conn.execute(f"DELETE FROM {table} WHERE task_id = ?", (task_id,))
        rows = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
        for index, item in enumerate(rows):
            if not isinstance(item, dict):
                continue
            key = str(item.get(key_name) or item.get("workload") or item.get("name") or f"{category}-{index}")
            if category == "identities":
                self.conn.execute("INSERT INTO identity_profiles(task_id, identity_key, profile_json) VALUES (?, ?, ?)", (task_id, key, json.dumps(item, ensure_ascii=False, default=str)))
            elif category == "service_account_tokens":
                self.conn.execute("INSERT INTO service_account_token_profiles(task_id, identity_key, profile_json) VALUES (?, ?, ?)", (task_id, key, json.dumps(item, ensure_ascii=False, default=str)))
            elif category == "etcd":
                self.conn.execute("INSERT INTO etcd_node_profiles(task_id, node_name, profile_json) VALUES (?, ?, ?)", (task_id, key, json.dumps(item, ensure_ascii=False, default=str)))
            elif category == "apiserver_etcd":
                self.conn.execute("INSERT INTO apiserver_etcd_profiles(task_id, server_name, profile_json) VALUES (?, ?, ?)", (task_id, key, json.dumps(item, ensure_ascii=False, default=str)))
            elif category == "encryption":
                rules = item.get("rules", []) if isinstance(item.get("rules"), list) else [item]
                for rule_index, rule in enumerate(rules):
                    resource_key = str((rule.get("resources") or [f"{key}-{rule_index}"])[0]) if isinstance(rule, dict) else f"{key}-{rule_index}"
                    self.conn.execute("INSERT INTO encryption_resource_rules(task_id, resource_key, rule_json) VALUES (?, ?, ?)", (task_id, resource_key, json.dumps(self._jsonable(rule), ensure_ascii=False, default=str)))
            elif category == "mtls":
                self.conn.execute("INSERT INTO mtls_coverage_results(task_id, workload_key, result_json) VALUES (?, ?, ?)", (task_id, key, json.dumps(item, ensure_ascii=False, default=str)))
    def list_processing_runs(self, task_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM processing_runs"
        params: tuple[Any, ...] = ()
        if task_id:
            query += " WHERE task_id = ?"
            params = (task_id,)
        query += " ORDER BY started_at DESC"
        with self.lock:
            rows = self.conn.execute(query, params).fetchall()
            return [
                dict(row)
                | {"source_run_ids": json.loads(row["source_run_ids_json"]), "summary": json.loads(row["summary_json"])}
                for row in rows
            ]

    def get_processing_run(self, processing_run_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute("SELECT * FROM processing_runs WHERE processing_run_id = ?", (processing_run_id,)).fetchone()
            return (
                dict(row)
                | {"source_run_ids": json.loads(row["source_run_ids_json"]), "summary": json.loads(row["summary_json"])}
                if row else None
            )

    def list_processing_steps(self, processing_run_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM processing_step_runs WHERE processing_run_id = ? ORDER BY step_order", (processing_run_id,)).fetchall()
            return [dict(row) | {"step_name": row["step_type"], "summary": json.loads(row["summary_json"])} for row in rows]

    def get_structured_payload(self, task_id: str) -> dict[str, Any]:
        with self.lock:
            runs = self.list_processing_runs(task_id)
            processing = runs[0] if runs else None
            steps = self.list_processing_steps(processing["processing_run_id"]) if processing else []
            quality_rows = self.conn.execute("SELECT * FROM data_quality_results WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            nodes = self.conn.execute("SELECT node_id, node_type, name FROM lineage_nodes WHERE task_id = ?", (task_id,)).fetchall()
            edges = self.conn.execute("SELECT source_node, target_node, relation FROM lineage_edges WHERE task_id = ?", (task_id,)).fetchall()
            assets = self.conn.execute("SELECT asset_json FROM normalized_assets WHERE task_id = ?", (task_id,)).fetchall()
            asset_edges = self.conn.execute("SELECT source_node AS source, target_node AS target, relation FROM asset_edges WHERE task_id = ?", (task_id,)).fetchall()
            auth = self.conn.execute("SELECT profile_json FROM authentication_profiles WHERE task_id = ?", (task_id,)).fetchone()
            identities = self.conn.execute("SELECT profile_json FROM identity_profiles WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            tokens = self.conn.execute("SELECT profile_json FROM service_account_token_profiles WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            etcd = self.conn.execute("SELECT profile_json FROM etcd_node_profiles WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            apiserver_etcd = self.conn.execute("SELECT profile_json FROM apiserver_etcd_profiles WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            encryption = self.conn.execute("SELECT rule_json FROM encryption_resource_rules WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            mtls = self.conn.execute("SELECT result_json FROM mtls_coverage_results WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            certificates = self.conn.execute("SELECT profile_json FROM certificate_profiles WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            consistency = self.conn.execute("SELECT result_json FROM config_consistency_results WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            cleaning = self.conn.execute("SELECT * FROM cleaning_actions WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            conflicts = self.conn.execute("SELECT * FROM data_conflicts WHERE task_id = ? ORDER BY conflict_id", (task_id,)).fetchall()
            sources = self.conn.execute(
                "SELECT source_id, source_type, display_name AS name, schema_version AS version FROM source_descriptors ORDER BY source_id"
            ).fetchall()
            collections = self.conn.execute(
                "SELECT run_id, task_id, source_id, started_at, finished_at AS completed_at, status, object_count, byte_count, warning_count, error_count, content_hash FROM collection_runs WHERE task_id = ? ORDER BY started_at",
                (task_id,),
            ).fetchall()
            return {
                "sources": [dict(row) for row in sources],
                "collection_runs": [dict(row) for row in collections],
                "processing_run": processing,
                "processing_steps": steps,
                "data_quality_results": [dict(row) | {"examples": json.loads(row["examples_json"])} for row in quality_rows],
                "lineage": {"nodes": [dict(row) for row in nodes], "edges": [dict(row) for row in edges]},
                "asset_graph": {"nodes": [json.loads(row["asset_json"]) for row in assets], "edges": [dict(row) for row in asset_edges]},
                "authentication": json.loads(auth["profile_json"]) if auth else None,
                "identities": [json.loads(row["profile_json"]) for row in identities],
                "service_account_tokens": [json.loads(row["profile_json"]) for row in tokens],
                "etcd": [json.loads(row["profile_json"]) for row in etcd],
                "apiserver_etcd": [json.loads(row["profile_json"]) for row in apiserver_etcd],
                "encryption": [json.loads(row["rule_json"]) for row in encryption],
                "mtls": [json.loads(row["result_json"]) for row in mtls],
                "certificates": [json.loads(row["profile_json"]) for row in certificates],
                "config_consistency": json.loads(consistency[0]["result_json"]) if consistency else None,
                "cleaning_actions": [dict(row) | {"before_value": json.loads(row["before_value"]), "after_value": json.loads(row["after_value"])} for row in cleaning],
                "data_conflicts": [dict(row) | {"candidate_values": json.loads(row["candidate_values_json"])} for row in conflicts],
            }
    def list_source_descriptors(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM source_descriptors ORDER BY source_id").fetchall()
            return [
                dict(row)
                | {
                    "capabilities": json.loads(row["capabilities_json"]),
                }
                for row in rows
            ]

    def task_comparison_payload(self, task_id: str) -> dict[str, Any]:
        report = self.get_report(task_id) or {}
        return {
            "task_id": task_id,
            "findings": self.list_findings(task_id),
            "assets": self.get_structured_payload(task_id).get("asset_graph", {}).get("nodes", []),
            "checkpoint_scores": report.get("checkpoint_scores", []),
            "summary": report.get("summary", {}),
        }

    def create_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_id = str(payload.get("id") or f"target-{uuid.uuid4().hex[:12]}")
        name = str(payload.get("name") or target_id)
        target_type = str(payload.get("type") or "kubernetes")
        connection_mode = str(payload.get("connection_mode") or ("manifest" if payload.get("manifest") else "pve_ssh" if payload.get("pve_ssh") else "kubeconfig"))
        labels = payload.get("labels") or {}
        with self.lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO targets
                (id, name, type, connection_mode, manifest, kubeconfig, pve_ssh, control_plane_ip, ssh_key, ssh_user, labels_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_id,
                    name,
                    target_type,
                    connection_mode,
                    payload.get("manifest"),
                    payload.get("kubeconfig"),
                    payload.get("pve_ssh"),
                    payload.get("control_plane_ip", "10.20.0.11"),
                    payload.get("ssh_key", "/root/.ssh/agent_lab"),
                    payload.get("ssh_user", "agent"),
                    json.dumps(labels, ensure_ascii=False, default=str),
                ),
            )
            self.conn.commit()
            return self.get_target(target_id) or {}

    def list_targets(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, name, type, connection_mode, manifest, kubeconfig, pve_ssh, control_plane_ip, ssh_key, ssh_user, labels_json, created_at
                FROM targets
                ORDER BY created_at DESC, id
                """
            ).fetchall()
            return [self._decode_target(row) for row in rows]

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, name, type, connection_mode, manifest, kubeconfig, pve_ssh, control_plane_ip, ssh_key, ssh_user, labels_json, created_at
                FROM targets
                WHERE id = ?
                """,
                (target_id,),
            ).fetchone()
            return self._decode_target(row) if row else None

    def delete_target(self, target_id: str) -> bool:
        with self.lock:
            cur = self.conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            self.conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def _decode_target(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["labels"] = json.loads(item.pop("labels_json"))
        return item

    def save_task(self, task_id: str, profile: str, request: dict[str, Any], status: str = "success") -> None:
        with self.lock:
            completed_at = "CURRENT_TIMESTAMP" if status in {"success", "failed", "canceled"} else "NULL"
            self.conn.execute(
                f"""
                INSERT OR REPLACE INTO assessment_tasks(id, profile, request_json, status, completed_at)
                VALUES (?, ?, ?, ?, {completed_at})
                """,
                (task_id, profile, json.dumps(request, ensure_ascii=False, default=str), status),
            )

    def append_task_event(self, task_id: str, stage: str, status: str, message: str, progress: int, detail: dict[str, Any] | None = None) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO assessment_events(task_id, stage, status, message, progress, detail_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (task_id, stage, status, message, progress, json.dumps(detail or {}, ensure_ascii=False, default=str)),
            )

    def replace_task_events(self, task_id: str, events: list[dict[str, Any]]) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM assessment_events WHERE task_id = ?", (task_id,))
            for event in events:
                self.append_task_event(
                    task_id,
                    event["stage"],
                    event.get("status", "done"),
                    event.get("message", event["stage"]),
                    int(event.get("progress", 0)),
                    event.get("detail", {}),
                )

    def save_raw_snapshot(self, task_id: str, source: str, summary: dict[str, Any], warning_count: int) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO raw_snapshots(task_id, source, kind, schema_version, content_hash, summary_json, warning_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    source,
                    summary.get("kind", "adapter_summary"),
                    summary.get("schema_version", "unknown"),
                    self._stable_hash_json(summary),
                    json.dumps(summary, ensure_ascii=False, default=str),
                    warning_count,
                ),
            )

    def save_findings(self, findings: list[Finding]) -> None:
        with self.lock:
            for finding in findings:
                storage_id = f"{finding.task_id}:{finding.id}"
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO findings
                    (id, task_id, tool_id, checkpoint_id, rule_id, title, status, severity, score, asset_json, evidence_json, remediation, fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        storage_id,
                        finding.task_id,
                        finding.tool_id,
                        finding.checkpoint_id,
                        finding.rule_id,
                        finding.title,
                        finding.status,
                        finding.severity,
                        finding.score,
                        json.dumps(asdict(finding.asset), ensure_ascii=False, default=str) if finding.asset else None,
                        json.dumps([asdict(evidence) for evidence in finding.evidence], ensure_ascii=False, default=str),
                        finding.remediation,
                        finding.fingerprint,
                    ),
                )

    def save_report(self, report: AssessmentReport) -> AssessmentReport:
        payload = report.to_dict()
        with self.lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO reports
                (task_id, schema_version, generated_at, summary_json, checkpoint_scores_json, report_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    report.task_id,
                    report.schema_version,
                    report.generated_at,
                    json.dumps(report.summary, ensure_ascii=False, default=str),
                    json.dumps(payload["checkpoint_scores"], ensure_ascii=False, default=str),
                    json.dumps(payload, ensure_ascii=False, default=str),
                ),
            )
            return report

    def clear_task_outputs(self, task_id: str) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM raw_snapshots WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM findings WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM reports WHERE task_id = ?", (task_id,))
            self.conn.execute(
                "DELETE FROM processing_step_runs WHERE processing_run_id IN (SELECT processing_run_id FROM processing_runs WHERE task_id = ?)",
                (task_id,),
            )
            self.conn.execute("DELETE FROM processing_runs WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM data_quality_results WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM lineage_nodes WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM lineage_edges WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM normalized_assets WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM asset_edges WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM authentication_profiles WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM identity_profiles WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM service_account_token_profiles WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM certificate_profiles WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM etcd_node_profiles WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM apiserver_etcd_profiles WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM encryption_resource_rules WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM kms_provider_profiles WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM config_consistency_results WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM cleaning_actions WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM data_conflicts WHERE task_id = ?", (task_id,))
            self.conn.execute("DELETE FROM mtls_coverage_results WHERE task_id = ?", (task_id,))

    def save_result(self, result: Any) -> AssessmentReport:
        with self.lock:
            self.clear_task_outputs(result.request.task_id)
            self.save_task(result.request.task_id, result.request.profile, asdict(result.request), "success")
            for adapter_result in result.adapter_results:
                self.save_raw_snapshot(result.request.task_id, adapter_result.tool_id, adapter_result.raw_summary, len(adapter_result.warnings))
            self.save_findings(result.findings)
            report = self.build_dynamic_report(result.request.task_id, result.findings, result.report.summary)
            self.save_report(report)
            self.save_structured_payload(result.request.task_id, result.structured)
            self.replace_task_events(result.request.task_id, completed_task_events(result))
            self.conn.commit()
            return report

    def _enabled_checkpoint_items(self) -> list[dict[str, Any]]:
        return [item for item in self.list_checkpoints() if item.get("enabled", True)]

    def scoring_checkpoints(self) -> list[Checkpoint]:
        return [
            Checkpoint(
                id=item["id"],
                tender_no=int(item["tender_no"]),
                name=item["name"],
                rule_group=item["rule_group"],
                domain=item["domain"],
                weight=float(item["weight"]),
                dimensions=item["dimensions"],
                data_sources=item["data_sources"],
            )
            for item in self._enabled_checkpoint_items()
        ]

    def build_dynamic_report(self, task_id: str, findings: list[Finding], base_summary: dict[str, Any] | None = None) -> AssessmentReport:
        checkpoint_items = self._enabled_checkpoint_items()
        filtered_findings, filter_summary = self._filter_findings_for_checkpoints(findings, checkpoint_items)
        report = build_report(task_id, filtered_findings, self.scoring_checkpoints())
        for key in ["data_quality", "tool_count", "tools", "tool_summary", "integration_pipeline"]:
            if base_summary and key in base_summary:
                report.summary[key] = base_summary[key]
        report.summary["dynamic_filter"] = filter_summary
        return report

    def _filter_findings_for_checkpoints(self, findings: list[Finding], checkpoint_items: list[dict[str, Any]]) -> tuple[list[Finding], dict[str, Any]]:
        checkpoint_by_id = {item["id"]: item for item in checkpoint_items}
        excluded = {"disabled_checkpoint": 0, "disabled_rule": 0, "not_applicable": 0}
        filtered: list[Finding] = []
        for finding in findings:
            checkpoint = checkpoint_by_id.get(finding.checkpoint_id)
            if not checkpoint:
                excluded["disabled_checkpoint"] += 1
                continue
            if not self._rule_is_enabled(finding, checkpoint):
                excluded["disabled_rule"] += 1
                continue
            if not self._finding_is_applicable(finding, checkpoint.get("applicability") or {}):
                excluded["not_applicable"] += 1
                continue
            filtered.append(finding)
        return filtered, {
            "raw_finding_total": len(findings),
            "included_finding_total": len(filtered),
            "excluded_finding_total": len(findings) - len(filtered),
            "excluded_by_reason": excluded,
        }

    @staticmethod
    def _rule_is_enabled(finding: Finding, checkpoint: dict[str, Any]) -> bool:
        rule_enabled = checkpoint.get("rule_enabled") or {}
        if not isinstance(rule_enabled, dict):
            return True
        rule_id = finding.rule_id
        if rule_id in rule_enabled:
            return bool(rule_enabled[rule_id])
        group = str(checkpoint.get("rule_group") or "")
        if group and group in rule_enabled:
            return bool(rule_enabled[group])
        for key, enabled in rule_enabled.items():
            key_str = str(key)
            if key_str and rule_id.startswith(f"{key_str}-"):
                return bool(enabled)
        return True

    @staticmethod
    def _finding_is_applicable(finding: Finding, applicability: dict[str, Any]) -> bool:
        scope = str(applicability.get("scope", "all")).lower()
        if scope in {"disabled", "none", "not_applicable", "not-applicable", "n/a"}:
            return False

        asset = finding.asset
        include_cluster_scoped = bool(applicability.get("include_cluster_scoped", True))
        if not asset and not include_cluster_scoped:
            return False
        if asset and asset.namespace is None and not include_cluster_scoped:
            return False

        namespaces = applicability.get("namespaces")
        if namespaces:
            namespace_set = {str(item) for item in namespaces}
            if asset and asset.namespace is not None and asset.namespace not in namespace_set:
                return False

        kinds = applicability.get("kinds")
        if kinds:
            kind_set = {str(item).lower() for item in kinds}
            if not asset or asset.kind.lower() not in kind_set:
                return False

        tools = applicability.get("tools")
        if tools and finding.tool_id not in {str(item) for item in tools}:
            return False

        statuses = applicability.get("statuses")
        if statuses and finding.status not in {str(item) for item in statuses}:
            return False

        severities = applicability.get("severities")
        if severities and finding.severity not in {str(item) for item in severities}:
            return False

        return True

    def list_checkpoints(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT c.*, mw.weight AS override_weight
                FROM checkpoints c
                LEFT JOIN metric_weights mw ON mw.checkpoint_id = c.id
                ORDER BY c.tender_no, c.id
                """
            ).fetchall()
            checkpoints = []
            for row in rows:
                item = dict(row)
                override_weight = item.pop("override_weight")
                item["base_weight"] = item["weight"]
                item["weight"] = override_weight if override_weight is not None else item["weight"]
                item["dimensions"] = json.loads(row["dimensions_json"])
                item["data_sources"] = json.loads(row["data_sources_json"])
                item["enabled"] = bool(row["enabled"])
                item["applicability"] = json.loads(row["applicability_json"] or "{}")
                item["rule_enabled"] = json.loads(row["rule_enabled_json"] or "{}")
                checkpoints.append(item)
            return checkpoints

    def upsert_checkpoint(self, payload: dict[str, Any]) -> dict[str, Any]:
        required = {"id", "tender_no", "name", "rule_group", "domain"}
        missing = sorted(required - payload.keys())
        if missing:
            raise ValueError(f"missing checkpoint fields: {', '.join(missing)}")
        weight = float(payload.get("weight", 1.0))
        if weight < 0:
            raise ValueError("checkpoint weight must be non-negative")
        with self.lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO checkpoints
                (id, tender_no, name, rule_group, domain, weight, dimensions_json, data_sources_json, enabled, applicability_json, rule_enabled_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["id"],
                    int(payload["tender_no"]),
                    payload["name"],
                    payload["rule_group"],
                    payload["domain"],
                    weight,
                    json.dumps(payload.get("dimensions", []), ensure_ascii=False),
                    json.dumps(payload.get("data_sources", []), ensure_ascii=False),
                    1 if payload.get("enabled", True) else 0,
                    json.dumps(payload.get("applicability", {}), ensure_ascii=False, default=str),
                    json.dumps(payload.get("rule_enabled", {}), ensure_ascii=False, default=str),
                ),
            )
            self.conn.commit()
            return self.get_checkpoint(payload["id"]) or {}

    def patch_checkpoint(self, checkpoint_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        current = self.get_checkpoint(checkpoint_id)
        if not current:
            return None
        updated = current | payload | {"id": checkpoint_id}
        return self.upsert_checkpoint(updated)

    def set_checkpoint_weight(self, checkpoint_id: str, weight: float) -> dict[str, Any] | None:
        if weight < 0:
            raise ValueError("checkpoint weight must be non-negative")
        if not self.get_checkpoint(checkpoint_id):
            return None
        with self.lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO metric_weights(checkpoint_id, weight, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (checkpoint_id, weight),
            )
            self.conn.commit()
            return self.get_checkpoint(checkpoint_id)

    def get_checkpoint(self, checkpoint_id: str) -> dict[str, Any] | None:
        with self.lock:
            rows = [item for item in self.list_checkpoints() if item["id"] == checkpoint_id]
            return rows[0] if rows else None

    def list_tasks(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, profile, request_json, status, created_at, completed_at
                FROM assessment_tasks
                ORDER BY completed_at DESC, created_at DESC
                """
            ).fetchall()
            return [
                dict(row) | {"request": json.loads(row["request_json"])}
                for row in rows
            ]

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, profile, request_json, status, created_at, completed_at
                FROM assessment_tasks
                WHERE id = ?
                """,
                (task_id,),
            ).fetchone()
            return dict(row) | {"request": json.loads(row["request_json"])} if row else None

    def list_task_events(self, task_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, task_id, stage, status, message, progress, detail_json, created_at
                FROM assessment_events
                WHERE task_id = ?
                ORDER BY id
                """,
                (task_id,),
            ).fetchall()
            return [dict(row) | {"detail": json.loads(row["detail_json"])} for row in rows]

    def cancel_task(self, task_id: str) -> dict[str, Any] | None:
        task = self.get_task(task_id)
        if not task:
            return None
        with self.lock:
            self.save_task(task_id, task["profile"], task["request"], "canceled")
            self.append_task_event(task_id, "cancel", "canceled", "任务已标记取消", 100)
            self.conn.commit()
            return self.get_task(task_id)

    def list_raw_snapshots(self, task_id: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            if task_id:
                rows = self.conn.execute(
                    """
                    SELECT id, task_id, source, kind, schema_version, content_hash, summary_json, warning_count
                    FROM raw_snapshots
                    WHERE task_id = ?
                    ORDER BY id
                    """,
                    (task_id,),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    """
                    SELECT id, task_id, source, kind, schema_version, content_hash, summary_json, warning_count
                    FROM raw_snapshots
                    ORDER BY task_id, id
                    """
                ).fetchall()
            return [dict(row) | {"summary": json.loads(row["summary_json"])} for row in rows]

    def get_rbac_matrix(self, task_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT summary_json
                FROM raw_snapshots
                WHERE task_id = ? AND source = 'cloud_native'
                ORDER BY id DESC
                LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if not row:
                return None
            summary = json.loads(row["summary_json"])
            return summary.get("rbac_matrix")

    def query_rbac_matrix(
        self,
        task_id: str,
        *,
        subject: str | None = None,
        resource: str | None = None,
        verb: str | None = None,
        scope: str | None = None,
        role: str | None = None,
        binding: str | None = None,
        dangerous_only: bool = False,
        limit: int | None = None,
    ) -> dict[str, Any] | None:
        matrix = self.get_rbac_matrix(task_id)
        if not matrix:
            return None
        rows = matrix.get("dangerous_rows") if dangerous_only else matrix.get("rows")
        rows = list(rows or [])

        def contains(haystack: Any, needle: str | None) -> bool:
            if not needle:
                return True
            return needle.lower() in str(haystack or "").lower()

        def contains_any(items: Any, needle: str | None) -> bool:
            if not needle:
                return True
            lowered = needle.lower()
            return any(lowered in str(item).lower() for item in (items or []))

        filtered = [
            row
            for row in rows
            if contains(row.get("subject"), subject)
            and contains_any(row.get("resources"), resource)
            and contains_any(row.get("verbs"), verb)
            and contains(row.get("scope"), scope)
            and contains(f"{row.get('role_kind')}/{row.get('role_name')}", role)
            and contains(f"{row.get('binding_kind')}/{row.get('binding_namespace') or '_cluster'}/{row.get('binding_name')}", binding)
        ]
        if limit is not None and limit >= 0:
            filtered = filtered[:limit]
        return {
            "summary": matrix.get("summary", {}),
            "filters": {
                "subject": subject or "",
                "resource": resource or "",
                "verb": verb or "",
                "scope": scope or "",
                "role": role or "",
                "binding": binding or "",
                "dangerous_only": dangerous_only,
                "limit": limit,
            },
            "row_count": len(filtered),
            "available_row_count": len(rows),
            "rows": filtered,
            "dangerous_rows": list(matrix.get("dangerous_rows") or []),
            "required_resource_coverage": matrix.get("required_resource_coverage", {}),
        }

    def get_report(self, task_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute("SELECT report_json FROM reports WHERE task_id = ?", (task_id,)).fetchone()
            return json.loads(row["report_json"]) if row else None

    def recalculate_report_weights(self, task_id: str) -> dict[str, Any] | None:
        with self.lock:
            report = self.get_report(task_id)
            if not report:
                return None
            findings = [self._finding_from_dict(item) for item in self.list_findings(task_id)]
            rebuilt = self.build_dynamic_report(task_id, findings, report.get("summary", {}))
            self.save_report(rebuilt)
            self.conn.commit()
            return self.get_report(task_id)

    @staticmethod
    def _stable_hash_json(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _finding_from_dict(item: dict[str, Any]) -> Finding:
        asset_payload = item.get("asset")
        asset = AssetRef(**asset_payload) if isinstance(asset_payload, dict) else None
        evidence_items: list[Evidence] = []
        for evidence_payload in item.get("evidence", []) or []:
            object_ref_payload = evidence_payload.get("object_ref")
            object_ref = AssetRef(**object_ref_payload) if isinstance(object_ref_payload, dict) else None
            evidence_items.append(
                Evidence(
                    summary=evidence_payload.get("summary", ""),
                    object_ref=object_ref,
                    json_path=evidence_payload.get("json_path"),
                    observed=evidence_payload.get("observed"),
                    expected=evidence_payload.get("expected"),
                    raw_snippet=evidence_payload.get("raw_snippet"),
                )
            )
        return Finding(
            id=item["id"].split(":", 1)[-1],
            task_id=item["task_id"],
            tool_id=item["tool_id"],
            checkpoint_id=item["checkpoint_id"],
            rule_id=item["rule_id"],
            title=item["title"],
            status=item["status"],
            severity=item["severity"],
            score=float(item["score"]),
            asset=asset,
            evidence=evidence_items,
            remediation=item["remediation"],
            fingerprint=item["fingerprint"],
        )

    def list_findings(
        self,
        task_id: str | None = None,
        tool_id: str | None = None,
        checkpoint_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        namespace: str | None = None,
        kind: str | None = None,
        keyword: str | None = None,
    ) -> list[dict[str, Any]]:
        with self.lock:
            clauses: list[str] = []
            params: list[Any] = []
            if task_id:
                clauses.append("task_id = ?")
                params.append(task_id)
            if tool_id:
                clauses.append("tool_id = ?")
                params.append(tool_id)
            if checkpoint_id:
                clauses.append("checkpoint_id = ?")
                params.append(checkpoint_id)
            if severity:
                clauses.append("severity = ?")
                params.append(severity)
            if status:
                clauses.append("status = ?")
                params.append(status)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = self.conn.execute(
                f"SELECT * FROM findings {where} ORDER BY severity, status, checkpoint_id, rule_id",
                params,
            ).fetchall()
            findings = [self._decode_finding_row(row) for row in rows]
            return [
                finding
                for finding in findings
                if self._finding_matches(finding, namespace, kind, keyword)
            ]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            return self._decode_finding_row(row) if row else None

    @staticmethod
    def _decode_finding_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["asset"] = json.loads(item["asset_json"]) if item.get("asset_json") else None
        item["evidence"] = json.loads(item["evidence_json"])
        return item

    @staticmethod
    def _finding_matches(finding: dict[str, Any], namespace: str | None, kind: str | None, keyword: str | None) -> bool:
        asset = finding.get("asset") or {}
        if namespace and asset.get("namespace") != namespace:
            return False
        if kind and asset.get("kind") != kind:
            return False
        if keyword:
            needle = keyword.lower()
            haystack = " ".join(
                str(value)
                for value in [
                    finding.get("id"),
                    finding.get("checkpoint_id"),
                    finding.get("rule_id"),
                    finding.get("title"),
                    finding.get("remediation"),
                    asset.get("kind"),
                    asset.get("namespace"),
                    asset.get("name"),
                    finding.get("evidence"),
                ]
            ).lower()
            return needle in haystack
        return True


def completed_task_events(result: Any) -> list[dict[str, Any]]:
    adapter_ids = [adapter_result.tool_id for adapter_result in result.adapter_results]
    object_count = 0
    cloud_native = next((adapter_result for adapter_result in result.adapter_results if adapter_result.tool_id == "cloud_native"), None)
    if cloud_native:
        object_count = int(cloud_native.raw_summary.get("object_count", 0))
    return [
        {"stage": "collect", "status": "done", "message": "采集 Kubernetes/工具原始数据", "progress": 15, "detail": {"object_count": object_count, "adapters": adapter_ids}},
        {"stage": "cloud_native_rules", "status": "done", "message": "执行云原生 15 项检查规则", "progress": 35, "detail": {"tool": "cloud_native"}},
        {"stage": "cloud_api_stub", "status": "done", "message": "接入云上 API 安全 stub", "progress": 50, "detail": {"enabled": "cloud_api_stub" in adapter_ids}},
        {"stage": "smart_cloud_stub", "status": "done", "message": "接入智算云安全 stub", "progress": 60, "detail": {"enabled": "smart_cloud_stub" in adapter_ids}},
        {"stage": "normalize", "status": "done", "message": "统一 Finding、去重和数据质量评估", "progress": 75, "detail": {"data_quality": asdict(result.data_quality)}},
        {"stage": "score", "status": "done", "message": "按检查点权重计算得分和符合度", "progress": 90, "detail": {"overall_score": result.report.summary.get("overall_score"), "checkpoint_total": result.report.summary.get("checkpoint_total")}},
        {"stage": "report", "status": "done", "message": "生成 JSON/Markdown 报告和页面数据", "progress": 100, "detail": {"finding_total": result.report.summary.get("finding_total")}},
    ]


def export_markdown_report(report: AssessmentReport, path: str | Path) -> None:
    write_markdown_report(report, path)
