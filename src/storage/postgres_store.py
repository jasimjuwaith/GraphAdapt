import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

import psycopg2
from psycopg2.extras import Json, RealDictCursor

logger = logging.getLogger("GraphADAPT.Postgres")


def _connect():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        dbname=os.getenv("POSTGRES_DB", "graph_adapt_db"),
        user=os.getenv("POSTGRES_USER", "adapt_user"),
        password=os.getenv("POSTGRES_PASSWORD", "adapt_password"),
        connect_timeout=5,
    )


def init_schema() -> None:
    ddl = """
    CREATE TABLE IF NOT EXISTS pipeline_runs (
        run_id BIGSERIAL PRIMARY KEY,
        rule_id TEXT NOT NULL,
        trigger_alert JSONB NOT NULL DEFAULT '{}'::jsonb,
        subgraph JSONB NOT NULL DEFAULT '{}'::jsonb,
        correlator_lineage JSONB NOT NULL DEFAULT '{}'::jsonb,
        oracle_output JSONB NOT NULL DEFAULT '{}'::jsonb,
        original_yaml TEXT,
        refined_yaml TEXT,
        yaml_diff TEXT,
        spl_query TEXT,
        iterations INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        approval_status TEXT NOT NULL DEFAULT 'PENDING',
        deployment_status TEXT,
        error_feedback TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_pipeline_runs_rule_id ON pipeline_runs(rule_id);
    CREATE INDEX IF NOT EXISTS idx_pipeline_runs_created_at ON pipeline_runs(created_at DESC);
    """
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(ddl)


def create_run(rule_id: str, trigger_alert: Dict[str, Any], status: str = "PROCESSING") -> int:
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pipeline_runs (rule_id, trigger_alert, status)
                VALUES (%s, %s, %s)
                RETURNING run_id
                """,
                (rule_id, Json(trigger_alert), status),
            )
            return int(cur.fetchone()[0])


def update_run(run_id: int, fields: Dict[str, Any]) -> None:
    allowed = {
        "subgraph", "correlator_lineage", "oracle_output", "original_yaml",
        "refined_yaml", "yaml_diff", "spl_query", "iterations", "status",
        "approval_status", "deployment_status", "error_feedback",
    }
    updates = {key: value for key, value in fields.items() if key in allowed}
    if not updates:
        return
    set_clause = []
    values = []
    json_fields = {"subgraph", "correlator_lineage", "oracle_output", "trigger_alert"}
    for key, value in updates.items():
        set_clause.append(f"{key} = %s")
        values.append(Json(value) if key in json_fields else value)
    values.append(run_id)
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE pipeline_runs
                SET {", ".join(set_clause)}, updated_at = NOW()
                WHERE run_id = %s
                """,
                values,
            )


def list_runs(limit: int = 50) -> Iterable[Dict[str, Any]]:
    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT run_id, rule_id, trigger_alert, subgraph, correlator_lineage,
                       oracle_output, original_yaml, refined_yaml, yaml_diff, spl_query,
                       iterations, status, approval_status, deployment_status,
                       error_feedback, created_at, updated_at
                FROM pipeline_runs
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (max(1, min(limit, 200)),),
            )
            rows = cur.fetchall()
    return [_serialize_row(row) for row in rows]


def get_run(run_id: int) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT run_id, rule_id, trigger_alert, subgraph, correlator_lineage,
                       oracle_output, original_yaml, refined_yaml, yaml_diff, spl_query,
                       iterations, status, approval_status, deployment_status,
                       error_feedback, created_at, updated_at
                FROM pipeline_runs
                WHERE run_id = %s
                """,
                (run_id,),
            )
            row = cur.fetchone()
    return _serialize_row(row) if row else None


def set_approval(run_id: int, approval_status: str, deployment_status: Optional[str] = None) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE pipeline_runs
                SET approval_status = %s,
                    deployment_status = COALESCE(%s, deployment_status),
                    updated_at = NOW()
                WHERE run_id = %s
                """,
                (approval_status, deployment_status, run_id),
            )
    return get_run(run_id)


def _serialize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(row)
    for key, value in result.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat()
    return result
