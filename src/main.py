"""
Graph-ADAPT FastAPI Service & Asynchronous Redis Queue Worker
Listens to `queue:adapt:degraded_rules`, invokes the LangGraph multi-agent workflow,
and exposes REST endpoints for health checks, manual tuning triggers, and Splunk webhooks.
"""

import os
import json
import asyncio
import logging
import difflib
from datetime import datetime
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from src.agents.workflow import graph_adapt_app
from src.gatekeeper.evaluator import AsynchronousGatekeeper
from src.gatekeeper.siem_connectors import get_siem_connector
from src.ingestion.telemetry import (
    TELEMETRY_STREAM,
    TelemetryStreamConsumer,
)
from src.ingestion.pruner import graph_pruning_loop
from src.storage import init_schema, create_run, update_run, list_runs, get_run, set_approval
from src.storage.event_bus import event_bus
from src.testing.regression_engine import DoubleLoopRegressionEngine

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("GraphADAPT.Main")

QUEUE_NAME = "queue:adapt:degraded_rules"
BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================================
# Request / Response Models
# ============================================================================

class TuneRuleRequest(BaseModel):
    rule_id: str = Field(..., example="SIG-001")
    target_host: str = Field(default="WIN-SEC-WORKSTATION-01")
    seed_pid: int = Field(default=4108)
    sigma_yaml: Optional[str] = Field(
        default=None,
        description="Optional inline Sigma YAML. If omitted, loads from rules/stock_unrefined/<rule_id>.yml"
    )


class TelemetryIngestRequest(BaseModel):
    events: Optional[list] = None
    event: Optional[Dict[str, Any]] = None


# ============================================================================
# Helper: Load Stock Sigma YAML
# ============================================================================

def load_stock_sigma_yaml(rule_id: str) -> str:
    """Loads unrefined Sigma rule YAML from rules/stock_unrefined/."""
    for ext in (".yml", ".yaml"):
        candidate = BASE_DIR / "rules" / "stock_unrefined" / f"{rule_id}{ext}"
        if candidate.exists():
            return candidate.read_text(encoding="utf-8")
    raise FileNotFoundError(f"Stock Sigma rule file not found for rule_id: {rule_id}")


# ============================================================================
# Core Pipeline Execution Wrapper
# ============================================================================

def execute_tuning_pipeline(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Invokes the compiled LangGraph state machine for a degraded rule payload."""
    rule_id = payload["rule_id"]
    target_host = payload.get("target_host", "WIN-SEC-WORKSTATION-01")
    seed_pid = int(payload.get("seed_pid", 4108))

    sigma_yaml = payload.get("sigma_yaml") or load_stock_sigma_yaml(rule_id)
    run_id = None
    try:
        run_id = create_run(rule_id, payload)
    except Exception as exc:
        logger.error("[Postgres] Could not create pipeline audit run: %s", exc)

    event_bus.publish("pipeline.started", {
        "run_id": run_id,
        "rule_id": rule_id,
        "target_host": target_host,
        "seed_pid": seed_pid,
    })

    initial_state = {
        "rule_id": rule_id,
        "raw_subgraph": None,
        "correlator_output": None,
        "analysis_report": None,
        "current_sigma_yaml": sigma_yaml,
        "refined_rule": None,
        "test_results": {
            "target_host": target_host,
            "seed_pid": seed_pid
        },
        "iteration": 1,
        "error_feedback": None,
        "status": "PROCESSING"
    }

    logger.info(f"[Worker] Starting LangGraph self-healing workflow for {rule_id} (Host={target_host}, PID={seed_pid})")
    final_state = dict(initial_state)
    try:
        for update in graph_adapt_app.stream(
            initial_state,
            config={"recursion_limit": 100},
            stream_mode="updates",
        ):
            if not isinstance(update, dict):
                continue
            for node_name, node_update in update.items():
                if isinstance(node_update, dict):
                    final_state.update(node_update)
                event_bus.publish("pipeline.node", {
                    "run_id": run_id,
                    "rule_id": rule_id,
                    "node": node_name,
                    "status": node_update.get("status") if isinstance(node_update, dict) else None,
                })
    except Exception as exc:
        logger.error("[Worker] LangGraph stream execution failed: %s", exc)
        final_state["status"] = "FAILED_LLM_ERROR"
        final_state["error_feedback"] = str(exc)

    status = final_state.get("status", "UNKNOWN")
    subgraph = final_state.get("raw_subgraph")
    correlator = final_state.get("correlator_output")
    oracle = final_state.get("analysis_report")
    refined = final_state.get("refined_rule")
    refined_yaml = final_state.get("current_sigma_yaml") if status == "PASSED_REGRESSION" else None

    def json_value(value: Any) -> Any:
        if value is None:
            return None
        if hasattr(value, "model_dump"):
            return value.model_dump()
        if hasattr(value, "dict"):
            return value.dict()
        return value

    spl_query = None
    if refined_yaml:
        engine = DoubleLoopRegressionEngine()
        _, compiled = engine.validate_and_compile_spl(refined_yaml)
        spl_query = compiled if not compiled.startswith("pySigma") else None

    original_yaml = sigma_yaml
    yaml_diff = "\n".join(difflib.unified_diff(
        original_yaml.splitlines(),
        (refined_yaml or "").splitlines(),
        fromfile=f"{rule_id}:original",
        tofile=f"{rule_id}:refined",
        lineterm="",
    ))

    if run_id is not None:
        try:
            update_run(run_id, {
                "subgraph": json_value(subgraph),
                "correlator_lineage": json_value(correlator),
                "oracle_output": json_value(oracle),
                "original_yaml": original_yaml,
                "refined_yaml": refined_yaml,
                "yaml_diff": yaml_diff,
                "spl_query": spl_query,
                "iterations": max(0, final_state.get("iteration", 1) - 1),
                "status": status,
                "approval_status": "PENDING" if status == "PASSED_REGRESSION" else "NOT_REQUIRED",
                "error_feedback": final_state.get("error_feedback"),
            })
        except Exception as exc:
            logger.error("[Postgres] Could not update pipeline audit run %s: %s", run_id, exc)

    event_bus.publish("pipeline.completed", {
        "run_id": run_id,
        "rule_id": rule_id,
        "status": status,
        "iterations_used": final_state.get("iteration", 1) - 1,
        "threat_tier": json_value(oracle).get("threat_tier") if isinstance(json_value(oracle), dict) else None,
        "approval_status": "PENDING" if status == "PASSED_REGRESSION" else "NOT_REQUIRED",
    })

    logger.info(f"[Worker] Completed workflow for {rule_id} -> Final Status: {status}")
    return {
        "run_id": run_id,
        "rule_id": rule_id,
        "status": status,
        "iterations_used": final_state.get("iteration", 1) - 1,
        "refined_sigma_yaml": refined_yaml,
        "spl_query": spl_query,
        "yaml_diff": yaml_diff,
        "error_feedback": final_state.get("error_feedback"),
    }


# ============================================================================
# Background Redis Consumer Loop
# ============================================================================

async def redis_queue_consumer(stop_event: asyncio.Event):
    """Continuously pops degraded rule jobs from Redis and processes them out-of-band."""
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))

    client = aioredis.Redis(host=redis_host, port=redis_port, db=0, decode_responses=True)
    logger.info(f"[RedisConsumer] Listening on queue '{QUEUE_NAME}' at {redis_host}:{redis_port}...")

    try:
        while not stop_event.is_set():
            try:
                # Blocking pop with 2-second timeout so shutdown signals are respected cleanly
                item = await client.brpop(QUEUE_NAME, timeout=2)
                if item:
                    _, raw_payload = item
                    payload = json.loads(raw_payload)
                    await asyncio.to_thread(execute_tuning_pipeline, payload)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[RedisConsumer] Error processing queued job: {e}")
                await asyncio.sleep(2)
    finally:
        await client.aclose()
        logger.info("[RedisConsumer] Shutdown complete.")


# ============================================================================
# FastAPI Application Lifespan & Endpoints
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    event_bus.bind(asyncio.get_running_loop())
    try:
        await asyncio.to_thread(init_schema)
        logger.info("[Postgres] Pipeline audit schema initialized.")
    except Exception as exc:
        logger.error("[Postgres] Audit schema initialization failed: %s", exc)

    stop_event = asyncio.Event()
    consumer_task = asyncio.create_task(redis_queue_consumer(stop_event))
    pruner_task = asyncio.create_task(graph_pruning_loop(stop_event))

    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    telemetry_redis = aioredis.Redis(
        host=redis_host,
        port=redis_port,
        db=0,
        decode_responses=True,
    )
    telemetry_consumer = TelemetryStreamConsumer(
        telemetry_redis,
        batch_size=int(os.getenv("TELEMETRY_BATCH_SIZE", 100)),
        flush_seconds=float(os.getenv("TELEMETRY_FLUSH_SECONDS", 0.5)),
    )
    telemetry_task = asyncio.create_task(telemetry_consumer.start())
    yield
    stop_event.set()
    await telemetry_consumer.stop()
    await telemetry_task
    await consumer_task
    await pruner_task
    await telemetry_redis.aclose()


app = FastAPI(
    title="Graph-ADAPT Autonomous Detection Engineering API",
    description="Out-of-band Splunk rule tuning via Causal Provenance Graphs & LangGraph Multi-Agent Regression.",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health")
async def health_check():
    """Container health check endpoint."""
    return {"status": "healthy", "service": "graph-adapt-core"}


@app.post("/api/v1/telemetry/ingest")
async def ingest_live_telemetry(request: Dict[str, Any]):
    """Webhook ingestion for Sysmon, WEF, Winlogbeat, Fluent Bit, and OCSF payloads."""
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    client = aioredis.Redis(
        host=redis_host,
        port=redis_port,
        db=0,
        decode_responses=True,
    )
    try:
        events = request.get("events") if isinstance(request, dict) else None
        if not isinstance(events, list):
            events = [request]
        accepted = 0
        for event in events:
            if not isinstance(event, dict):
                continue
            await client.xadd(
                TELEMETRY_STREAM,
                {"payload": json.dumps(event)},
                maxlen=int(os.getenv("TELEMETRY_STREAM_MAXLEN", 100000)),
                approximate=True,
            )
            accepted += 1
        return {"accepted": accepted, "stream": TELEMETRY_STREAM}
    finally:
        await client.aclose()


def _alert_value(payload: Dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    nested = payload.get("data") or payload.get("alert") or payload.get("event") or {}
    if isinstance(nested, dict):
        for key in keys:
            if key in nested:
                return nested[key]
    return None


def _extract_alert_metadata(payload: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = _alert_value(
        payload,
        ("rule_id", "ruleId", "rule_name", "ruleName", "search_name", "signature_id"),
    )
    hostname = _alert_value(
        payload,
        ("hostname", "host", "computer", "Computer", "agent_name"),
    )
    if isinstance(hostname, dict):
        hostname = hostname.get("name") or hostname.get("hostname")
    target_pid = _alert_value(
        payload,
        ("target_pid", "targetProcessId", "process_id", "pid", "ProcessId"),
    )
    process_guid = _alert_value(
        payload,
        ("process_guid", "processGuid", "ProcessGuid", "process.entity_id"),
    )
    status = str(
        _alert_value(payload, ("disposition", "disposition_status", "status", "state"))
        or "open"
    ).strip().lower()
    return {
        "rule_id": str(rule_id or "unknown-rule"),
        "hostname": str(hostname or "unknown-host"),
        "target_pid": int(target_pid) if target_pid not in (None, "") else 4108,
        "process_guid": process_guid,
        "status": status,
    }


@app.post("/api/v1/alerts/webhook")
async def receive_live_alert(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    """Tracks live alert conversion ratios and immediately queues degraded rules."""
    metadata = _extract_alert_metadata(payload)
    rule_id = metadata["rule_id"]
    event_bus.publish("alert.received", {
        "rule_id": rule_id,
        "hostname": metadata["hostname"],
        "target_pid": metadata["target_pid"],
        "status": metadata["status"],
    })

    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    client = aioredis.Redis(
        host=redis_host,
        port=redis_port,
        db=0,
        decode_responses=True,
    )
    try:
        now = asyncio.get_running_loop().time()
        window_seconds = int(os.getenv("GATEKEEPER_WINDOW_SECONDS", 86400))
        alerts_key = f"gatekeeper:alerts:{rule_id}"
        incidents_key = f"gatekeeper:incidents:{rule_id}"

        await client.zadd(alerts_key, {json.dumps(metadata): now})
        confirmed_statuses = {
            "true_positive",
            "confirmed",
            "resolved_true_positive",
            "closed",
        }
        false_positive_statuses = {
            "false_positive",
            "benign",
            "closed_false_positive",
        }
        if metadata["status"] in confirmed_statuses:
            await client.zadd(incidents_key, {json.dumps(metadata): now})
        await client.zremrangebyscore(alerts_key, "-inf", now - window_seconds)
        await client.zremrangebyscore(incidents_key, "-inf", now - window_seconds)

        total_alerts = await client.zcard(alerts_key)
        true_incidents = await client.zcard(incidents_key)
        denominator = max(1, true_incidents)
        conversion_ratio = total_alerts / denominator
        theta = float(os.getenv("GATEKEEPER_THETA_THRESHOLD", 15.0))
        max_fp = int(os.getenv("GATEKEEPER_MAX_FP_24H", 20))
        degraded = conversion_ratio >= theta or (
            metadata["status"] in false_positive_statuses
            and total_alerts >= max_fp
        )

        await client.hset(
            f"gatekeeper:health:{rule_id}",
            mapping={
                "total_alerts": total_alerts,
                "true_incidents": true_incidents,
                "conversion_ratio": round(conversion_ratio, 4),
                "status": "DEGRADED" if degraded else "HEALTHY",
                "updated_at": datetime.utcnow().isoformat() + "Z",
            },
        )

        if degraded:
            cooldown_key = f"gatekeeper:queued:{rule_id}"
            already_queued = not await client.set(
                cooldown_key,
                "1",
                ex=int(os.getenv("GATEKEEPER_QUEUE_COOLDOWN_SECONDS", 900)),
                nx=True,
            )
            if already_queued:
                return {
                    "accepted": True,
                    "degraded": True,
                    "conversion_ratio": round(conversion_ratio, 4),
                    "queued": False,
                    "reason": "queue cooldown active",
                }
            tuning_payload = {
                "rule_id": rule_id,
                "rule_title": str(_alert_value(payload, ("rule_title", "title", "name")) or rule_id),
                "trigger_timestamp": datetime.utcnow().isoformat() + "Z",
                "conversion_ratio": round(conversion_ratio, 4),
                "recent_alerts_count_24h": total_alerts,
                "target_host": metadata["hostname"],
                "seed_pid": metadata["target_pid"],
                "process_guid": metadata["process_guid"],
                "retry_iteration": 1,
            }
            queue_len = await client.lpush(
                QUEUE_NAME,
                json.dumps(tuning_payload),
            )
            logger.warning(
                "Live webhook degraded rule %s; Tr=%.2f; queued length=%s",
                rule_id,
                conversion_ratio,
                queue_len,
            )
            return {
                "accepted": True,
                "degraded": True,
                "conversion_ratio": round(conversion_ratio, 4),
                "queued": True,
            }
        return {
            "accepted": True,
            "degraded": False,
            "conversion_ratio": round(conversion_ratio, 4),
            "queued": False,
        }
    finally:
        await client.aclose()


@app.post("/api/v1/gatekeeper/evaluate/{rule_id}")
async def trigger_gatekeeper_check(rule_id: str, background_tasks: BackgroundTasks):
    """Triggers an on-demand Splunk conversion ratio check for a specific rule ID."""
    gatekeeper = AsynchronousGatekeeper()
    background_tasks.add_task(gatekeeper.evaluate_rule, rule_id)
    return {"message": f"Gatekeeper evaluation scheduled for rule '{rule_id}'."}


@app.get("/api/v1/gatekeeper/health/{rule_id}")
async def live_gatekeeper_health(rule_id: str):
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    client = aioredis.Redis(
        host=redis_host,
        port=redis_port,
        db=0,
        decode_responses=True,
    )
    try:
        health = await client.hgetall(f"gatekeeper:health:{rule_id}")
        return health or {
            "rule_id": rule_id,
            "status": "UNKNOWN",
            "total_alerts": 0,
            "true_incidents": 0,
            "conversion_ratio": 0,
        }
    finally:
        await client.aclose()


@app.post("/api/v1/pipeline/tune")
async def trigger_direct_tuning(request: TuneRuleRequest):
    """Synchronously invokes the Graph-ADAPT tuning pipeline for testing or direct API integration."""
    try:
        result = await asyncio.to_thread(execute_tuning_pipeline, request.model_dump())
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Pipeline execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws/events")
async def events_websocket(websocket: WebSocket):
    await websocket.accept()
    queue = event_bus.subscribe()
    try:
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=20)
                await websocket.send_text(message)
            except asyncio.TimeoutError:
                await websocket.send_text(
                    '{"type":"heartbeat","timestamp":"","payload":{"status":"connected"}}'
                )
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(queue)


@app.get("/api/v1/runs")
async def get_pipeline_runs(limit: int = 50):
    try:
        return await asyncio.to_thread(list_runs, limit)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {exc}")


@app.get("/api/v1/runs/{run_id}")
async def get_pipeline_run(run_id: int):
    try:
        run = await asyncio.to_thread(get_run, run_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {exc}")
    if not run:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return run


class RunActionRequest(BaseModel):
    analyst: str = Field(default="SOC Analyst")
    reason: Optional[str] = None


@app.post("/api/v1/runs/{run_id}/approve")
async def approve_run(run_id: int, action: RunActionRequest):
    run = await asyncio.to_thread(get_run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    if not run.get("spl_query"):
        raise HTTPException(status_code=409, detail="Run has no approved/regression-tested SPL")
    try:
        connector = get_siem_connector()
        deployment_status = await asyncio.to_thread(
            connector.deploy_rule,
            run["rule_id"],
            run["spl_query"],
            approved_by=action.analyst,
        )
        updated = await asyncio.to_thread(
            set_approval,
            run_id,
            "APPROVED",
            deployment_status,
        )
        event_bus.publish("run.approved", {
            "run_id": run_id,
            "rule_id": run["rule_id"],
            "analyst": action.analyst,
            "deployment_status": deployment_status,
        })
        return updated
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"SIEM approval failed: {exc}")


@app.post("/api/v1/runs/{run_id}/rollback")
async def rollback_run(run_id: int, action: RunActionRequest):
    run = await asyncio.to_thread(get_run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    updated = await asyncio.to_thread(set_approval, run_id, "ROLLED_BACK", "ROLLBACK_RECORDED")
    event_bus.publish("run.rollback", {
        "run_id": run_id,
        "rule_id": run["rule_id"],
        "analyst": action.analyst,
        "reason": action.reason,
    })
    return updated


@app.post("/api/v1/runs/{run_id}/escalate")
async def escalate_run(run_id: int, action: RunActionRequest):
    run = await asyncio.to_thread(get_run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    updated = await asyncio.to_thread(set_approval, run_id, "ESCALATED", "SOC_REVIEW")
    event_bus.publish("run.escalated", {
        "run_id": run_id,
        "rule_id": run["rule_id"],
        "analyst": action.analyst,
        "reason": action.reason,
    })
    return updated


DASHBOARD_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"><title>Graph-ADAPT SOC Command Center</title>
  <style>
    :root{--bg:#09111f;--panel:#111d31;--line:#263956;--cyan:#65d9ff;--green:#55d68b;--red:#ff6b81;--amber:#ffc15e}
    body{margin:0;background:var(--bg);color:#dbe7ff;font-family:Segoe UI,Arial,sans-serif}
    header{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;border-bottom:1px solid var(--line)}
    h1{font-size:20px;margin:0}.live{color:var(--green)}
    main{display:grid;grid-template-columns:280px 1fr 1fr;gap:12px;padding:12px;height:calc(100vh - 88px)}
    .panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}
    #runs{grid-row:1/3}.graph{height:260px}.diff{height:220px}.spl{height:220px}
    pre{white-space:pre-wrap;color:#b9c9ea;font-size:12px}.run{padding:9px;border-bottom:1px solid var(--line);cursor:pointer}
    .run:hover{background:#172743}.badge{float:right;border-radius:10px;padding:2px 8px;font-size:11px}
    .healthy{background:#1d6948}.degraded{background:#7a2e3d}.pending{background:#806127}
    .actions button{margin:4px;padding:8px;border:0;border-radius:5px;cursor:pointer}
    #approve{background:var(--green);color:#06150d}#rollback{background:var(--amber);color:#1c1300}#escalate{background:var(--red);color:#fff}
    canvas{width:100%;height:250px}
  </style>
</head>
<body>
<header><h1>Graph-ADAPT / SOC Analyst Command Center</h1><span id="socket" class="live">Connecting...</span></header>
<main>
  <section id="runs" class="panel"><h3>Pipeline Runs</h3><div id="runList"></div></section>
  <section class="panel">
    <h3>Rule Health & Causal Provenance</h3>
    <div id="health"></div>
    <canvas id="graph" class="graph"></canvas>
  </section>
  <section class="panel">
    <h3>Exploit Oracle</h3><pre id="oracle">Select a run</pre>
  </section>
  <section class="panel">
    <h3>YAML Diff</h3><pre id="diff" class="diff">Select a run</pre>
  </section>
  <section class="panel">
    <h3>Compiled SPL</h3><pre id="spl" class="spl">Select a run</pre>
    <div class="actions">
      <button id="approve">Approve & Push to SIEM</button>
      <button id="rollback">Rollback</button>
      <button id="escalate">Escalate</button>
    </div>
  </section>
</main>
<script>
let selected=null;
async function loadRuns(){
  const runs=await (await fetch('/api/v1/runs')).json();
  const el=document.getElementById('runList');
  el.innerHTML=runs.map(r=>`<div class="run" data-id="${r.run_id}">
    <b>${r.rule_id}</b><span class="badge ${r.status==='PASSED_REGRESSION'?'healthy':'degraded'}">${r.status}</span>
    <small>#${r.run_id} · ${r.approval_status}</small></div>`).join('');
  document.queryAll=undefined;
  el.querySelectorAll('.run').forEach(x=>x.onclick=()=>selectRun(x.dataset.id));
  if(runs.length&&!selected) selectRun(runs[0].run_id);
}
async function selectRun(id){
  selected=id;
  const r=await (await fetch('/api/v1/runs/'+id)).json();
  document.getElementById('health').textContent=`${r.status} · ${r.iterations||0} iteration(s) · ${r.approval_status||'PENDING'}`;
  document.getElementById('oracle').textContent=JSON.stringify(r.oracle_output||{},null,2);
  document.getElementById('diff').textContent=r.yaml_diff||'No YAML changes';
  document.getElementById('spl').textContent=r.spl_query||'No compiled SPL';
  drawGraph(r.subgraph);
}
function drawGraph(subgraph){
  const c=document.getElementById('graph'),ctx=c.getContext('2d');
  c.width=c.clientWidth;c.height=250;ctx.clearRect(0,0,c.width,c.height);
  const nodes=(subgraph&&subgraph.nodes)||[];
  nodes.slice(0,12).forEach((n,i)=>{
    const x=50+(i%4)*((c.width-100)/3),y=55+Math.floor(i/4)*65;
    ctx.beginPath();ctx.arc(x,y,18,0,Math.PI*2);ctx.fillStyle=i===0?'#65d9ff':'#263956';ctx.fill();
    ctx.fillStyle='#dbe7ff';ctx.font='11px Segoe UI';ctx.fillText(n.label,x-22,y+35);
  });
  const edges=(subgraph&&subgraph.edges)||[];
  ctx.strokeStyle='#65d9ff';ctx.globalAlpha=.35;
  edges.slice(0,20).forEach((e,i)=>{if(i>=11)return;ctx.beginPath();ctx.moveTo(50+(i%4)*((c.width-100)/3),55+Math.floor(i/4)*65);ctx.lineTo(50+((i+1)%4)*((c.width-100)/3),55+Math.floor((i+1)/4)*65);ctx.stroke()});ctx.globalAlpha=1;
}
async function action(name){
  if(!selected)return;
  const res=await fetch(`/api/v1/runs/${selected}/${name}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({analyst:'SOC Analyst',reason:'Analyst command center action'})});
  if(!res.ok) alert(await res.text());
  loadRuns();selectRun(selected);
}
document.getElementById('approve').onclick=()=>action('approve');
document.getElementById('rollback').onclick=()=>action('rollback');
document.getElementById('escalate').onclick=()=>action('escalate');
const protocol=location.protocol==='https:'?'wss':'ws';
const ws=new WebSocket(`${protocol}://${location.host}/ws/events`);
ws.onopen=()=>document.getElementById('socket').textContent='Live Event Bus Connected';
ws.onclose=()=>document.getElementById('socket').textContent='Disconnected';
ws.onmessage=e=>{const m=JSON.parse(e.data);if(['pipeline.completed','pipeline.started','run.approved','run.rollback','run.escalated'].includes(m.type))loadRuns()};
setInterval(loadRuns,5000);loadRuns();
</script>
</body></html>
"""


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(DASHBOARD_HTML)