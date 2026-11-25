# Graph-ADAPT

Graph-ADAPT is a graph-assisted, agent-driven platform for detecting noisy SIEM rules, correlating endpoint activity, classifying the surrounding threat context, and proposing or escalating detection-rule changes.

The current implementation combines:

- FastAPI ingestion and control endpoints
- Redis queues and Redis Streams
- Memgraph causal provenance graph storage
- LangGraph multi-agent orchestration
- Groq-powered LLM agents
- Double-loop Sigma/Splunk regression testing
- Mock, Splunk, Elastic, and Wazuh-compatible SIEM connector interfaces

> This is an active research prototype. It has a working core and real-time telemetry/Gatekeeper foundations, but it is not yet a complete SOC production platform. The remaining work is listed in the implementation gap table below.

---

## Table of contents

- [What the project does](#what-the-project-does)
- [Architecture](#architecture)
- [Implemented components](#implemented-components)
- [Repository structure](#repository-structure)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Docker deployment](#docker-deployment)
- [Running locally](#running-locally)
- [API reference](#api-reference)
- [Telemetry replay](#telemetry-replay)
- [LangGraph workflow](#langgraph-workflow)
- [Regression testing](#regression-testing)
- [Graph ingestion](#graph-ingestion)
- [SIEM integration](#siem-integration)
- [Operational procedures](#operational-procedures)
- [Implementation status](#implementation-status)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Security considerations](#security-considerations)

---

## What the project does

Graph-ADAPT runs a self-healing detection-engineering pipeline:

1. SIEM alerts or endpoint telemetry arrive through REST webhooks or Redis Streams.
2. The Gatekeeper calculates the alert-to-confirmed-incident conversion ratio.
3. A degraded rule is queued for investigation.
4. The GraphRAG node retrieves a three-hop causal process subgraph from Memgraph.
5. The Context Correlator describes the process execution lineage.
6. The Exploit Oracle classifies the event as L0, L1, L2, or L3.
7. L0/L1 benign or administrative activity is sent to the Rule Refiner.
8. L2/L3 malicious activity is escalated to human review.
9. A refined Sigma rule is tested against benign historical noise and Atomic Red Team-style attack payloads.
10. Passed rules export Sigma YAML and compiled Splunk SPL; failed rules use bounded feedback retries.

The Gatekeeper conversion ratio is:

\[
T_r = \frac{\text{Total Alerts}}{\max(1,\text{Confirmed Incidents})}
\]

The default degradation threshold is `GATEKEEPER_THETA_THRESHOLD=15.0`.

---

## Architecture

```text
Telemetry / SIEM
  | REST webhook or Redis Stream
  v
FastAPI Service
  |-- /api/v1/telemetry/ingest
  |-- /api/v1/alerts/webhook
  |-- /api/v1/pipeline/tune
  `-- /api/v1/gatekeeper/evaluate/{rule_id}

Redis
  |-- queue:adapt:degraded_rules
  |-- stream:telemetry:sysmon
  `-- rolling Gatekeeper counters

Memgraph
  |-- Process, File, UserToken, IPAddress nodes
  `-- SPAWNED, WRITTEN_TO, AUTHENTICATED_AS, CONNECTED_TO edges

LangGraph
  GraphRAG -> Context Correlator -> Exploit Oracle
                                   |-- L0/L1 -> Rule Refiner -> Regression -> retry/end
                                   `-- L2/L3 -> Human escalation

Regression Engine
  |-- pySigma validation
  |-- Loop 1: 48-hour benign-noise suppression
  `-- Loop 2: attack recall retention

PostgreSQL
  Reserved for persistent execution and deployment records
```

---

## Implemented components

### API and workers

The main FastAPI application starts:

- A Redis queue consumer for `queue:adapt:degraded_rules`
- A Redis consumer group for `stream:telemetry:sysmon`
- A periodic Memgraph graph-pruning task

The queue consumer invokes the LangGraph workflow out-of-band with `asyncio.to_thread`.

### Real-time telemetry ingestion

The API accepts:

- Sysmon JSON with an `Event`/`System`/`EventData` structure
- Flat or Winlogbeat-style telemetry
- Batched payloads using an `events` array
- Windows Event Forwarding-style nested event data

Webhook telemetry is written to the Redis Stream, allowing the FastAPI process to remain responsive.

### Redis Streams consumer

The current consumer:

- Uses `XGROUP CREATE`
- Uses `XREADGROUP`
- Reads bounded batches of up to 100 events
- Ingests graph data outside FastAPI request handling
- Uses `XACK` after successful batch processing

The defaults are configurable with environment variables.

### Memgraph causal graph

The graph builder converts:

- Sysmon EID 1: process creation
- Sysmon EID 11: file creation
- Sysmon EID 3: network connection

The GraphRAG extractor retrieves process lineage and execution context and serializes it into `SubGraphPayload`.

The pruning query removes old leaf nodes with no incoming or outgoing graph edges. It is not intended to delete connected attack evidence.

### LangGraph agents

The workflow uses:

- `ContextCorrelatorOutput`
- `ExploitOracleOutput`
- `RefinedSigmaOutput`
- `GraphADAPTState`

The Oracle routes L0/L1 to the refiner and L2/L3 to human escalation.

### Gatekeeper

The existing Gatekeeper supports:

- Threshold-based conversion-ratio evaluation
- Maximum false-positive evaluation
- Redis rolling counters for live alert webhooks
- A queue cooldown to prevent repeated tuning bursts
- Mock, Splunk, Elastic, and Wazuh-oriented connector classes

### Regression engine

The regression engine:

- Validates Sigma YAML with pySigma
- Compiles SPL using the pySigma Splunk backend
- Matches selected and filtered Sigma blocks against JSON telemetry
- Runs the historical-noise Loop 1
- Runs the attack-corpus Loop 2
- Exports verified artifacts into `rules/refined_output/`

### Rule deployment

The SIEM connector interface includes deployment methods for:

- Mock mode
- Splunk Saved Searches
- Elasticsearch/Kibana-oriented detection records

Automatic deployment is not yet connected to a persisted approval workflow.

---

## Repository structure

```text
GraphAdapt/
|-- .env.example
|-- requirements.txt
|-- README.md
|-- docker/
|   |-- Dockerfile
|   `-- docker-compose.yml
|-- src/
|   |-- main.py
|   |-- agents/
|   |   |-- agent_nodes.py
|   |   |-- schemas.py
|   |   `-- workflow.py
|   |-- gatekeeper/
|   |   |-- evaluator.py
|   |   `-- siem_connectors.py
|   |-- graph/
|   |   |-- cypher_queries.py
|   |   `-- graph_builder.py
|   |-- ingestion/
|   |   |-- telemetry.py
|   |   `-- pruner.py
|   `-- testing/
|       `-- regression_engine.py
|-- scripts/
|   |-- live_stream_agent.py
|   `-- seed_memgraph.py
|-- rules/
|   |-- stock_unrefined/
|   `-- refined_output/
|-- data/
|   |-- raw_logs/
|   `-- atomic_payloads/
`-- tests/
```

---

## Requirements

- Windows 10/11 or WSL2
- Docker Desktop
- Docker Compose v2
- Python 3.11 recommended for host-side scripts
- Groq API key
- Optional Splunk or Elasticsearch credentials

Python dependencies are listed in [requirements.txt](requirements.txt).

---

## Configuration

Copy the example file:

```powershell
Copy-Item .env.example .env
```

Set at least:

```dotenv
GROQ_API_KEY=replace_with_your_groq_api_key
LLM_MODEL_NAME=openai/gpt-oss-120b
SIEM_MODE=mock

MEMGRAPH_HOST=localhost
MEMGRAPH_PORT=7687
MEMGRAPH_USER=admin
MEMGRAPH_PASSWORD=password123

REDIS_HOST=localhost
REDIS_PORT=6379

GATEKEEPER_THETA_THRESHOLD=15.0
GATEKEEPER_MAX_FP_24H=20
GATEKEEPER_WINDOW_SECONDS=86400
GATEKEEPER_QUEUE_COOLDOWN_SECONDS=900
MAX_REGRESSION_RETRIES=3

TELEMETRY_BATCH_SIZE=100
TELEMETRY_FLUSH_SECONDS=0.5
TELEMETRY_STREAM_MAXLEN=100000
GRAPH_RETENTION_HOURS=72
GRAPH_PRUNE_INTERVAL_SECONDS=3600
```

Optional Splunk settings:

```dotenv
SIEM_MODE=splunk
SPLUNK_URL=https://splunk.example.com:8089
SPLUNK_TOKEN=
SPLUNK_USERNAME=
SPLUNK_PASSWORD=
SIEM_VERIFY_SSL=false
```

Optional Elastic/Wazuh settings:

```dotenv
SIEM_MODE=elastic
ELASTIC_URL=https://elastic.example.com:9200
ELASTIC_API_KEY=
ELASTIC_ALERT_INDEX=logs-*
SIEM_VERIFY_SSL=false
```

Use `SIEM_MODE=wazuh` to route to the Elastic-compatible connector.

---

## Docker deployment

Start all existing services:

```powershell
docker compose -f docker/docker-compose.yml up --build
```

Start in detached mode:

```powershell
docker compose -f docker/docker-compose.yml up -d --build
```

Check service status:

```powershell
docker compose -f docker/docker-compose.yml ps
```

View application logs:

```powershell
docker compose -f docker/docker-compose.yml logs -f graph_adapt_core
```

Stop services:

```powershell
docker compose -f docker/docker-compose.yml down
```

Remove persisted database, Redis, and Memgraph volumes:

```powershell
docker compose -f docker/docker-compose.yml down -v
```

Exposed endpoints:

| Service | Address |
|---|---|
| FastAPI | http://localhost:8000 |
| API health | http://localhost:8000/health |
| Interactive API docs | http://localhost:8000/docs |
| Memgraph Bolt | localhost:7687 |
| Memgraph Lab | http://localhost:3000 |
| Redis | localhost:6379 |
| PostgreSQL | localhost:5442 |

PostgreSQL is exposed on host port `5442` and maps to container port `5432`.

---

## Running locally

Install dependencies:

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Compile the Python source tree:

```powershell
python -m compileall -q src scripts
```

Start the API with local Redis and Memgraph running:

```powershell
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify the application:

```powershell
curl http://localhost:8000/health
```

---

## API reference

### Health

```http
GET /health
```

### Direct tuning

```http
POST /api/v1/pipeline/tune
Content-Type: application/json
```

```json
{
  "rule_id": "SIG-001",
  "target_host": "WIN-SEC-WORKSTATION-01",
  "seed_pid": 4108
}
```

The inline `sigma_yaml` field is optional. If absent, the stock YAML is loaded from `rules/stock_unrefined/SIG-001.yml`.

### Gatekeeper evaluation

```http
POST /api/v1/gatekeeper/evaluate/SIG-001
```

Returns a scheduled background-task response.

### Live Gatekeeper health

```http
GET /api/v1/gatekeeper/health/SIG-001
```

### Telemetry ingestion

```http
POST /api/v1/telemetry/ingest
Content-Type: application/json
```

Single event:

```json
{
  "@timestamp": "2026-11-25T12:00:00Z",
  "host": {"name": "WIN-SEC-WORKSTATION-01"},
  "winlog": {
    "event_id": 1,
    "event_data": {
      "UtcTime": "2026-11-25T12:00:00Z",
      "ProcessId": "4108",
      "ProcessGuid": "{demo-guid}",
      "ParentProcessId": "700",
      "ParentProcessGuid": "{parent-guid}",
      "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "CommandLine": "powershell.exe -EncodedCommand ZABlAG0AbwA=",
      "User": "NT AUTHORITY\\SYSTEM",
      "IntegrityLevel": "System"
    }
  }
}
```

Batch:

```json
{
  "events": [
    {"@timestamp": "2026-11-25T12:00:00Z", "event_id": 1},
    {"@timestamp": "2026-11-25T12:00:01Z", "event_id": 11}
  ]
}
```

### SIEM alert webhook

```http
POST /api/v1/alerts/webhook
Content-Type: application/json
```

Supported sample fields include `rule_id`, `ruleName`, `rule_name`, `hostname`, `host`, `target_pid`, `targetProcessId`, `pid`, `process_guid`, `processGuid`, `status`, and `disposition`.

```json
{
  "rule_id": "SIG-001",
  "hostname": "WIN-SEC-WORKSTATION-01",
  "target_pid": 4108,
  "process_guid": "{demo-guid}",
  "disposition": "false_positive"
}
```

---

## Telemetry replay

Send generated telemetry through the REST webhook:

```powershell
python scripts/live_stream_agent.py --mode webhook --rate 10 --count 100
```

Send generated telemetry directly into Redis:

```powershell
python scripts/live_stream_agent.py --mode redis --rate 25 --count 100
```

To target another API:

```powershell
python scripts/live_stream_agent.py --url http://localhost:8000 --mode webhook --rate 10 --count 100
```

Useful Redis checks:

```powershell
docker exec -it graph_adapt_redis redis-cli XLEN stream:telemetry:sysmon
docker exec -it graph_adapt_redis redis-cli XPENDING stream:telemetry:sysmon graph-adapt-ingestors
docker exec -it graph_adapt_redis redis-cli LRANGE queue:adapt:degraded_rules 0 20
```

---

## Verified mock-data procedure

The repository is usable for mock GraphRAG and mock Gatekeeper demonstrations, but the full mock run is not yet guaranteed to produce a verified refined rule. A 2026-11-25 verification reached GraphRAG, Correlator, L1 classification, the Rule Refiner, and all three regression attempts, then ended with `ESCALATED_TO_HUMAN` because pySigma rejected the generated YAML.

Use this procedure to reproduce the current behavior.

### 1. Start infrastructure

```powershell
cd "C:\Users\jasim\OneDrive\Documents\JASIM\RESEARCH\Final Year Project\GraphAdapt"
Copy-Item .env.example .env
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml ps
```

Set at least:

```dotenv
SIEM_MODE=mock
GROQ_API_KEY=your_groq_api_key
LLM_MODEL_NAME=openai/gpt-oss-120b
MEMGRAPH_HOST=memgraph
MEMGRAPH_PORT=7687
MEMGRAPH_USER=admin
MEMGRAPH_PASSWORD=password123
REDIS_HOST=redis
REDIS_PORT=6379
```

Verify the API:

```powershell
curl.exe http://localhost:8000/health
```

### 2. Seed the mock SCCM lineage

```powershell
python scripts/seed_memgraph.py
```

This creates the mock lineage:

```text
services.exe -> CcmExec.exe -> powershell.exe
PID 680 -> PID 2104 -> PID 4108
```

It also loads the benign noise and attack records used by the regression engine.

### 3. Verify GraphRAG directly

```powershell
python -c "from src.graph.graph_builder import CausalProvenanceEngine; s=CausalProvenanceEngine().retrieve_3hop_subgraph('WIN-SEC-WORKSTATION-01',4108,'SIG-001'); print(s.model_dump_json(indent=2) if s else 'NO_SUBGRAPH')"
```

A working result should contain:

- A root PowerShell process
- The CcmExec parent
- The services parent
- A SYSTEM UserToken
- `SPAWNED` and `AUTHENTICATED_AS` edges

### 4. Trigger the mock Gatekeeper

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:8000/api/v1/gatekeeper/evaluate/SIG-001" `
  -Method Post
```

The mock connector reports `100` alerts and `2` incidents, producing a conversion ratio of `50.00`. It should queue `SIG-001` for tuning.

Inspect the queue:

```powershell
docker exec -it graph_adapt_redis redis-cli LRANGE queue:adapt:degraded_rules 0 20
docker compose -f docker/docker-compose.yml logs -f graph_adapt_core
```

### 5. Trigger the direct mock pipeline

```powershell
$body = @{
  rule_id = "SIG-001"
  target_host = "WIN-SEC-WORKSTATION-01"
  seed_pid = 4108
} | ConvertTo-Json

Invoke-RestMethod `
  -Uri "http://localhost:8000/api/v1/pipeline/tune" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body `
  -TimeoutSec 180 |
  ConvertTo-Json -Depth 12
```

Expected successful result shape:

```json
{
  "rule_id": "SIG-001",
  "status": "PASSED_REGRESSION",
  "iterations_used": 1,
  "refined_sigma_yaml": "<Sigma YAML>",
  "error_feedback": null
}
```

The generated artifacts should appear in:

```text
rules/refined_output/SIG-001.yml
rules/refined_output/SIG-001.spl
```

### 6. Current verified output

As of the latest verification:

```json
{
  "rule_id": "SIG-001",
  "status": "ESCALATED_TO_HUMAN",
  "iterations_used": 3,
  "refined_sigma_yaml": null,
  "error_feedback": "Escalated to human review. Reason: Regression Failure (Max Retries Exceeded)"
}
```

This means the mock run has reached and exercised:

- Mock Gatekeeper degradation
- Redis queue processing
- Memgraph 3-hop GraphRAG
- Context Correlator
- L1 threat classification
- Rule Refiner
- Three pySigma/Double-Loop attempts

It does not currently prove that the Refiner-generated mock rule is valid. Generated YAML has been rejected for unsupported or malformed Sigma expressions.

### 7. Verify stock-rule compilation independently

```powershell
python -c "from src.testing.regression_engine import DoubleLoopRegressionEngine; from pathlib import Path; r=Path('rules/stock_unrefined/SIG-001.yml').read_text(); e=DoubleLoopRegressionEngine(); print(e.validate_and_compile_spl(r))"
```

The stock rule has independently compiled to Splunk SPL. This only validates the existing stock artifact, not an LLM-generated refinement.

Seed the graph manually:

```powershell
python scripts/seed_memgraph.py
```

---

## LangGraph workflow

The compiled workflow is in [src/agents/workflow.py](src/agents/workflow.py).

Node behavior:

| Node | Output |
|---|---|
| `graphrag_extractor` | `SubGraphPayload` or graph error |
| `context_correlator` | Execution lineage and anomalous indicators |
| `exploit_oracle` | L0-L3 classification and action route |
| `rule_refiner` | Updated Sigma YAML |
| `regression_tester` | Pass, Loop 1 failure, or Loop 2 failure |
| `escalate_human` | Human-review terminal status |

Routing:

- L0/L1 or `REFINE_RULE`: refine rule
- L2/L3 or `ESCALATE_HUMAN`: escalate
- Both regression loops pass: finish
- A regression loop fails: retry up to `MAX_REGRESSION_RETRIES`
- Maximum retries or missing data: escalate

Groq model configuration:

```dotenv
LLM_MODEL_NAME=openai/gpt-oss-120b
GROQ_API_KEY=...
```

The agent nodes require the Groq API key and use structured JSON output. The project should not send secrets or sensitive production telemetry to external LLM providers without authorization and redaction.

---

## Regression testing

Run a direct tuning workflow:

```powershell
curl -X POST "http://localhost:8000/api/v1/pipeline/tune" `
  -H "Content-Type: application/json" `
  -d '{\"rule_id\":\"SIG-001\",\"target_host\":\"WIN-SEC-WORKSTATION-01\",\"seed_pid\":4108}'
```

Datasets:

- Benign noise: `data/raw_logs/background_noise_48h.json`
- Attack corpus: `data/atomic_payloads/attack_corpus_all.json`

Verified outputs:

- `rules/refined_output/SIG-001.yml`
- `rules/refined_output/SIG-001.spl`

The stock rule is [rules/stock_unrefined/SIG-001.yml](rules/stock_unrefined/SIG-001.yml).

---

## Graph ingestion

Memgraph 2.14 is used. Native Cypher is required:

- No APOC
- No Cypher list comprehensions
- No map projections inside list comprehensions
- Every `mgclient`/GQLAlchemy call supplies parameters, with `{}` used instead of `None`

Example Memgraph queries should use parameter variables such as `$target_pid` and `$target_host`.

Example storage checks:

```cypher
MATCH (n) RETURN labels(n), count(n);
```

```cypher
MATCH ()-[r]->() RETURN type(r), count(r);
```

---

## SIEM integration

### Mock mode

```dotenv
SIEM_MODE=mock
```

The mock connector returns deterministic `100` alerts and `2` incidents.

### Splunk

Splunk mode uses:

- `/services/search/jobs` for REST search jobs
- `/services/search/jobs/{sid}/results` for search results
- Saved Search creation in the namespace used by the connector

Deployment to a live Splunk instance should remain approval-gated until the deployment audit workflow is implemented.

### Elastic or Wazuh

Elastic/Wazuh mode uses Elasticsearch `_count`, `_search`, and a Kibana-oriented detection-record path. Alert schemas vary significantly; field mappings must be adapted for the target deployment.

---

## Operational procedures

### Upgrade a rule

1. Send or observe live telemetry.
2. Receive a live alert webhook.
3. Confirm `Tr` reaches the configured threshold.
4. Confirm a tuning payload appears in `queue:adapt:degraded_rules`.
5. Verify GraphRAG returns a subgraph.
6. Review agent status and regression results.
7. Review generated YAML and SPL.
8. Deploy only after manual approval until approval persistence and deployment APIs are complete.

### Roll back a rule

The current repository does not yet implement persistent rule versions or automatic rollback. Operators should manually:

1. Retain the stock rule.
2. Retain the previous deployed Saved Search or Elastic rule definition.
3. Disable the refined rule.
4. Restore the previous rule artifact.
5. Record the incident, reason, and operator in the SOC ticket.

---

## Implementation status

| Area | Status |
|---|---|
| FastAPI service | Implemented |
| Redis tuning queue | Implemented |
| Redis telemetry stream | Implemented |
| Micro-batch Redis consumer | Implemented |
| REST telemetry webhook | Implemented |
| Live alert webhook | Implemented |
| Rolling conversion ratios | Implemented |
| Memgraph process/file/network ingestion | Implemented |
| 3-hop GraphRAG extraction | Implemented with native Cypher |
| Memgraph leaf pruning | Implemented foundation |
| LangGraph workflow | Implemented |
| Groq agents | Implemented |
| L0/L1 vs L2/L3 routing | Implemented |
| Mock SIG-001 GraphRAG demo | Verified; attributes and causal edges now serialize |
| Mock L1 classification | Verified |
| Mock Rule Refiner | Verified to generate candidates |
| Double-loop regression | Implemented basic JSON-corpus engine; generated mock refinements may fail pySigma validation |
| Sigma YAML export | Implemented for rules that pass validation |
| Splunk SPL export | Implemented for rules that pass validation |
| Mock SIEM | Implemented |
| Splunk connector | Implemented basic REST foundation |
| Elastic/Wazuh connector | Implemented basic REST foundation |
| SQLite/PostgreSQL execution store | Not implemented |
| SQLAlchemy async persistence | Not implemented |
| Rule version history | Not implemented |
| WebSocket/SSE event bus | Not implemented |
| React/Vue/other dashboard | Not implemented |
| Approval buttons | Not implemented |
| Rule rollback API | Not implemented |
| Live deployment confirmation tracking | Not implemented |
| Full KQL/Lucene deployment | Not implemented |
| Splunk saved-search result polling robustness | Partial |
| Elastic alert field mapping | Partial and deployment-specific |
| Stream delayed-message/retry handling | Partial |
| Redis Stream dead-letter queue | Not implemented |
| Stream pending-entry reclaim | Not implemented |
| Authentication and authorization | Not implemented |
| API key management | Not implemented |
| TLS termination | Not configured |
| Rate limiting | Not implemented |
| Metrics and tracing | Not implemented |
| Docker healthcheck for the core API | Not implemented |
| End-to-end automated test suite | Not implemented |
| Frontend causal graph viewer | Not implemented |

---

## What needs to be implemented

### Priority 1: state persistence

Add [src/storage/](src/storage/) with SQLAlchemy async models and migrations for:

- Execution/run metadata
- Trigger alert metadata
- Extracted subgraph payload
- Correlator output
- Oracle classification
- Refiner iterations
- Loop 1 and Loop 2 results
- Original/refined YAML diff
- Compiled SPL/KQL/Lucene
- Deployment status
- Approvals and rollback history

Recommended states:

```text
PENDING_APPROVAL
DEPLOYED
ROLLED_BACK
ESCALATED
FAILED
```

### Priority 2: real-time event bus

Add `GET /ws/events` with WebSocket broadcast support for:

- `TELEMETRY_INGESTED`
- `ALERT_RECEIVED`
- `RULE_DEGRADED`
- `GRAPHRAG_EXTRACTED`
- `AGENT_CORRELATED`
- `ORACLE_CLASSIFIED`
- `REGRESSION_RESULT`
- `RULE_DEPLOYED`

An SSE fallback can be added for browser or reverse-proxy compatibility.

### Priority 3: analyst command center

Add `frontend/` or mount a FastAPI-served dashboard providing:

- Telemetry and alerts-per-second counters
- Memgraph node/edge counts
- Per-rule conversion-ratio gauges
- Three-hop graph visualization
- Context and Oracle results
- YAML side-by-side diff
- Compiled SPL/KQL/Lucene
- Regression pass/fail evidence
- Approve, Reject, Escalate, and Rollback controls

### Priority 4: safe deployment workflow

Implement:

- Human approval before deployment
- Immutable rule versions
- Pre-deployment validation
- Deployment confirmation from the SIEM
- Automatic rollback on health degradation
- Deployment audit trail
- Least-privilege SIEM credentials

### Priority 5: robust streaming

Implement:

- Reclaim of abandoned pending Redis Stream entries
- Dead-letter queues
- Per-stream metrics
- Backpressure
- Duplicate event detection
- Tombstone handling
- Graceful draining during shutdown
- Configurable max in-flight batches

### Priority 6: regression correctness

Improve the regression engine to:

- Fully execute Sigma conditions instead of using a limited subset
- Support all relevant pySigma modifiers
- Use realistic historical telemetry
- Validate host, PID, process GUID, parent and grandparent lineage
- Compile Elasticsearch and KQL where applicable
- Preserve at least 100% recall in the attack corpus
- Prevent flat wildcard exclusions
- Emit machine-readable feedback traces

### Priority 7: security and operations

Add:

- API authentication and role-based authorization
- Secret rotation support
- TLS and reverse-proxy configuration
- Request size limits
- Input validation and redaction
- Rate limiting
- Prometheus metrics
- OpenTelemetry traces
- Structured audit logging
- Docker core-service healthcheck

### Priority 8: test coverage

Create `tests/` for:

- Telemetry normalization
- Sysmon EID ingestion
- Memgraph Cypher parameter handling
- Redis Stream batching and acknowledgements
- Conversion-ratio thresholds
- Live alert payload extraction
- LangGraph L0/L1 routing
- LangGraph L2/L3 escalation
- Loop 1 false-positive suppression
- Loop 2 recall retention
- Sigma YAML and SPL compilation
- Mock/Splunk/Elastic deployment paths
- Pruning behavior
- API lifespan behavior

---

## Testing

No complete test suite is currently present. Suggested minimum commands:

```powershell
python -m compileall -q src scripts
pytest -q
```

Add pytest-asyncio tests under `tests/` as the persistence and WebSocket features are implemented.

Example validation points:

1. L1 benign SCCM/CcmExec/PowerShell telemetry should route to the refiner.
2. Refined rules should generate zero matches in the benign corpus.
3. Refined rules should preserve all attack-corpus matches.
4. L2/L3 events should change status to `ESCALATED_TO_HUMAN`.
5. Redis Stream entries should be acknowledged once graph ingestion succeeds.
6. Empty or malformed telemetry should be rejected or discarded safely.

---

## Troubleshooting

### FastAPI cannot connect to Redis

Confirm the container network and environment:

```dotenv
REDIS_HOST=redis
REDIS_PORT=6379
```

When running outside Docker, use:

```dotenv
REDIS_HOST=localhost
REDIS_PORT=6379
```

### FastAPI cannot connect to Memgraph

Inside Docker:

```dotenv
MEMGRAPH_HOST=memgraph
MEMGRAPH_PORT=7687
```

Outside Docker:

```dotenv
MEMGRAPH_HOST=localhost
MEMGRAPH_PORT=7687
```

### Groq agent errors

Verify:

```dotenv
GROQ_API_KEY=...
LLM_MODEL_NAME=openai/gpt-oss-120b
```

The model and account must support the configured Groq request. Check API logs for JSON schema or quota errors.

### No subgraph is returned

Confirm:

- The process node exists in Memgraph.
- The host and PID match the graph node.
- The process node was ingested using Sysmon EID 1.
- The graph node's `pid` and `host_id` properties match the query parameters.

### Redis Stream messages are pending

Inspect pending entries:

```powershell
docker exec -it graph_adapt_redis redis-cli XPENDING stream:telemetry:sysmon graph-adapt-ingestors - + 20
```

Pending-reclaim and dead-letter handling must be implemented before production use.

### PostgreSQL port conflict

The Compose file publishes PostgreSQL on host port `5442`, not `5432`, to reduce port conflicts.

---

## Security considerations

- Never commit `.env`, Groq keys, SIEM tokens, or service passwords.
- Do not deploy generated rules without analyst approval.
- Validate every SIEM webhook origin and signature if supported.
- Redact command lines, usernames, IP addresses, and secrets before sending data to external LLM providers.
- Apply strict process-lineage constraints rather than flat wildcard exclusions.
- Protect Redis because it can carry alert metadata and tuning payloads.
- Protect Memgraph because it can contain endpoint, process, identity, and network information.
- Encrypt SIEM and database connections.
- Restrict the Docker and host-mounted source/rules/data directories.
- Add a rollback mechanism before enabling automatic SIEM deployment.
