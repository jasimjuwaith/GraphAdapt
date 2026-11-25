"""
Graph-ADAPT Asynchronous Gatekeeper Evaluator
Deterministic service that monitors SIEM rule performance metrics against 
Analyst Case Management dispositions. Queues degraded rules for autonomous tuning.

Criteria for degradation (configurable in .env):
1. Incident Conversion Ratio (Tr) >= THETA_THRESHOLD (Default: 15.0)
   WHERE Tr = Total Alerts / True Incidents
OR
2. Raw False Positive count >= MAX_FP_24H (Default: 20)
"""

import os
import json
import logging
import requests
import redis
from datetime import datetime, timedelta
from dotenv import load_dotenv
from src.gatekeeper.siem_connectors import get_siem_connector

# Import Schemas from Batch 1 (if available locally, else assumed in container)
try:
    from src.agents.schemas import NodeEntity
except ImportError:
    NodeEntity = None # Fallback if schematic verification is handled elsewhere

# Load configuration
load_dotenv()

# Configure Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("GraphADAPT.Gatekeeper")

# Disable SSL warnings for internal self-signed certs if configured
if os.getenv("SIEM_VERIFY_SSL", "true").lower() == "false":
    requests.packages.urllib3.disable_warnings()


class SplunkAPIIntegrator:
    """Handles authenticated queries to SIEM and SOAR Case Management APIs."""
    
    def __init__(self):
        # SIEM Config (e.g., Wazuh)
        self.siem_url = os.getenv("SIEM_API_URL")
        self.siem_headers = {"Authorization": f"Bearer {os.getenv('SIEM_API_KEY')}"}
        self.siem_verify = os.getenv("SIEM_VERIFY_SSL", "true").lower() == "true"
        
        # SOAR/Case Management Config (e.g., TheHive)
        self.soar_url = os.getenv("CASE_MANAGEMENT_API_URL")
        self.soar_headers = {"Authorization": f"Bearer {os.getenv('CASE_MANAGEMENT_API_KEY')}"}
        self.soar_verify = os.getenv("CASE_VERIFY_SSL", "true").lower() == "true"

    def get_performance_metrics(self, rule_id: str, window_hours: int = 24) -> tuple[int, int]:
        """
        Queries APIs to count total alerts vs confirmed human incidents.
        Returns: (total_alerts, true_incidents)
        """
        logger.debug(f"Querying performance metrics for rule {rule_id} over last {window_hours}h")
        
        # Calculate time boundary
        time_limit = (datetime.utcnow() - timedelta(hours=window_hours)).isoformat()

        # 1. PLACEHOLDER: SIEM API Query for Total Alerts
        # Example Wazuh API: GET /alerts?search=rule_id:{rule_id}&confirmed=all
        try:
            # sim_response = requests.get(
            #     f"{self.siem_url}/alerts/count", 
            #     headers=self.siem_headers, 
            #     params={"rule_id": rule_id, "after": time_limit},
            #     verify=self.siem_verify
            # )
            # total_alerts = sim_response.json().get('data', {}).get('count', 0)
            
            # For local reproducibility without active SIEM, simulate high volume noise:
            logger.warning("Using SIMULATED SIEM metrics. Integrate actual REST API in production.")
            total_alerts = 100 # Simulated: Rule fired 100 times

        except Exception as e:
            logger.error(f"Failed to query SIEM API: {e}")
            total_alerts = 0

        # 2. PLACEHOLDER: Case Management API Query for Confirmed TRUE_POSITIVES
        # Example TheHive API: POST /api/case/search {"query": {"_and": [{"_field": "rule_id", "_value": "{rule_id}"}, {"_field": "tags", "_value": "disposition:TRUE_POSITIVE"}]}}
        try:
            # soar_response = requests.post(
            #     f"{self.soar_url}/api/case/count",
            #     headers=self.soar_headers,
            #     json={"rule_id": rule_id, "status": "Resolved", "disposition": "TruePositive", "after": time_limit},
            #     verify=self.soar_verify
            # )
            # true_incidents = soar_response.json().get('count', 0)
            
            # For local reproducibility, simulate low true incident count:
            true_incidents = 2 # Simulated: Only 2 out of 100 alerts were real attacks

        except Exception as e:
            logger.error(f"Failed to query SOAR API: {e}")
            true_incidents = 0

        return total_alerts, true_incidents

    def get_seed_alert_metadata(self, rule_id: str) -> tuple[str, int, str]:
        """
        Retrieves necessary metadata from the LATEST alert log to seed GraphRAG.
        Returns: (hostname, pid, rule_title)
        """
        logger.debug(f"Retrieving seed metadata for rule {rule_id}...")
        
        # 3. PLACEHOLDER: SIEM API Query for latest raw alert log
        try:
            # response = requests.get(
            #     f"{self.siem_url}/alerts",
            #     headers=self.siem_headers,
            #     params={"rule_id": rule_id, "limit": 1, "sort": "timestamp:desc"},
            #     verify=self.siem_verify
            # )
            # latest_alert = response.json().get('data', {}).get('items', [{}])[0]
            # data = latest_alert.get('_source', {}) # Assuming JSON structure

            # hostname = data.get('agent', {}).get('name') or data.get('win', {}).get('system', {}).get('computer')
            # pid = data.get('win', {}).get('eventdata', {}).get('processId')
            # rule_title = latest_alert.get('rule', {}).get('description')

            # For local reproducibility, simulate a common noisy endpoint scenario:
            logger.warning("Using SIMULATED seed metadata (SCCM Example).")
            hostname = "WIN-SEC-WORKSTATION-01"
            pid = 4108 # The PID of the noisy process (e.g., PowerShell)
            rule_title = "Suspicious Encoded PowerShell Execution"

        except Exception as e:
            logger.error(f"Failed to retrieve seed metadata from SIEM: {e}")
            raise # Cannot proceed without seed data

        if not hostname or not pid:
            raise ValueError(f"Incomplete seed metadata for rule {rule_id}. Host:{hostname}, PID:{pid}")

        return hostname, int(pid), rule_title


class AsynchronousGatekeeper:
    """
    Main Gatekeeper Service. Performs arithmetic evaluation 
    and publishes to Redis queue.
    """
    
    def __init__(self):
        self.ops = get_siem_connector()
        
        # Redis connection to the Tuning Queue
        self.r = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            db=0,
            decode_responses=True
        )
        self.queue_name = "queue:adapt:degraded_rules"
        
        # Configurable thresholds
        self.theta = float(os.getenv("GATEKEEPER_THETA_THRESHOLD", 15.0))
        self.max_fp = int(os.getenv("GATEKEEPER_MAX_FP_24H", 20))

    def evaluate_rule(self, rule_id: str):
        """Perform deterministic mathematical evaluation of a detection rule."""
        logger.info(f"--- Evaluating Rule: {rule_id} ---")
        
        # 1. Get performance counters from operational APIs
        alerts, incidents = self.ops.get_performance_metrics(rule_id)
        logger.info(f"Performance (24h): Alerts={alerts}, Confirmed Incidents={incidents}")

        if alerts == 0:
            logger.info("Rule is healthy (0 alerts). Discarding.")
            return

        # 2. Arithmetic Evaluation

        # Handle division by zero fallback. If alerts > max_fp but 0 incidents, 
        # rule is definitionally degraded.
        denom = max(1, incidents)
        conversion_ratio = alerts / denom
        
        logger.info(f"Calculated Conversion Ratio (Tr): {conversion_ratio:.2f} (Threshold Theta: {self.theta})")

        # 3. Decision Logic
        is_degraded = False
        reason = ""

        if conversion_ratio >= self.theta:
            is_degraded = True
            reason = f"Tr ratio {conversion_ratio:.2f} >= threshold {self.theta}"
        elif alerts >= self.max_fp and incidents == 0:
            is_degraded = True
            reason = f"False positive count {alerts} >= max threshold {self.max_fp} with 0 incidents"

        # 4. Action
        if is_degraded:
            logger.warning(f"RULE DEGRADED: {rule_id}. Reason: {reason}. Queuing for autonomous tuning.")
            self._queue_for_tuning(rule_id, conversion_ratio, alerts)
        else:
            logger.info(f"Rule {rule_id} is healthy (Conversion Ratio acceptable). No action required.")

    def _queue_for_tuning(self, rule_id: str, ratio: float, total_alerts: int):
        """Collects seed metadata and publishes payload to Redis queue."""
        try:
            # Retrieve latest host/PID context needed by GraphRAG
            seed = self.ops.get_seed_alert_metadata(rule_id)
            hostname, pid, title = seed[0], seed[1], seed[2]
            process_guid = seed[3] if len(seed) > 3 else None
            
            # Construct JSON Payload contract for the Graph Engine (Batch 2)
            payload = {
                "rule_id": rule_id,
                "rule_title": title,
                "trigger_timestamp": datetime.utcnow().isoformat() + "Z",
                "conversion_ratio": round(ratio, 2),
                "recent_alerts_count_24h": total_alerts,
                # GraphRAG Seeds
                "target_host": hostname,
                "seed_pid": pid,
                "process_guid": process_guid,
                "retry_iteration": 1 # Initial attempt
            }
            
            # Publish to Redis LPUSH (Left Push, creating FIFO queue)
            queue_len = self.r.lpush(self.queue_name, json.dumps(payload))
            logger.info(f"Successfully queued degraded rule payload in Redis. Queue length: {queue_len}")
            logger.debug(f"Payload: {json.dumps(payload, indent=2)}")

        except Exception as e:
            logger.error(f"Critcal failure during queuing action for {rule_id}: {e}")
            # Potential Future Work: Implement dead-letter queue or metric increment
            return


if __name__ == "__main__":
    # Example standalone execution. 
    # In production, this might be triggered per SOAR webhook 
    # or run periodically via Cron/Celery worker.
    load_dotenv()
    
    # ID of the stock "Suspicious Encoded PowerShell" Sigma rule commonly noisy with SCCM
    DEMO_RULE_ID = "sigma-powershell-encoded-cmd-001"
    
    gatekeeper = AsynchronousGatekeeper()
    
    # Add a delay for Redis healthcheck inside docker if necessary
    import time
    time.sleep(1) 
    
    gatekeeper.evaluate_rule(DEMO_RULE_ID)