import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.graph.graph_builder import CausalProvenanceEngine

def seed():
    base_dir = Path(__file__).resolve().parent.parent
    noise_file = base_dir / "data" / "raw_logs" / "background_noise_48h.json"

    with open(noise_file, "r", encoding="utf-8") as f:
        logs = json.load(f)

    # 1. Grandparent: Windows Service Control Manager (services.exe, PID 680)
    services_grandparent_event = {
        "Event": {
            "System": {"EventID": 1, "Computer": "WIN-SEC-WORKSTATION-01"},
            "EventData": {
                "UtcTime": "2026-10-10 07:59:00.000",
                "ProcessGuid": "{A1B2C3D4-0001-0001-0001-000000000680}",
                "ProcessId": "680",
                "Image": "C:\\Windows\\System32\\services.exe",
                "CommandLine": "C:\\Windows\\system32\\services.exe",
                "IntegrityLevel": "System",
                "User": "NT AUTHORITY\\SYSTEM",
                "ParentProcessGuid": "{A1B2C3D4-0001-0001-0001-000000000500}",
                "ParentProcessId": "500",
                "ParentImage": "C:\\Windows\\System32\\wininit.exe"
            }
        }
    }

    # 2. Parent: Microsoft SCCM Client Executive (CcmExec.exe, PID 2104)
    sccm_parent_event = {
        "Event": {
            "System": {"EventID": 1, "Computer": "WIN-SEC-WORKSTATION-01"},
            "EventData": {
                "UtcTime": "2026-10-10 08:00:00.000",
                "ProcessGuid": "{A1B2C3D4-0001-0001-0001-000000002104}",
                "ProcessId": "2104",
                "Image": "C:\\Windows\\CCM\\CcmExec.exe",
                "CommandLine": "C:\\Windows\\CCM\\CcmExec.exe",
                "IntegrityLevel": "System",
                "User": "NT AUTHORITY\\SYSTEM",
                "ParentProcessGuid": "{A1B2C3D4-0001-0001-0001-000000000680}",
                "ParentProcessId": "680",
                "ParentImage": "C:\\Windows\\System32\\services.exe"
            }
        }
    }

    engine = CausalProvenanceEngine()
    # Clear old partial nodes first so the graph is clean
    engine.db.execute_query("MATCH (n) DETACH DELETE n")
    engine.process_sysmon_log_batch([services_grandparent_event, sccm_parent_event] + logs)
    print("Memgraph seeded cleanly with services.exe -> CcmExec.exe -> powershell.exe!")

if __name__ == "__main__":
    seed()