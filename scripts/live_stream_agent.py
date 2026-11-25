import argparse
import json
import os
import random
import time
from datetime import datetime, timezone

import requests
import redis


STREAM_NAME = "stream:telemetry:sysmon"


def sample_event(index: int) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    host = os.getenv("DEMO_HOSTNAME", "WIN-SEC-WORKSTATION-01")
    pid = 4108 + (index % 20)
    return {
        "@timestamp": now,
        "host": {"name": host},
        "winlog": {
            "computer_name": host,
            "event_id": 1,
            "event_data": {
                "UtcTime": now,
                "ProcessGuid": f"{{{host}-{pid}-{index}}}",
                "ProcessId": str(pid),
                "ParentProcessGuid": "{services.exe}",
                "ParentProcessId": "700",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\SCCM\\inventory.ps1",
                "ParentImage": "C:\\Windows\\CCM\\CcmExec.exe",
                "User": "NT AUTHORITY\\SYSTEM",
                "IntegrityLevel": "System",
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Graph-ADAPT live telemetry replay agent")
    parser.add_argument("--url", default=os.getenv("GRAPH_ADAPT_URL", "http://localhost:8000"))
    parser.add_argument("--mode", choices=("webhook", "redis"), default="webhook")
    parser.add_argument("--rate", type=float, default=10.0, help="Events per second")
    parser.add_argument("--count", type=int, default=1000)
    args = parser.parse_args()

    redis_client = None
    if args.mode == "redis":
        redis_client = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=0,
            decode_responses=True,
        )

    interval = 1.0 / max(args.rate, 0.1)
    for index in range(args.count):
        event = sample_event(index)
        if redis_client is not None:
            redis_client.xadd(
                STREAM_NAME,
                {"payload": json.dumps(event)},
                maxlen=100000,
                approximate=True,
            )
        else:
            response = requests.post(
                f"{args.url.rstrip('/')}/api/v1/telemetry/ingest",
                json=event,
                timeout=10,
            )
            response.raise_for_status()
        time.sleep(interval)


if __name__ == "__main__":
    main()
