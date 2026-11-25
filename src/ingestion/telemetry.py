import asyncio
import json
import logging
import os
from typing import Any, Dict, Iterable, List

import redis.asyncio as aioredis

from src.graph.graph_builder import CausalProvenanceEngine


logger = logging.getLogger("GraphADAPT.Telemetry")
TELEMETRY_STREAM = "stream:telemetry:sysmon"
CONSUMER_GROUP = "graph-adapt-ingestors"
CONSUMER_NAME = "ingestor-1"


def normalize_telemetry_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes Sysmon XML-JSON, OCSF, WEF, and flat Winlogbeat payloads."""
    if "Event" in raw and isinstance(raw["Event"], dict):
        return raw

    event = raw.get("event", raw)
    system = raw.get("winlog", {}).get("event_data", {})
    if isinstance(system, dict) and system:
        event_data = {
            key: value
            for key, value in system.items()
            if value is not None
        }
    else:
        event_data = raw.get("EventData", raw.get("event_data", {}))

    winlog = raw.get("winlog", {})
    system_block = raw.get("System", {})
    event_id = (
        winlog.get("event_id")
        or raw.get("event_id")
        or raw.get("EventID")
        or system_block.get("EventID")
        or raw.get("class_uid")
    )
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = None

    computer = (
        raw.get("host", {}).get("name")
        if isinstance(raw.get("host"), dict)
        else raw.get("host")
        or winlog.get("computer_name")
        or raw.get("computer_name")
        or raw.get("Computer")
        or system_block.get("Computer")
        or "unknown-host"
    )

    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "Computer": computer,
                "TimeCreated": {
                    "@SystemTime": raw.get("@timestamp", raw.get("timestamp"))
                },
                "EventRecordID": raw.get("event", {}).get("sequence")
                if isinstance(raw.get("event"), dict)
                else raw.get("event_id", 0),
            },
            "EventData": event_data,
        }
    }


class TelemetryStreamConsumer:
    def __init__(
        self,
        redis_client: aioredis.Redis,
        batch_size: int = 100,
        flush_seconds: float = 0.5,
    ):
        self.redis = redis_client
        self.batch_size = batch_size
        self.flush_seconds = flush_seconds
        self.running = False

    async def start(self) -> None:
        self.running = True
        try:
            await self.redis.xgroup_create(
                TELEMETRY_STREAM,
                CONSUMER_GROUP,
                id="0",
                mkstream=True,
            )
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        logger.info(
            "Started telemetry stream consumer %s at %s",
            CONSUMER_NAME,
            TELEMETRY_STREAM,
        )

        while self.running:
            entries = await self.redis.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=CONSUMER_NAME,
                streams={TELEMETRY_STREAM: ">"},
                count=self.batch_size,
                block=int(self.flush_seconds * 1000),
            )
            if not entries:
                continue

            batch: List[Dict[str, Any]] = []
            delivery_ids: List[Any] = []
            for _, messages in entries:
                for message_id, fields in messages:
                    delivery_ids.append(message_id)
                    raw_text = fields.get("payload") or fields.get("event")
                    if raw_text:
                        try:
                            batch.append(normalize_telemetry_event(json.loads(raw_text)))
                        except json.JSONDecodeError:
                            logger.warning("Discarding invalid JSON telemetry record")

            if batch:
                engine = CausalProvenanceEngine()
                await asyncio.to_thread(engine.process_sysmon_log_batch, batch)
                for message_id in delivery_ids:
                    await self.redis.xack(
                        TELEMETRY_STREAM,
                        CONSUMER_GROUP,
                        message_id,
                    )

    async def stop(self) -> None:
        self.running = False
