import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from src.graph.graph_builder import MemgraphConnector
from src.graph.cypher_queries import PRUNE_BENIGN_LEAF_NODES


logger = logging.getLogger("GraphADAPT.GraphPruner")


async def graph_pruning_loop(stop_event: asyncio.Event) -> None:
    interval_seconds = int(os.getenv("GRAPH_PRUNE_INTERVAL_SECONDS", 3600))
    retention_hours = int(os.getenv("GRAPH_RETENTION_HOURS", 72))

    while not stop_event.is_set():
        try:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(hours=retention_hours)
            ).isoformat()
            connector = MemgraphConnector()
            connector.execute_query(
                PRUNE_BENIGN_LEAF_NODES,
                {"cutoff": cutoff},
            )
            logger.info("Graph pruning cycle complete; cutoff=%s", cutoff)
        except Exception as exc:
            logger.error("Graph pruning failed: %s", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass
