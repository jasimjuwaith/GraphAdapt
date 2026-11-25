"""
Graph-ADAPT Causal Provenance Engine
Handles parsing of Sysmon JSON telemetry, ingestion into Memgraph DAG,
and GraphRAG subgraph extraction for LangGraph agents.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dotenv import load_dotenv
from gqlalchemy import Memgraph

# Import Schemas discussed in Batch 1
from src.agents.schemas import (
    SubGraphPayload, NodeEntity, EdgeRelationship
)
from src.graph.cypher_queries import (
    INGEST_PROCESS_CREATE,
    INGEST_FILE_CREATE,
    INGEST_NETWORK_CONNECT,
    GRAPHRAG_EXTRACT_3HOP_SUBGRAPH,
    PRUNE_BENIGN_LEAF_NODES,
)

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("GraphADAPT.GraphBuilder")


class MemgraphConnector:
    """Manages authenticated connection persistence to Memgraph DB."""
    def __init__(self):
        self.host = os.getenv("MEMGRAPH_HOST", "localhost")
        self.port = int(os.getenv("MEMGRAPH_PORT", 7687))
        self.username = os.getenv("MEMGRAPH_USER")
        self.password = os.getenv("MEMGRAPH_PASSWORD")
        self.driver = None
        self.connect()

    def connect(self):
        try:
            self.driver = Memgraph(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password
            )
            logger.info(f"Connected to Memgraph at {self.host}:{self.port} as '{self.username}'")
        except Exception as e:
            logger.error(f"Failed to connect to Memgraph: {e}")
            raise

    def execute_query(self, query: str, parameters: Dict[str, Any] = None):
        if not self.driver:
            self.connect()
        params = parameters if parameters is not None else {}
        try:
            if "RETURN" in query.upper():
                return list(self.driver.execute_and_fetch(query, params))
            else:
                self.driver.execute(query, params)
                return []
        except Exception as e:
            logger.error(f"Cypher Execution Error: {repr(e)}\nQuery: {query}\nParams: {params}")
            return None


class CausalProvenanceEngine:
    """Handles parsing, ingestion, and GraphRAG retrieval."""
    
    def __init__(self):
        self.db = MemgraphConnector()

    # ========================================================================
    # 1. Parsing & Ingestion (EIDs -> Cypher)
    # ========================================================================

    def process_sysmon_log_batch(self, log_batch: List[Dict[str, Any]]):
        """Parses and ingests a batch of Sysmon logs."""
        logger.info(f"Processing batch of {len(log_batch)} Sysmon logs...")
        for log in log_batch:
            try:
                # Ensure it's a Sysmon event with necessary data
                if 'Event' not in log or 'System' not in log['Event']:
                    continue
                
                system_data = log['Event']['System']
                event_id = int(system_data['EventID'])
                host_id = system_data['Computer']
                event_data = log['Event']['EventData']

                # Map Sysmon EID to OCSF Graph Schema
                if event_id == 1:
                    self._ingest_process_create(host_id, event_data)
                elif event_id == 11:
                    self._ingest_file_create(host_id, system_data, event_data)
                elif event_id == 3:
                    self._ingest_network_connect(host_id, system_data, event_data)
                
            except Exception as e:
                logger.warning(f"Error parsing single log line: {e}")
                continue

    def prune_benign_leaves(self, cutoff: str) -> None:
        self.db.execute_query(PRUNE_BENIGN_LEAF_NODES, {"cutoff": cutoff})

    def _generate_process_guid(self, host: str, pid: str, create_time: str) -> str:
        """Generates unique deterministic ID for Process nodes to handle PID reuse."""
        # Simple concatenation for reproducibility. In production, use hashing.
        return f"{host}:{pid}:{create_time}"

    def _ingest_process_create(self, host: str, data: Dict[str, Any]):
        """Parses Sysmon EID 1 (Process Create)."""
        # Parse Times
        utc_time_str = data.get('UtcTime', datetime.utcnow().isoformat())
        
        # Parent GUID
        parent_pid = data['ParentProcessId']
        parent_create_time = data.get('ParentProcessGuid', 'unknown') # Guid contains time
        p_guid = self._generate_process_guid(host, parent_pid, parent_create_time)
        
        # Child GUID
        child_pid = data['ProcessId']
        child_create_time = data.get('ProcessGuid', 'unknown')
        c_guid = self._generate_process_guid(host, child_pid, child_create_time)

        # SID Mapping
        user_sid = data['User']
        u_sid_id = f"{host}:UserSid:{user_sid}"

        # Setup parameters for INGEST_PROCESS_CREATE query
        params = {
            # User
            "user_sid_id": u_sid_id,
            "user_domain": data.get('User').split('\\')[0] if '\\' in data.get('User', '') else 'Local',
            "user_name": data.get('User').split('\\')[-1],
            "user_is_admin": data.get('IntegrityLevel') == 'High' or data.get('IntegrityLevel') == 'System',
            # Parent
            "parent_id": p_guid,
            "parent_pid": int(parent_pid),
            "host_id": host,
            # Child
            "child_id": c_guid,
            "child_pid": int(child_pid),
            "child_image": data['Image'],
            "child_image_endswith": os.path.basename(data['Image']),
            "child_cmd": data.get('CommandLine', ''),
            "child_time": utc_time_str,
            "child_integrity": data.get('IntegrityLevel', 'Unknown')
        }

        self.db.execute_query(INGEST_PROCESS_CREATE, params)

    def _ingest_file_create(self, host: str, sys: Dict[str, Any], data: Dict[str, Any]):
        """Parses Sysmon EID 11 (File Create)."""
        proc_pid = data['ProcessId']
        proc_guid = data.get('ProcessGuid', 'unknown')
        p_guid = self._generate_process_guid(host, proc_pid, proc_guid)
        
        file_path = data['TargetFilename']
        f_guid = f"{host}:File:{file_path}"
        
        params = {
            "proc_id": p_guid,
            "proc_pid": int(proc_pid),
            "host_id": host,
            "file_id": f_guid,
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_ext": os.path.splitext(file_path)[-1],
            "file_hash": data.get('Hashes', 'SHA256=Unknown').split('SHA256=')[-1].split(',')[0],
            "timestamp": data.get('UtcTime', sys.get('TimeCreated', {}).get('@SystemTime')),
            "event_id": sys['EventRecordID']
        }
        self.db.execute_query(INGEST_FILE_CREATE, params)

    def _ingest_network_connect(self, host: str, sys: Dict[str, Any], data: Dict[str, Any]):
        """Parses Sysmon EID 3 (Network Connection)."""
        proc_pid = data['ProcessId']
        proc_guid = data.get('ProcessGuid', 'unknown')
        p_guid = self._generate_process_guid(host, proc_pid, proc_guid)
        
        dest_ip = data['DestinationIp']
        
        # Simple RFC1918 check
        is_internal = dest_ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))

        params = {
            "proc_id": p_guid,
            "proc_pid": int(proc_pid),
            "host_id": host,
            "dest_ip": dest_ip,
            "is_internal": is_internal,
            "timestamp": data.get('UtcTime', sys.get('TimeCreated', {}).get('@SystemTime')),
            "dest_port": int(data['DestinationPort']),
            "protocol": data.get('Protocol', 'tcp')
        }
        self.db.execute_query(INGEST_NETWORK_CONNECT, params)

    # ========================================================================
    # 2. GraphRAG Subgraph Extraction (Cypher -> Pydantic)
    # ========================================================================

    def retrieve_3hop_subgraph(self, hostname: str, pid: int, rule_id: str) -> Optional[SubGraphPayload]:
        """Executes depth-bounded Cypher traversal and serializes into SubGraphPayload."""
        logger.info(f"Executing GraphRAG for PID {pid} on host {hostname} (Rule: {rule_id})")
        results = self.db.execute_query(
            GRAPHRAG_EXTRACT_3HOP_SUBGRAPH,
            {"target_pid": pid, "target_host": hostname}
        )

        if not results:
            logger.warning(f"No subgraph returned for PID {pid} on {hostname}")
            return None

        parsed_nodes: List[NodeEntity] = []
        parsed_edges: List[EdgeRelationship] = []
        seen_node_ids = set()
        seen_edges = set()
        internal_id_to_logical_id: Dict[int, str] = {}
        valid_labels = {"Process", "File", "UserToken", "IPAddress"}
        valid_rels = {"SPAWNED", "WRITTEN_TO", "AUTHENTICATED_AS", "CONNECTED_TO"}

        def get_props(value: Any) -> Dict[str, Any]:
            if value is None:
                return {}
            if hasattr(value, "_properties"):
                return dict(value._properties or {})
            if hasattr(value, "properties"):
                return dict(value.properties or {})
            if isinstance(value, dict):
                nested = value.get("n")
                if nested is not None:
                    return get_props(nested)
                nested = value.get("properties")
                if isinstance(nested, dict):
                    return dict(nested)
                return dict(value)
            return {}

        def get_id(value: Any) -> Optional[str]:
            props = get_props(value)
            if props.get("id"):
                return str(props["id"])
            if hasattr(value, "_id"):
                return str(value._id)
            if hasattr(value, "id"):
                return str(value.id)
            return None

        def get_labels(value: Any) -> List[str]:
            if hasattr(value, "_labels"):
                return list(value._labels)
            if hasattr(value, "labels"):
                return list(value.labels)
            if isinstance(value, dict):
                labels = value.get("labels") or []
                return list(labels)
            return []

        def get_rel_type(value: Any) -> Optional[str]:
            if hasattr(value, "_type"):
                rel_type = getattr(value, "_type", None)
                if rel_type:
                    return str(rel_type)
            if hasattr(value, "type"):
                return str(value.type)
            if isinstance(value, dict):
                return value.get("relationship") or value.get("type")
            return None

        def get_rel_endpoints(rel: Any) -> tuple[Optional[str], Optional[str]]:
            if hasattr(rel, "_nodes"):
                nodes = getattr(rel, "_nodes", None)
                if isinstance(nodes, tuple) and len(nodes) == 2:
                    return (
                        internal_id_to_logical_id.get(nodes[0]),
                        internal_id_to_logical_id.get(nodes[1]),
                    )
            if hasattr(rel, "_start_node_id") and hasattr(rel, "_end_node_id"):
                start_id = getattr(rel, "_start_node_id", None)
                end_id = getattr(rel, "_end_node_id", None)
                if start_id is not None and end_id is not None:
                    # Resolve logical node IDs from the already-parsed node map.
                    return str(start_id), str(end_id)
            if hasattr(rel, "start_node") and hasattr(rel, "end_node"):
                return get_id(rel.start_node), get_id(rel.end_node)
            if isinstance(rel, dict):
                return rel.get("source_id"), rel.get("target_id")
            return None, None

        for record in results:
            record_dict = dict(record) if not isinstance(record, dict) else record
            for key in ("root", "ancestor", "child", "seed_ctx", "ctx_node"):
                node = record_dict.get(key)
                logical_id = get_id(node)
                if node is None or not logical_id or logical_id in seen_node_ids:
                    continue
                labels = get_labels(node)
                node_label = next(
                    (label for label in labels if label in valid_labels),
                    "Process",
                )
                seen_node_ids.add(logical_id)
                internal_id = getattr(node, "_id", None)
                if internal_id is not None:
                    internal_id_to_logical_id[int(internal_id)] = logical_id
                parsed_nodes.append(
                    NodeEntity(
                        node_id=logical_id,
                        label=node_label,
                        attributes=get_props(node),
                    )
                )

            for key in ("spawn_rel", "seed_rel", "ctx_rel"):
                rel = record_dict.get(key)
                rel_type = get_rel_type(rel)
                if rel_type not in valid_rels:
                    continue
                source_id, target_id = get_rel_endpoints(rel)
                if not source_id or not target_id:
                    continue
                edge_key = (source_id, rel_type, target_id)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    parsed_edges.append(
                        EdgeRelationship(
                            source_id=source_id,
                            target_id=target_id,
                            relationship=rel_type,
                        )
                    )

        return SubGraphPayload(
            root_pid=pid,
            target_host=hostname,
            trigger_rule_id=rule_id,
            nodes=parsed_nodes,
            edges=parsed_edges
        )