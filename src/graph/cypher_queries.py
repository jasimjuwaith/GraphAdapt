"""
Graph-ADAPT Cypher Query Repository
Defines parameterized Cypher queries for OCSF/Sysmon data ingestion 
and depth-bounded GraphRAG sub-graph extraction.
No APOC procedures or unsupported list comprehensions are required.
"""

# ============================================================================
# 1. Data Ingestion Queries (EQL -> Graph DAG)
# Unique IDs combine host, pid, and creation time to handle PID reuse.
# ============================================================================

# Ingest Process Node and create SPAWNED edge from parent
INGEST_PROCESS_CREATE = """
    // 1. Ensure UserToken node exists
    MERGE (u:UserToken {id: $user_sid_id})
    SET u.domain = $user_domain,
        u.username = $user_name,
        u.is_admin = $user_is_admin

    // 2. Ensure Parent Process exists (might be unknown if created before Sysmon start)
    MERGE (p:Process {id: $parent_id})
    ON CREATE SET p.pid = $parent_pid, p.host_id = $host_id, p.status = 'UNKNOWN'

    // 3. Create/Update Child Process
    MERGE (c:Process {id: $child_id})
    SET c.pid = $child_pid,
        c.host_id = $host_id,
        c.image_path = $child_image,
        c.image_path_endswith = $child_image_endswith,
        c.command_line = $child_cmd,
        c.creation_time = $child_time,
        c.integrity_level = $child_integrity,
        c.status = 'ACTIVE'

    // 4. Create Relationships
    MERGE (p)-[r1:SPAWNED]->(c)
    MERGE (c)-[r2:AUTHENTICATED_AS]->(u)
    SET r1.timestamp = $child_time,
        r2.timestamp = $child_time,
        c.last_seen = $child_time,
        p.last_seen = $child_time,
        u.last_seen = $child_time
"""

# Ingest File Node and WRITTEN_TO edge
INGEST_FILE_CREATE = """
    // 1. Ensure creating Process exists
    MERGE (p:Process {id: $proc_id})
    ON CREATE SET p.pid = $proc_pid, p.host_id = $host_id, p.status = 'UNKNOWN'

    // 2. Create/Merge File Node
    MERGE (f:File {id: $file_id})
    SET f.host_id = $host_id,
        f.file_path = $file_path,
        f.file_name = $file_name,
        f.extension = $file_ext,
        f.hash_sha256 = $file_hash

    // 3. Create relationship
    MERGE (p)-[r:WRITTEN_TO]->(f)
    SET r.timestamp = $timestamp,
        r.event_id = $event_id,
        f.last_seen = $timestamp,
        p.last_seen = $timestamp
"""

# Ingest IPAddress Node and CONNECTED_TO edge
INGEST_NETWORK_CONNECT = """
    // 1. Ensure creating Process exists
    MERGE (p:Process {id: $proc_id})
    ON CREATE SET p.pid = $proc_pid, p.host_id = $host_id, p.status = 'UNKNOWN'

    // 2. Create/Merge Destination IPAddress Node
    MERGE (ip:IPAddress {id: $dest_ip})
    SET ip.is_internal = $is_internal

    // 3. Create relationship
    MERGE (p)-[r:CONNECTED_TO]->(ip)
    SET r.timestamp = $timestamp,
        r.dest_port = $dest_port,
        r.protocol = $protocol,
        ip.last_seen = $timestamp,
        p.last_seen = $timestamp
"""

# ============================================================================
# 2. GraphRAG Sub-Graph Extraction Query
# ============================================================================

# Depth-bounded traversal centered on the misfiring Process ID.
# Walks UP (<SPAWNED) up to 3 hops to capture parent -> grandparent lineage,
# and OUT (AUTHENTICATED_AS, WRITTEN_TO, CONNECTED_TO) for execution context.
GRAPHRAG_EXTRACT_3HOP_SUBGRAPH = """
    MATCH (p:Process {pid: $target_pid, host_id: $target_host})
    OPTIONAL MATCH (ancestor:Process)-[:SPAWNED*1..3]->(p)
    OPTIONAL MATCH (ancestor)-[spawn_rel:SPAWNED]->(child:Process)
    OPTIONAL MATCH (p)-[seed_rel:AUTHENTICATED_AS|WRITTEN_TO|CONNECTED_TO]->(seed_ctx)
    OPTIONAL MATCH (ancestor)-[ctx_rel:AUTHENTICATED_AS|WRITTEN_TO|CONNECTED_TO]->(ctx_node)
    RETURN p AS root,
           ancestor,
           child,
           seed_ctx,
           ctx_node,
           spawn_rel,
           seed_rel,
           ctx_rel
"""

PRUNE_BENIGN_LEAF_NODES = """
    MATCH (n)
    WHERE n.last_seen IS NOT NULL
      AND n.last_seen < $cutoff
      AND (n:Process OR n:File OR n:UserToken OR n:IPAddress)
    OPTIONAL MATCH (n)--(neighbor)
    WITH n, count(neighbor) AS degree
    WHERE degree = 0
    DETACH DELETE n
"""