"""
Graph-ADAPT LangGraph Workflow Orchestrator
Builds and compiles the stateful multi-agent DAG with cyclic retry regression logic.
"""

import logging
import os
from typing import Dict, Any, Literal
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END

from src.agents.schemas import GraphADAPTState
from src.agents.agent_nodes import (
    context_correlator_node,
    exploit_oracle_node,
    rule_refiner_node,
    escalate_human_node
)
from src.graph.graph_builder import CausalProvenanceEngine
from src.testing.regression_engine import DoubleLoopRegressionEngine

load_dotenv()
logger = logging.getLogger("GraphADAPT.Workflow")


# ============================================================================
# Auxiliary Sub-Graph Extractor Node & Regression Node Wrappers
# ============================================================================

def graphrag_extraction_node(state: GraphADAPTState) -> Dict[str, Any]:
    """
    Entry Node: Fetches 3-hop sub-graph from Memgraph if raw_subgraph is missing.
    """
    logger.info(f"[Node: GraphRAG] Fetching causal provenance sub-graph for Rule: {state['rule_id']}")
    
    if state.get("raw_subgraph") is not None:
        logger.info("[Node: GraphRAG] Sub-graph payload already present in state.")
        return {"status": "SUBGRAPH_READY"}

    # Extract seeds from state
    rule_id = state["rule_id"]
    target_host = state.get("test_results", {}).get("target_host", "WIN-SEC-WORKSTATION-01")
    seed_pid = state.get("test_results", {}).get("seed_pid", 4108)

    try:
        graph_engine = CausalProvenanceEngine()
        subgraph = graph_engine.retrieve_3hop_subgraph(
            hostname=target_host,
            pid=seed_pid,
            rule_id=rule_id
        )
        
        if not subgraph:
            logger.error("[Node: GraphRAG] Failed to extract sub-graph from Memgraph.")
            return {"status": "FAILED_MISSING_DATA", "error_feedback": "Sub-graph extraction returned empty."}

        return {"raw_subgraph": subgraph, "status": "SUBGRAPH_READY"}
    except Exception as e:
        logger.error(f"[Node: GraphRAG] Retrieval Exception: {e}")
        return {"status": "FAILED_GRAPH_ERROR", "error_feedback": f"GraphRAG exception: {str(e)}"}


def double_loop_regression_node(state: GraphADAPTState) -> Dict[str, Any]:
    """
    Circuit Breaker Node: Validates refined rule against Loop 1 (Noise) and Loop 2 (Attack).
    """
    logger.info(f"[Node: RegressionTester] Executing Double-Loop testing for Rule: {state['rule_id']}")
    
    current_yaml = state.get("current_sigma_yaml")
    if not current_yaml:
        return {"status": "FAILED_MISSING_DATA", "error_feedback": "Missing current_sigma_yaml to test."}

    engine = DoubleLoopRegressionEngine()
    passed, loop_failed, feedback_msg = engine.evaluate_rule_regression(
        rule_id=state["rule_id"],
        refined_yaml=current_yaml
    )

    if passed:
        logger.info(f"[Node: RegressionTester] Rule {state['rule_id']} PASSED both regression loops!")
        return {
            "status": "PASSED_REGRESSION",
            "error_feedback": None
        }
    else:
        iteration = state.get("iteration", 1)
        logger.warning(f"[Node: RegressionTester] Rule {state['rule_id']} FAILED Loop {loop_failed}. Feedback: {feedback_msg}")
        
        # Check iteration threshold
        max_retries = int(os.getenv("MAX_REGRESSION_RETRIES", 3))
        if iteration > max_retries:
            logger.error(f"[Node: RegressionTester] Max retries ({max_retries}) exceeded.")
            return {
                "status": "MAX_RETRIES_EXCEEDED",
                "error_feedback": f"Failed after {max_retries} attempts. Last error: {feedback_msg}"
            }
        
        return {
            "status": "FAILED_REGRESSION_RETRYING",
            "error_feedback": feedback_msg
        }


# ============================================================================
# Conditional Edge Router Functions
# ============================================================================

def threat_level_router(state: GraphADAPTState) -> Literal["rule_refiner", "escalate_human"]:
    """Routes state based on Exploit Oracle threat tier (L0/L1 -> Refiner, L2/L3 -> Human)."""
    status = state.get("status")
    if status == "REFRACTORING":
        return "rule_refiner"
    return "escalate_human"


def regression_result_router(state: GraphADAPTState) -> Literal["rule_refiner", "escalate_human", "__end__"]:
    """Routes state based on Double-Loop circuit breaker test results."""
    status = state.get("status")
    if status == "PASSED_REGRESSION":
        return END
    elif status == "FAILED_REGRESSION_RETRYING":
        return "rule_refiner"
    else: # MAX_RETRIES_EXCEEDED or ERROR
        return "escalate_human"


# ============================================================================
# LangGraph Workflow Assembly & Compilation
# ============================================================================

def build_graph_adapt_workflow():
    """Assembles and compiles the Graph-ADAPT LangGraph StateGraph."""
    workflow = StateGraph(GraphADAPTState)

    # 1. Add Nodes
    workflow.add_node("graphrag_extractor", graphrag_extraction_node)
    workflow.add_node("context_correlator", context_correlator_node)
    workflow.add_node("exploit_oracle", exploit_oracle_node)
    workflow.add_node("rule_refiner", rule_refiner_node)
    workflow.add_node("regression_tester", double_loop_regression_node)
    workflow.add_node("escalate_human", escalate_human_node)

    # 2. Set Entry Point
    workflow.set_entry_point("graphrag_extractor")

    # 3. Define Standard Edges
    workflow.add_edge("graphrag_extractor", "context_correlator")
    workflow.add_edge("context_correlator", "exploit_oracle")

    # 4. Define Conditional Edges
    workflow.add_conditional_edges(
        "exploit_oracle",
        threat_level_router,
        {
            "rule_refiner": "rule_refiner",
            "escalate_human": "escalate_human"
        }
    )

    workflow.add_edge("rule_refiner", "regression_tester")

    workflow.add_conditional_edges(
        "regression_tester",
        regression_result_router,
        {
            END: END,
            "rule_refiner": "rule_refiner",
            "escalate_human": "escalate_human"
        }
    )

    workflow.add_edge("escalate_human", END)

    # Compile app
    app = workflow.compile()
    logger.info("Graph-ADAPT LangGraph workflow compiled successfully.")
    return app


# Compiled application instance ready for import in main.py
graph_adapt_app = build_graph_adapt_workflow()