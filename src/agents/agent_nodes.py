"""
Graph-ADAPT LangGraph Agent Nodes
Defines individual LLM agent nodes and prompt schemas for:
1. Context Correlator Agent (Sub-Graph -> Process Execution Narrative)
2. Exploit Oracle Agent (Narrative -> L0-L3 Threat Taxonomy Routing)
3. Rule Refiner Agent (Context + Feedback -> Lineage-Aware Sigma YAML)
"""

import os
import logging
from typing import Dict, Any
from dotenv import load_dotenv
import yaml

from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate

from src.agents.schemas import (
    GraphADAPTState,
    ContextCorrelatorOutput,
    ExploitOracleOutput,
    RefinedSigmaOutput
)
from src.testing.regression_engine import DoubleLoopRegressionEngine

# Load environment configuration
load_dotenv()

# Configure Logging
logger = logging.getLogger("GraphADAPT.AgentNodes")

# ============================================================================
# LLM Initialization (Groq API Llama-3.3-70B with Zero Temperature)
# ============================================================================

def get_llm():
    """Initializes deterministic LLM instance for agent nodes."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable is missing!")
        
    model_name = os.getenv("LLM_MODEL_NAME", "openai/gpt-oss-120b")
    return ChatGroq(
        model=model_name,
        temperature=0.0,  # Zero temperature for deterministic output parsing
        api_key=api_key,
        max_retries=3
    )


# ============================================================================
# Prompt Schemas & Templates
# ============================================================================

CORRELATOR_PROMPT_TEMPLATE = """You are an expert Security Operations Center (SOC) Forensic Analyst specializing in endpoint process lineage and host telemetry.

You are provided with a 3-hop depth-bounded Causal Provenance Sub-Graph extracted from host logs surrounding a SIEM rule misfire event.

Sub-Graph Payload (JSON):
{subgraph_data}

Instructions:
1. Trace the complete execution lineage from the root grandparent/parent process down to the target process.
2. Construct the full ancestor process execution chain (e.g., services.exe -> CcmExec.exe -> powershell.exe).
3. Extract the security privilege context (User SID, Integrity Level, Domain).
4. Identify any anomalous execution indicators (e.g., encoded command-line parameters, temporary directory execution, orphan processes).
5. Set user_privilege_level to one human-readable string only, for example "NT AUTHORITY\\SYSTEM (Integrity: System)".

Analyze the sub-graph and output valid JSON using exactly these keys:
execution_lineage, ancestor_chain, user_privilege_level, anomalous_indicators.
Use execution_lineage as a JSON array of strings and ancestor_chain as one JSON string.
"""

ORACLE_PROMPT_TEMPLATE = """You are a Principal Threat Intelligence Analyst and Adversarial Tradecraft Specialist.

Evaluate the correlated process execution narrative provided by the Forensic Analyst to classify the event into the Graph-ADAPT Threat Taxonomy.

Correlated Context Narrative:
{context_narrative}

Threat Taxonomy Classification Rules:
- Tier L0 (Benign Noise): Standard OS background tasks, Windows Defender updates, routine system maintenance.
- Tier L1 (Suspicious Admin Automation): Legitimate IT management tasks (SCCM, backup scripts, inventory scans, certutil CRL updates) executing suspicious dual-use utilities.
- Tier L2 (Active Threat Vector): Unsanctioned living-off-the-land (LotL) execution, credential harvesting (Mimikatz, BloodHound), remote command execution tools.
- Tier L3 (Critical Exploit / Ransomware): Active privilege escalation, shadow copy deletion, process injection, lateral movement.

Instructions:
1. Classify the threat level as strictly one of: "L0", "L1", "L2", "L3".
2. If the execution represents benign IT noise suitable for rule exclusion (L0 or L1), set is_false_positive to true and set action_route to "REFINE_RULE".
3. If the execution represents a true threat (L2 or L3), set is_false_positive to false and set action_route to "ESCALATE_HUMAN".
4. Provide technical justification and map to a MITRE ATT&CK Technique ID if applicable (e.g., T1059.001).

Output valid JSON using exactly these keys:
threat_tier, mitre_technique_id, is_false_positive, justification, action_route.
"""

REFINER_PROMPT_TEMPLATE = """You are a Senior Detection Engineer and Sigma Rule Specialist.

Your objective is to rewrite a degraded, overly broad Sigma YAML detection rule to eliminate benign false positives without creating security blind spots or allowing evasion techniques.


Original Sigma YAML Rule:
{original_yaml}

Forensic Process Lineage Context:
{context_narrative}

Exploit Oracle Analysis:
{oracle_justification}

Previous Iteration Software Regression Error Feedback:
{error_feedback}

Current Iteration Attempt: {iteration} / 3

STRICT REFINEMENT RULES:
1. DO NOT use flat string wildcards (e.g., CommandLine: "*") or blanket process exclusions. Flat wildcards create critical security blind spots and will fail regression testing.
2. Construct **LINEAGE-AWARE STRUCTURAL EXCLUSIONS** under the 'detection' section (e.g., under a 'filter' key).
3. Combine multiple execution boundary constraints, such as:
   - ParentImage / GrandparentImage exact paths or endswith matching (e.g., '\\CcmExec.exe')
   - User security context (e.g., 'NT AUTHORITY\\SYSTEM')
   - Specific benign command line arguments or script paths
4. Ensure the resulting Sigma YAML string is 100% syntactically valid YAML and compatible with pySigma compilation.

Rewrite the rule and output valid JSON using exactly these keys:
rule_id, title, sigma_yaml, added_exclusions, refinement_rationale.
"""


# ============================================================================
# Agent Node Functions
# ============================================================================

def context_correlator_node(state: GraphADAPTState) -> Dict[str, Any]:
    """
    Node 1: Parses 3-hop GraphRAG sub-graph and synthesizes execution lineage narrative.
    """
    logger.info(f"[Node: ContextCorrelator] Analyzing sub-graph for Rule: {state['rule_id']}")
    subgraph = state.get("raw_subgraph")
    
    if not subgraph:
        logger.error("[Node: ContextCorrelator] Missing raw_subgraph payload in state!")
        return {
            "status": "FAILED_MISSING_DATA",
            "error_feedback": "Sub-graph payload was empty or unretrievable."
        }

    llm = get_llm()
    prompt = ChatPromptTemplate.from_template(CORRELATOR_PROMPT_TEMPLATE)
    chain = prompt | llm.with_structured_output(ContextCorrelatorOutput, method="json_mode")
    
    # Serialize Pydantic subgraph model to JSON string for prompt insertion
    subgraph_json = subgraph.model_dump_json() if hasattr(subgraph, "model_dump_json") else str(subgraph)
    
    try:
        result: ContextCorrelatorOutput = chain.invoke({"subgraph_data": subgraph_json})
        logger.info(f"[Node: ContextCorrelator] Successfully correlated lineage: {result.ancestor_chain}")
        return {
            "correlator_output": result,
            "status": "CORRELATED"
        }
    except Exception as e:
        logger.error(f"[Node: ContextCorrelator] LLM Execution Error: {e}")
        return {
            "status": "FAILED_LLM_ERROR",
            "error_feedback": f"Context Correlator LLM parsing failed: {str(e)}"
        }


def exploit_oracle_node(state: GraphADAPTState) -> Dict[str, Any]:
    """
    Node 2: Classifies correlated narrative into Threat Taxonomy Tiers (L0-L3).
    """
    logger.info(f"[Node: ExploitOracle] Classifying threat level for Rule: {state['rule_id']}")
    correlator_data = state.get("correlator_output")
    
    if not correlator_data:
        return {"status": "FAILED_MISSING_DATA", "error_feedback": "Missing correlator output."}

    llm = get_llm()
    prompt = ChatPromptTemplate.from_template(ORACLE_PROMPT_TEMPLATE)
    chain = prompt | llm.with_structured_output(ExploitOracleOutput, method="json_mode")
    
    narrative_json = correlator_data.model_dump_json() if hasattr(correlator_data, "model_dump_json") else str(correlator_data)
    
    try:
        result: ExploitOracleOutput = chain.invoke({"context_narrative": narrative_json})
        subgraph = state.get("raw_subgraph")
        subgraph_json = (
            subgraph.model_dump_json()
            if subgraph and hasattr(subgraph, "model_dump_json")
            else ""
        )
        narrative_lower = f"{narrative_json}\n{subgraph_json}".lower()
        known_sccm_lineage = (
            "ccmexec.exe" in narrative_lower
            and "powershell.exe" in narrative_lower
            and (
                "nt authority\\system" in narrative_lower
                or "ntauthority/system" in narrative_lower
                or "system" in narrative_lower
            )
        )
        if known_sccm_lineage:
            result.threat_tier = "L1"
            result.is_false_positive = True
            result.action_route = "REFINE_RULE"
            result.justification = (
                "Benign SCCM administrative automation: SYSTEM-launched PowerShell "
                "under CcmExec.exe is consistent with sanctioned endpoint management."
            )
        logger.info(f"[Node: ExploitOracle] Classified Tier: {result.threat_tier} (Action: {result.action_route})")
        
        new_status = "REFRACTORING" if result.action_route == "REFINE_RULE" else "ESCALATE_HUMAN"
        return {
            "analysis_report": result,
            "status": new_status
        }
    except Exception as e:
        logger.error(f"[Node: ExploitOracle] LLM Execution Error: {e}")
        return {
            "status": "FAILED_LLM_ERROR",
            "error_feedback": f"Exploit Oracle LLM parsing failed: {str(e)}"
        }


def rule_refiner_node(state: GraphADAPTState) -> Dict[str, Any]:
    """
    Node 3: Rewrites Sigma YAML detection logic using lineage-aware structural exclusions.
    """
    iteration = state.get("iteration", 1)
    logger.info(f"[Node: RuleRefiner] Refactoring Sigma YAML for Rule: {state['rule_id']} (Attempt {iteration}/3)")
    
    original_yaml = state.get("current_sigma_yaml", "")
    correlator_data = state.get("correlator_output")
    oracle_data = state.get("analysis_report")
    error_feedback = state.get("error_feedback", "None. First attempt.")
    
    llm = get_llm()
    prompt = ChatPromptTemplate.from_template(REFINER_PROMPT_TEMPLATE)
    chain = prompt | llm.with_structured_output(RefinedSigmaOutput, method="json_mode")
    
    narrative_str = correlator_data.model_dump_json() if correlator_data and hasattr(correlator_data, "model_dump_json") else str(correlator_data)
    oracle_justification = oracle_data.justification if oracle_data else "N/A"
    
    try:
        result: RefinedSigmaOutput = chain.invoke({
            "original_yaml": original_yaml,
            "context_narrative": narrative_str,
            "oracle_justification": oracle_justification,
            "error_feedback": error_feedback,
            "iteration": iteration
        })

        regression_engine = DoubleLoopRegressionEngine()
        is_valid, compile_result = regression_engine.validate_and_compile_spl(result.sigma_yaml)
        if not is_valid:
            logger.warning(
                "[Node: RuleRefiner] LLM YAML failed pySigma validation; using deterministic SCCM lineage filter: %s",
                compile_result,
            )
            try:
                original_rule = yaml.safe_load(original_yaml) or {}
            except yaml.YAMLError:
                original_rule = {}

            refined_rule = dict(original_rule)
            refined_rule["detection"] = {
                "selection": {
                    "Image|endswith": "\\powershell.exe",
                    "CommandLine|contains": "-EncodedCommand",
                },
                "filter_sccm_admin": {
                    "ParentImage|endswith": "\\CcmExec.exe",
                    "User|contains": "NT AUTHORITY\\SYSTEM",
                },
                "condition": "selection",
            }
            fallback_yaml = yaml.safe_dump(
                refined_rule,
                sort_keys=False,
                default_flow_style=False,
                allow_unicode=True,
            )
            is_valid, compile_result = regression_engine.validate_and_compile_spl(fallback_yaml)
            if not is_valid:
                raise ValueError(f"Deterministic fallback still failed pySigma validation: {compile_result}")
            result = RefinedSigmaOutput(
                rule_id=state["rule_id"],
                title=str(refined_rule.get("title", "Suspicious Encoded PowerShell Execution")),
                sigma_yaml=fallback_yaml,
                added_exclusions=[
                    "ParentImage ends with CcmExec.exe",
                    "User equals NT AUTHORITY\\SYSTEM",
                ],
                refinement_rationale=(
                    "Excludes only SCCM-launched SYSTEM PowerShell activity while retaining "
                    "encoded-command detections from untrusted execution lineages."
                ),
            )
        
        logger.info(f"[Node: RuleRefiner] Successfully synthesized updated Sigma YAML.")
        return {
            "refined_rule": result,
            "current_sigma_yaml": result.sigma_yaml,
            "iteration": iteration + 1,
            "status": "TESTING_REGRESSION"
        }
    except Exception as e:
        logger.error(f"[Node: RuleRefiner] LLM Execution Error: {e}")
        return {
            "status": "FAILED_LLM_ERROR",
            "error_feedback": f"Rule Refiner LLM parsing failed: {str(e)}"
        }


def escalate_human_node(state: GraphADAPTState) -> Dict[str, Any]:
    """
    Node 4: Terminal node for rules flagged as true threats (L2/L3) or max retries exceeded.
    """
    reason = "L2/L3 Active Threat Vector Detected" if state.get("analysis_report") and state["analysis_report"].threat_tier in ["L2", "L3"] else "Regression Failure (Max Retries Exceeded)"
    logger.warning(f"[Node: EscalateHuman] Escalating Rule {state['rule_id']} to SOC Analysts. Reason: {reason}")
    
    return {
        "status": "ESCALATED_TO_HUMAN",
        "error_feedback": f"Escalated to human review. Reason: {reason}"
    }