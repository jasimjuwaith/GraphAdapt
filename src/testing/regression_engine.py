"""
Graph-ADAPT Double-Loop Software Regression Engine
Deterministic circuit breaker that validates candidate Sigma rules against:
  - Loop 1: 48-hour historical corporate noise telemetry (Target: 0 False Positives / NRE = 100%)
  - Loop 2: Synthetic Atomic Red Team attack payloads (Target: 100% Detection / TPRR = 1.0)
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
from dotenv import load_dotenv

from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend

load_dotenv()
logger = logging.getLogger("GraphADAPT.RegressionEngine")


class DoubleLoopRegressionEngine:
    """Executes syntax validation, SPL compilation, and dual-loop behavioral verification."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).resolve().parent.parent.parent
        self.noise_dataset_path = self.base_dir / "data" / "raw_logs" / "background_noise_48h.json"
        self.attack_dataset_path = self.base_dir / "data" / "atomic_payloads" / "attack_corpus_all.json"
        self.output_dir = self.base_dir / "rules" / "refined_output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.splunk_backend = SplunkBackend()

    def _load_json_dataset(self, path: Path) -> List[Dict[str, Any]]:
        """Loads telemetry JSON log corpus from disk."""
        if not path.exists():
            logger.warning(f"Dataset file not found at {path}. Returning empty list.")
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            logger.error(f"Failed to parse JSON dataset {path}: {e}")
            return []

    def validate_and_compile_spl(self, sigma_yaml: str) -> Tuple[bool, str]:
        """
        Validates Sigma YAML structure via pySigma and translates it to Splunk SPL.
        Returns: (is_valid, spl_query_or_error_message)
        """
        try:
            rule_collection = SigmaCollection.from_yaml(sigma_yaml)
            spl_queries = self.splunk_backend.convert(rule_collection)
            if not spl_queries:
                return False, "pySigma returned empty SPL query output."
            spl_query = spl_queries[0]
            try:
                parsed = yaml.safe_load(sigma_yaml) or {}
                detection = parsed.get("detection", {})
                exclusions = []
                for name, block in detection.items():
                    if name.startswith("filter") and isinstance(block, dict):
                        terms = []
                        for key, value in block.items():
                            field_name = key.split("|")[0]
                            modifier = key.split("|")[1].lower() if "|" in key else "exact"
                            value_text = value if isinstance(value, str) else str(value)
                            if modifier == "contains":
                                terms.append(f'{field_name}="*{value_text}*"')
                            elif modifier == "endswith":
                                terms.append(f'{field_name}="*{value_text}"')
                            elif modifier == "startswith":
                                terms.append(f'{field_name}="{value_text}*"')
                            else:
                                terms.append(f'{field_name}="{value_text}"')
                        if terms:
                            exclusions.append("(" + " AND ".join(terms) + ")")
                if exclusions:
                    spl_query = f"{spl_query} NOT (" + " OR ".join(exclusions) + ")"
            except Exception as compile_error:
                logger.warning("Could not append Sigma exclusions to SPL: %s", compile_error)
            return True, spl_query
        except Exception as e:
            return False, f"pySigma Validation/Compilation Error: {str(e)}"

    def _match_field_condition(self, log_value: Any, condition_key: str, expected_value: Any) -> bool:
        """Evaluates Sigma field modifiers (exact, endswith, startswith, contains) against a log event."""
        if log_value is None:
            return False

        log_str = str(log_value).lower()
        exp_list = expected_value if isinstance(expected_value, list) else [expected_value]
        parts = condition_key.split("|")
        modifier = parts[1].lower() if len(parts) > 1 else "exact"

        for item in exp_list:
            exp_str = str(item).lower()
            if modifier == "exact" and log_str == exp_str:
                return True
            elif modifier == "endswith" and log_str.endswith(exp_str):
                return True
            elif modifier == "startswith" and log_str.startswith(exp_str):
                return True
            elif modifier == "contains" and exp_str in log_str:
                return True
        return False

    def _evaluate_selection_block(self, log: Dict[str, Any], block: Dict[str, Any]) -> bool:
        """Checks whether a single log event satisfies all key-value constraints in a detection block."""
        for cond_key, expected_val in block.items():
            field_name = cond_key.split("|")[0]
            # Support nested Sysmon EventData or flat JSON keys
            event_data = log.get("Event", {}).get("EventData", log)
            actual_val = event_data.get(field_name) or log.get(field_name)
            if not self._match_field_condition(actual_val, cond_key, expected_val):
                return False
        return True

    def execute_sigma_against_logs(self, sigma_yaml: str, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simulates Sigma rule execution over a list of telemetry log records."""
        parsed = yaml.safe_load(sigma_yaml)
        detection = parsed.get("detection", {})

        selections = [v for k, v in detection.items() if k.startswith("selection") and isinstance(v, dict)]
        filters = [v for k, v in detection.items() if k.startswith("filter") and isinstance(v, dict)]

        if not selections:
            return []

        matched_logs = []
        for log in logs:
            # Must match at least one selection block
            in_selection = any(self._evaluate_selection_block(log, sel) for sel in selections)
            if not in_selection:
                continue

            # Must NOT match any filter exclusion block
            in_filter = any(self._evaluate_selection_block(log, flt) for flt in filters)
            if not in_filter:
                matched_logs.append(log)

        return matched_logs

    def evaluate_rule_regression(self, rule_id: str, refined_yaml: str) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Runs the complete Double-Loop Software Regression check.
        Returns: (passed: bool, loop_failed: Optional[1|2], feedback_trace: Optional[str])
        """
        # Step 0: Syntax & Splunk SPL Compilation Gate
        is_valid, spl_or_err = self.validate_and_compile_spl(refined_yaml)
        if not is_valid:
            feedback = (
                f"[SYNTAX FAILURE] {spl_or_err}\n"
                f"INSTRUCTIONS: Fix YAML syntax or invalid Sigma modifiers so pySigma compiles cleanly to Splunk SPL."
            )
            return False, 1, feedback

        # Step 1: Loop 1 — False Positive Abatement Test (48h Corporate Noise)
        noise_logs = self._load_json_dataset(self.noise_dataset_path)
        rule_noise = [
            log for log in noise_logs
            if log.get("target_rule_id", rule_id) == rule_id
        ]

        misfired_logs = self.execute_sigma_against_logs(refined_yaml, rule_noise)
        if len(misfired_logs) > 0:
            sample_misfires = json.dumps(misfired_logs[:2], indent=2)
            feedback = (
                f"[LOOP 1 FAILURE: FALSE POSITIVE ABATEMENT]\n"
                f"ERROR: Refined rule still triggered {len(misfired_logs)} false alarms on 48h corporate noise.\n"
                f"SAMPLE MISFIRED LOGS:\n{sample_misfires}\n"
                f"INSTRUCTIONS: Your structural filter is too narrow. Inspect ParentImage, GrandparentImage, "
                f"and User fields in the sample logs above and refine your exclusion block."
            )
            return False, 1, feedback

        # Step 2: Loop 2 — True Positive Recall Retention Test (Atomic Red Team)
        attack_logs = self._load_json_dataset(self.attack_dataset_path)
        rule_attacks = [
            log for log in attack_logs
            if log.get("target_rule_id", rule_id) == rule_id
        ]

        if rule_attacks:
            caught_attacks = self.execute_sigma_against_logs(refined_yaml, rule_attacks)
            tprr = len(caught_attacks) / len(rule_attacks)
            if tprr < 1.0:
                caught_ids = {c.get("attack_id") for c in caught_attacks}
                missed = [a.get("attack_id", "unknown") for a in rule_attacks if a.get("attack_id") not in caught_ids]
                feedback = (
                    f"[LOOP 2 FAILURE: TRUE POSITIVE RECALL DROP (TPRR = {tprr:.2f})]\n"
                    f"ERROR: Your exclusion filter was TOO BROAD and suppressed genuine Atomic Red Team attacks!\n"
                    f"MISSED ATTACK PAYLOADS: {missed}\n"
                    f"INSTRUCTIONS: Remove broad wildcards. Tighten the filter by requiring exact ParentImage "
                    f"and User SID lineage constraints so malicious executions are still detected."
                )
                return False, 2, feedback

        # Step 3: Export Verified Sigma YAML & Compiled Splunk SPL
        self._export_verified_artifacts(rule_id, refined_yaml, spl_or_err)
        return True, None, None

    def _export_verified_artifacts(self, rule_id: str, sigma_yaml: str, spl_query: str) -> None:
        """Persists validated Sigma YAML and Splunk SPL query to rules/refined_output/."""
        yaml_path = self.output_dir / f"{rule_id}.yml"
        spl_path = self.output_dir / f"{rule_id}.spl"

        with open(yaml_path, "w", encoding="utf-8") as f:
            f.write(sigma_yaml.strip() + "\n")

        with open(spl_path, "w", encoding="utf-8") as f:
            f.write(spl_query.strip() + "\n")

        logger.info(f"[RegressionEngine] Exported verified Sigma YAML -> {yaml_path}")
        logger.info(f"[RegressionEngine] Exported compiled Splunk SPL -> {spl_path}")