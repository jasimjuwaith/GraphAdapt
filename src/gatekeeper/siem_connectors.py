import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests


logger = logging.getLogger("GraphADAPT.Siem")


class BaseSIEMConnector(ABC):
    @abstractmethod
    def get_performance_metrics(
        self,
        rule_id: str,
        window_hours: int = 24,
    ) -> Tuple[int, int]:
        raise NotImplementedError

    @abstractmethod
    def get_seed_alert_metadata(
        self,
        rule_id: str,
    ) -> Tuple[str, int, str, Optional[str]]:
        raise NotImplementedError

    @abstractmethod
    def deploy_rule(self, rule_id: str, compiled_query: str, **kwargs: Any) -> str:
        raise NotImplementedError


class MockSIEMConnector(BaseSIEMConnector):
    def get_performance_metrics(
        self,
        rule_id: str,
        window_hours: int = 24,
    ) -> Tuple[int, int]:
        return 100, 2

    def get_seed_alert_metadata(
        self,
        rule_id: str,
    ) -> Tuple[str, int, str, Optional[str]]:
        return (
            "WIN-SEC-WORKSTATION-01",
            4108,
            "Suspicious Encoded PowerShell Execution",
            None,
        )

    def deploy_rule(self, rule_id: str, compiled_query: str, **kwargs: Any) -> str:
        logger.info("MOCK deployed rule %s", rule_id)
        return "DEPLOYED"


class SplunkConnector(BaseSIEMConnector):
    def __init__(self) -> None:
        self.base_url = os.getenv("SPLUNK_URL", "").rstrip("/")
        self.token = os.getenv("SPLUNK_TOKEN", "")
        self.username = os.getenv("SPLUNK_USERNAME")
        self.password = os.getenv("SPLUNK_PASSWORD")
        self.verify = os.getenv("SIEM_VERIFY_SSL", "true").lower() != "false"
        self.headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _auth(self) -> Optional[Tuple[str, str]]:
        if self.username and self.password:
            return self.username, self.password
        return None

    def _search_count(self, search: str) -> int:
        if not self.base_url:
            raise RuntimeError("SPLUNK_URL is not configured")
        job = requests.post(
            f"{self.base_url}/services/search/jobs",
            headers=self.headers,
            auth=self._auth(),
            verify=self.verify,
            data={"search": f"search {search}", "exec_mode": "normal", "output_mode": "json"},
            timeout=30,
        )
        job.raise_for_status()
        job_data = job.json()
        if isinstance(job_data, dict):
            count = job_data.get("content", {}).get("count")
            if count is not None:
                return int(count)
            sid = job_data.get("sid")
            if sid:
                result = requests.get(
                    f"{self.base_url}/services/search/jobs/{sid}/results",
                    headers=self.headers,
                    auth=self._auth(),
                    verify=self.verify,
                    params={"output_mode": "json"},
                    timeout=30,
                )
                result.raise_for_status()
                results = result.json().get("results", [])
                if results:
                    for key in ("count", "alert_count", "_count"):
                        if key in results[0]:
                            return int(results[0][key])
        return 0

    def get_performance_metrics(
        self,
        rule_id: str,
        window_hours: int = 24,
    ) -> Tuple[int, int]:
        earliest = f"-{window_hours}h"
        alerts = self._search_count(
            f'index=* rule_id="{rule_id}" earliest="{earliest}" | stats count'
        )
        incidents = self._search_count(
            f'index=notable rule_id="{rule_id}" disposition="True Positive" earliest="{earliest}" | stats count'
        )
        return alerts, incidents

    def get_seed_alert_metadata(
        self,
        rule_id: str,
    ) -> Tuple[str, int, str, Optional[str]]:
        if not self.base_url:
            raise RuntimeError("SPLUNK_URL is not configured")
        search = (
            f'search index=* rule_id="{rule_id}" '
            "| head 1 "
            "| table host target_process_id process_guid rule_title"
        )
        response = requests.post(
            f"{self.base_url}/services/search/jobs",
            headers=self.headers,
            auth=self._auth(),
            verify=self.verify,
            data={"search": search, "exec_mode": "normal", "output_mode": "json"},
            timeout=30,
        )
        response.raise_for_status()
        sid = response.json().get("sid")
        if not sid:
            raise RuntimeError("Splunk search job did not return a SID")
        result = requests.get(
            f"{self.base_url}/services/search/jobs/{sid}/results",
            headers=self.headers,
            auth=self._auth(),
            verify=self.verify,
            params={"output_mode": "json"},
            timeout=30,
        )
        result.raise_for_status()
        records = result.json().get("results", [])
        if not records:
            raise RuntimeError(f"No seed alert found for rule {rule_id}")
        alert = records[0]
        return (
            str(alert.get("host") or alert.get("hostname") or "unknown-host"),
            int(alert.get("target_process_id") or alert.get("pid") or 0),
            str(alert.get("rule_title") or rule_id),
            alert.get("process_guid"),
        )

    def deploy_rule(self, rule_id: str, compiled_query: str, **kwargs: Any) -> str:
        if not self.base_url:
            return "PENDING_APPROVAL"
        response = requests.post(
            f"{self.base_url}/servicesNS/nobody/search/saved/searches",
            headers=self.headers,
            auth=self._auth(),
            verify=self.verify,
            data={"name": rule_id, "search": compiled_query, "disabled": "0"},
            timeout=30,
        )
        response.raise_for_status()
        return "DEPLOYED"


class ElasticWazuhConnector(BaseSIEMConnector):
    def __init__(self) -> None:
        self.base_url = os.getenv("ELASTIC_URL", os.getenv("SIEM_API_URL", "")).rstrip("/")
        self.api_key = os.getenv("ELASTIC_API_KEY", os.getenv("SIEM_API_KEY", ""))
        self.verify = os.getenv("SIEM_VERIFY_SSL", "true").lower() != "false"
        self.headers = {"Authorization": f"ApiKey {self.api_key}"} if self.api_key else {}
        self.alert_index = os.getenv("ELASTIC_ALERT_INDEX", "logs-*")

    def _count(self, query: Dict[str, Any]) -> int:
        if not self.base_url:
            raise RuntimeError("ELASTIC_URL/SIEM_API_URL is not configured")
        response = requests.post(
            f"{self.base_url}/{self.alert_index}/_count",
            headers=self.headers,
            verify=self.verify,
            json=query,
            timeout=30,
        )
        response.raise_for_status()
        return int(response.json().get("count", 0))

    def get_performance_metrics(
        self,
        rule_id: str,
        window_hours: int = 24,
    ) -> Tuple[int, int]:
        start = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
        time_filter = {"range": {"@timestamp": {"gte": start}}}
        rule_filter = {"term": {"rule_id": rule_id}}
        alerts = self._count(
            {"query": {"bool": {"filter": [time_filter, rule_filter]}}}
        )
        incidents = self._count(
            {
                "query": {
                    "bool": {
                        "filter": [
                            time_filter,
                            rule_filter,
                            {"terms": {"status": ["closed", "resolved"]}},
                            {"term": {"disposition": "true_positive"}},
                        ]
                    }
                }
            }
        )
        return alerts, incidents

    def get_seed_alert_metadata(
        self,
        rule_id: str,
    ) -> Tuple[str, int, str, Optional[str]]:
        if not self.base_url:
            raise RuntimeError("ELASTIC_URL/SIEM_API_URL is not configured")
        response = requests.post(
            f"{self.base_url}/{self.alert_index}/_search",
            headers=self.headers,
            verify=self.verify,
            json={
                "size": 1,
                "sort": [{"@timestamp": "desc"}],
                "query": {"term": {"rule_id": rule_id}},
            },
            timeout=30,
        )
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
        if not hits:
            raise RuntimeError(f"No seed alert found for rule {rule_id}")
        source = hits[0].get("_source", {})
        process = source.get("process", {})
        return (
            str(source.get("host", {}).get("name") or source.get("hostname") or "unknown-host"),
            int(process.get("pid") or source.get("target_pid") or 0),
            str(source.get("rule", {}).get("name") or source.get("rule_name") or rule_id),
            process.get("entity_id") or source.get("process_guid"),
        )

    def deploy_rule(self, rule_id: str, compiled_query: str, **kwargs: Any) -> str:
        if not self.base_url:
            return "PENDING_APPROVAL"
        response = requests.put(
            f"{self.base_url}/.kibana/_doc/detection-rule-{rule_id}",
            headers=self.headers,
            verify=self.verify,
            json={"rule_id": rule_id, "query": compiled_query, "updated_at": datetime.now(timezone.utc).isoformat()},
            timeout=30,
        )
        response.raise_for_status()
        return "DEPLOYED"


def get_siem_connector() -> BaseSIEMConnector:
    mode = os.getenv("SIEM_MODE", "mock").strip().lower()
    if mode == "splunk":
        return SplunkConnector()
    if mode in {"elastic", "wazuh"}:
        return ElasticWazuhConnector()
    return MockSIEMConnector()
