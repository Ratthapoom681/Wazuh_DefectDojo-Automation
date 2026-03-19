import httpx
import json
import logging
from urllib.parse import quote
from tenacity import retry, wait_exponential, stop_after_attempt
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class DefectDojoClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json"
        }
        # Caches
        self.user_cache = {}
        self.context_cache = {}
        self.endpoint_cache = {}

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _request(self, method: str, endpoint: str, **kwargs):
        url = f"{self.base_url}/api/v2/{endpoint}"
        with httpx.Client() as client:
            response = client.request(method, url, headers=self.headers, timeout=10.0, **kwargs)
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                request_payload = kwargs.get("json")
                payload_preview = (
                    json.dumps(request_payload, default=str)[:2000]
                    if request_payload is not None
                    else None
                )
                body_preview = response.text[:4000]
                raise RuntimeError(
                    f"DefectDojo API {method} {endpoint} failed with HTTP {response.status_code}. "
                    f"Response body: {body_preview}. "
                    f"Request payload: {payload_preview}"
                ) from exc

            return response.json() if response.content else None

    def get_user(self, username: str) -> Optional[Dict]:
        if username in self.user_cache:
            return self.user_cache[username]
            
        try:
            res = self._request("GET", f"users/?username={username}")
            if res and res.get("count", 0) > 0:
                user = res["results"][0]
                self.user_cache[username] = user
                return user
        except Exception as e:
            logger.error(f"Failed to fetch user {username}: {e}")
        return None

    def is_user_active(self, username: str) -> bool:
        user = self.get_user(username)
        return bool(user and user.get("is_active", False))

    def ensure_context(self) -> Dict[str, int]:
        """Ensures a default Product, Engagement, and Test exist."""
        if "context" in self.context_cache:
            return self.context_cache["context"]

        # 1. Product Type
        pt_res = self._request("GET", "product_types/?name=Wazuh")
        pt_id = pt_res["results"][0]["id"] if pt_res["count"] > 0 else self._request("POST", "product_types/", json={"name": "Wazuh", "description": "Wazuh Alerts"})["id"]

        # 2. Product
        prod_res = self._request("GET", "products/?name=Wazuh Endpoint Security")
        prod_id = prod_res["results"][0]["id"] if prod_res["count"] > 0 else self._request("POST", "products/", json={"name": "Wazuh Endpoint Security", "description": "Alerts", "prod_type": pt_id})["id"]

        # 3. Engagement
        eng_res = self._request("GET", f"engagements/?product={prod_id}&name=Continuous Monitoring")
        eng_id = eng_res["results"][0]["id"] if eng_res["count"] > 0 else self._request("POST", "engagements/", json={"name": "Continuous Monitoring", "product": prod_id, "target_start": "2020-01-01", "target_end": "2099-12-31", "status": "In Progress"})["id"]

        # 4. Test
        test_res = self._request("GET", f"tests/?engagement={eng_id}&title=Wazuh Alerts Test")
        test_id = test_res["results"][0]["id"] if test_res["count"] > 0 else self._request("POST", "tests/", json={"title": "Wazuh Alerts Test", "engagement": eng_id, "test_type": 1, "target_start": "2020-01-01", "target_end": "2099-12-31"})["id"]

        context = {
            "product_type_id": pt_id,
            "product_id": prod_id,
            "engagement_id": eng_id,
            "test_id": test_id,
        }
        self.context_cache["context"] = context
        return context

    def get_finding_by_dedup(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        search = self._request("GET", f"findings/?unique_id_from_tool={quote(dedup_key)}")
        if search and search.get("count", 0) > 0:
            return search["results"][0]
        return None

    def ensure_endpoint(self, host: str, product_id: int) -> Optional[int]:
        cache_key = f"{product_id}:{host}"
        if cache_key in self.endpoint_cache:
            return self.endpoint_cache[cache_key]

        try:
            search = self._request("GET", f"endpoints/?product={product_id}&host={quote(host)}")
            if search and search.get("count", 0) > 0:
                endpoint_id = search["results"][0]["id"]
                logger.info("Reusing DefectDojo endpoint %s for host %s", endpoint_id, host)
                self.endpoint_cache[cache_key] = endpoint_id
                return endpoint_id

            endpoint = self._request("POST", "endpoints/", json={"host": host, "product": product_id})
            endpoint_id = endpoint["id"]
            logger.info("Created DefectDojo endpoint %s for host %s", endpoint_id, host)
            self.endpoint_cache[cache_key] = endpoint_id
            return endpoint_id
        except Exception as exc:
            logger.warning("Failed to ensure endpoint for host %s: %s", host, exc)
            return None

    def _extract_related_ids(self, values: Any) -> list[int]:
        ids: list[int] = []
        if not isinstance(values, list):
            return ids

        for value in values:
            if isinstance(value, int):
                ids.append(value)
            elif isinstance(value, dict) and isinstance(value.get("id"), int):
                ids.append(value["id"])
        return ids

    def _extract_tag_names(self, values: Any) -> list[str]:
        names: list[str] = []
        if not isinstance(values, list):
            return names

        for value in values:
            if isinstance(value, str):
                names.append(value)
            elif isinstance(value, dict) and isinstance(value.get("name"), str):
                names.append(value["name"])
        return names

    def _extract_reviewer_ids(self, finding: Dict[str, Any]) -> list[int]:
        reviewer_ids = self._extract_related_ids(finding.get("reviewers", []))

        reviewer = finding.get("reviewer")
        if isinstance(reviewer, int):
            reviewer_ids.append(reviewer)
        elif isinstance(reviewer, dict) and isinstance(reviewer.get("id"), int):
            reviewer_ids.append(reviewer["id"])

        return sorted(set(reviewer_ids))

    def push_finding(
        self,
        finding_data: dict,
        assign_note: str,
        existing_finding: Optional[Dict[str, Any]] = None,
        endpoint_id: Optional[int] = None,
    ):
        dedup_key = finding_data["unique_id_from_tool"]

        if existing_finding is None:
            existing_finding = self.get_finding_by_dedup(dedup_key)

        payload = dict(finding_data)
        if existing_finding:
            existing_tags = self._extract_tag_names(existing_finding.get("tags", []))
            payload["tags"] = sorted(set(existing_tags + payload.get("tags", [])))

        if endpoint_id:
            endpoint_ids = self._extract_related_ids(existing_finding.get("endpoints", [])) if existing_finding else []
            endpoint_ids.append(endpoint_id)
            payload["endpoints"] = sorted(set(endpoint_ids))

        if existing_finding:
            finding_id = existing_finding["id"]
            logger.info("Updating existing DefectDojo finding for dedup key %s", dedup_key)
            existing_reviewer_ids = self._extract_reviewer_ids(existing_finding)
            if existing_reviewer_ids:
                payload["reviewers"] = [existing_reviewer_ids[0]]
            try:
                self._request("PATCH", f"findings/{finding_id}/", json=payload)
            except Exception:
                if "endpoints" not in payload:
                    raise
                logger.warning(
                    "Updating finding %s with endpoints failed. Retrying without endpoint association.",
                    finding_id,
                )
                payload.pop("endpoints", None)
                self._request("PATCH", f"findings/{finding_id}/", json=payload)
            should_add_note = False
        else:
            logger.info("Creating new DefectDojo finding for dedup key %s", dedup_key)
            try:
                finding_id = self._request("POST", "findings/", json=payload)["id"]
            except Exception:
                if "endpoints" not in payload:
                    raise
                logger.warning(
                    "Creating finding with endpoints failed for dedup key %s. Retrying without endpoint association.",
                    dedup_key,
                )
                payload.pop("endpoints", None)
                finding_id = self._request("POST", "findings/", json=payload)["id"]
            should_add_note = True
            
        # Add a note regarding assignment using the finding-scoped endpoint.
        if should_add_note:
            try:
                self._request("POST", f"findings/{finding_id}/notes/", json={"entry": assign_note})
            except Exception as e:
                logger.warning(f"Note attachment variation failed, skipping note: {e}")
