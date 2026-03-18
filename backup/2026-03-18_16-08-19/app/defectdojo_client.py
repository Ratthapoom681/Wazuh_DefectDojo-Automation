import httpx
import json
import logging
from tenacity import retry, wait_exponential, stop_after_attempt
from typing import Optional, Dict

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

    def ensure_context(self) -> int:
        """Ensures a default Product, Engagement, and Test exists. Returns Test ID."""
        if "test_id" in self.context_cache:
            return self.context_cache["test_id"]

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

        self.context_cache["test_id"] = test_id
        return test_id

    def push_finding(self, finding_data: dict, assign_note: str):
        dedup_key = finding_data["unique_id_from_tool"]
        
        # Check if finding exists
        search = self._request("GET", f"findings/?unique_id_from_tool={dedup_key}")
        
        if search and search.get("count", 0) > 0:
            finding_id = search["results"][0]["id"]
            logger.info("Updating existing DefectDojo finding for dedup key %s", dedup_key)
            self._request("PATCH", f"findings/{finding_id}/", json=finding_data)
        else:
            logger.info("Creating new DefectDojo finding for dedup key %s", dedup_key)
            finding_id = self._request("POST", "findings/", json=finding_data)["id"]
            
        # Add a note regarding assignment using the finding-scoped endpoint.
        try:
            self._request("POST", f"findings/{finding_id}/notes/", json={"entry": assign_note})
        except Exception as e:
            logger.warning(f"Note attachment variation failed, skipping note: {e}")
