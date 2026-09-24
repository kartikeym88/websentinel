import requests
import time
from urllib.parse import urljoin
from typing import Dict, Any, List
from app.core.config import get_settings
from app.core.logger import setup_logger

logger = setup_logger(__name__)

class ZAPClientException(Exception):
    pass

class ZAPClient:
    def __init__(self):
        self.settings = get_settings()
        self.base_url = f"http://{self.settings.zap_host}:{self.settings.zap_port}"
        self.api_key = self.settings.zap_api_key
        self.session = requests.Session()
        self.session.headers.update({
            "X-ZAP-API-Key": self.api_key,
            "Accept": "application/json"
        })

    def _request(self, method: str, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        url = urljoin(self.base_url, endpoint)
        if params is None:
            params = {}
            
        try:
            response = self.session.request(method, url, params=params, timeout=self.settings.request_timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"ZAP API Request failed: {e}")
            raise ZAPClientException(f"Failed to communicate with ZAP API: {e}")

    def check_connection(self) -> bool:
        """Check if ZAP is running and accessible."""
        try:
            res = self._request("GET", "/JSON/core/view/version/")
            return "version" in res
        except ZAPClientException:
            return False

    def start_spider(self, target_url: str) -> str:
        """Starts the ZAP spider on the target URL."""
        res = self._request("GET", "/JSON/spider/action/scan/", {"url": target_url})
        return res.get("scan", "")

    def get_spider_status(self, scan_id: str) -> int:
        res = self._request("GET", "/JSON/spider/view/status/", {"scanId": scan_id})
        return int(res.get("status", 0))

    def start_active_scan(self, target_url: str) -> str:
        """Starts the ZAP active scanner on the target URL."""
        res = self._request("GET", "/JSON/ascan/action/scan/", {"url": target_url})
        return res.get("scan", "")

    def get_active_scan_status(self, scan_id: str) -> int:
        res = self._request("GET", "/JSON/ascan/view/status/", {"scanId": scan_id})
        return int(res.get("status", 0))

    def get_alerts(self, baseurl: str = "") -> List[Dict[str, Any]]:
        """Retrieves alerts from ZAP."""
        params = {}
        if baseurl:
            params["baseurl"] = baseurl
        res = self._request("GET", "/JSON/core/view/alerts/", params)
        return res.get("alerts", [])

    def wait_for_spider(self, scan_id: str, timeout: int = 300) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            status = self.get_spider_status(scan_id)
            if status >= 100:
                return True
            time.sleep(2)
        return False

    def wait_for_active_scan(self, scan_id: str, timeout: int = 300) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            status = self.get_active_scan_status(scan_id)
            if status >= 100:
                return True
            time.sleep(2)
        return False
