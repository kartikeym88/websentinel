from typing import List
from app.zap.client import ZAPClient
from app.zap.adapter import convert_zap_alert_to_finding
from app.findings.models import Finding
from app.core.logger import setup_logger
from app.core.config import get_settings

logger = setup_logger(__name__)

class ZAPService:
    def __init__(self):
        self.client = ZAPClient()
        self.settings = get_settings()
        
    def is_available(self) -> bool:
        if not self.settings.zap_enabled:
            return False
        return self.client.check_connection()
        
    def run_scan(self, target_url: str) -> List[Finding]:
        findings = []
        if not self.is_available():
            logger.warning("ZAP is not enabled or not available. Skipping ZAP scan.")
            return findings
            
        from app.http.client import HTTPClient
        if not HTTPClient().is_allowed_domain(target_url):
            logger.warning(f"Target {target_url} is not in allowed domains. Aborting ZAP scan.")
            raise ValueError(f"Domain not in allowed list: {target_url}")
            
        logger.info(f"Starting ZAP Spider for {target_url}")
        spider_id = self.client.start_spider(target_url)
        if spider_id:
            logger.info(f"Waiting for ZAP Spider (Scan ID: {spider_id})")
            completed = self.client.wait_for_spider(spider_id, timeout=self.settings.zap_timeout)
            if not completed:
                logger.warning("ZAP Spider timed out.")
                raise TimeoutError("ZAP Spider timed out.")
        
        logger.info(f"Starting ZAP Active Scan for {target_url}")
        scan_id = self.client.start_active_scan(target_url)
        if scan_id:
            logger.info(f"Waiting for ZAP Active Scan (Scan ID: {scan_id})")
            completed = self.client.wait_for_active_scan(scan_id, timeout=self.settings.zap_timeout)
            if not completed:
                logger.warning("ZAP Active Scan timed out.")
                raise TimeoutError("ZAP Active Scan timed out.")
                
        logger.info("Retrieving ZAP alerts")
        alerts = self.client.get_alerts(baseurl=target_url)
        for alert in alerts:
            finding = convert_zap_alert_to_finding(alert)
            findings.append(finding)
            
        return findings
