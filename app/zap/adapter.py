from typing import Dict, Any, List
from app.findings.models import Finding, Severity, Confidence
from app.core.logger import setup_logger

logger = setup_logger(__name__)

def map_severity(risk_level: str) -> Severity:
    risk_level = risk_level.upper()
    if risk_level == "INFORMATIONAL" or risk_level == "0":
        return Severity.INFORMATIONAL
    elif risk_level == "LOW" or risk_level == "1":
        return Severity.LOW
    elif risk_level == "MEDIUM" or risk_level == "2":
        return Severity.MEDIUM
    elif risk_level == "HIGH" or risk_level == "3":
        return Severity.HIGH
    elif risk_level == "CRITICAL" or risk_level == "4":
        return Severity.CRITICAL
    return Severity.INFORMATIONAL

def map_confidence(confidence_level: str) -> Confidence:
    confidence_level = confidence_level.upper()
    if confidence_level in ["LOW", "1"]:
        return Confidence.LOW
    elif confidence_level in ["MEDIUM", "2"]:
        return Confidence.MEDIUM
    elif confidence_level in ["HIGH", "3"]:
        return Confidence.HIGH
    return Confidence.LOW

def convert_zap_alert_to_finding(alert: Dict[str, Any]) -> Finding:
    try:
        return Finding(
            title=alert.get("name", "Unknown ZAP Alert"),
            category="ZAP Alert",
            url=alert.get("url", ""),
            method=alert.get("method", "GET") or "GET",
            parameter=alert.get("param", ""),
            severity=map_severity(alert.get("risk", "INFORMATIONAL")),
            confidence=map_confidence(alert.get("confidence", "LOW")),
            evidence=alert.get("evidence", ""),
            description=alert.get("description", ""),
            remediation=alert.get("solution", ""),
            scanner_source="OWASP ZAP"
        )
    except Exception as e:
        logger.error(f"Failed to convert ZAP alert to Finding: {e}")
        # Return a generic finding in case of parsing errors so we don't drop it entirely
        return Finding(
            title="Malformed ZAP Alert",
            category="ZAP Alert",
            url="",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.LOW,
            description=f"Error parsing alert: {str(e)}",
            evidence="",
            remediation="",
            scanner_source="OWASP ZAP"
        )
