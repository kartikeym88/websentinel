import pytest
from unittest.mock import patch, MagicMock
from app.zap.client import ZAPClient, ZAPClientException
from app.zap.adapter import convert_zap_alert_to_finding, map_severity, map_confidence
from app.zap.service import ZAPService
from app.findings.models import Severity, Confidence
from app.core.config import Settings
import requests

@pytest.fixture
def mock_zap_client():
    with patch("app.zap.service.ZAPClient") as MockClient:
        yield MockClient.return_value

@pytest.fixture
def mock_settings():
    with patch("app.zap.client.get_settings") as mock_get:
        settings = Settings()
        settings.zap_enabled = True
        mock_get.return_value = settings
        yield settings

def test_zap_client_check_connection(mock_settings):
    with patch("requests.Session.request") as mock_request:
        mock_response = MagicMock()
        mock_response.json.return_value = {"version": "2.14.0"}
        mock_request.return_value = mock_response
        
        client = ZAPClient()
        assert client.check_connection() is True

def test_zap_client_connection_error(mock_settings):
    with patch("requests.Session.request") as mock_request:
        mock_request.side_effect = requests.exceptions.RequestException("Connection Refused")
        
        client = ZAPClient()
        assert client.check_connection() is False

def test_map_severity():
    assert map_severity("INFORMATIONAL") == Severity.INFORMATIONAL
    assert map_severity("0") == Severity.INFORMATIONAL
    assert map_severity("1") == Severity.LOW
    assert map_severity("2") == Severity.MEDIUM
    assert map_severity("3") == Severity.HIGH
    assert map_severity("4") == Severity.CRITICAL
    assert map_severity("UNKNOWN") == Severity.INFORMATIONAL

def test_map_confidence():
    assert map_confidence("1") == Confidence.LOW
    assert map_confidence("2") == Confidence.MEDIUM
    assert map_confidence("3") == Confidence.HIGH
    assert map_confidence("UNKNOWN") == Confidence.LOW

def test_convert_zap_alert():
    alert = {
        "name": "Test Alert",
        "url": "http://localhost/",
        "method": "POST",
        "param": "test_param",
        "risk": "3",
        "confidence": "2",
        "evidence": "test_evidence",
        "description": "test_desc",
        "solution": "test_sol"
    }
    
    finding = convert_zap_alert_to_finding(alert)
    assert finding.title == "Test Alert"
    assert finding.url == "http://localhost/"
    assert finding.method == "POST"
    assert finding.parameter == "test_param"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.MEDIUM
    assert finding.evidence == "test_evidence"
    assert finding.description == "test_desc"
    assert finding.remediation == "test_sol"
    assert finding.scanner_source == "OWASP ZAP"

def test_convert_zap_alert_malformed():
    alert = {"invalid": "alert"}
    finding = convert_zap_alert_to_finding(alert)
    assert finding.title == "Unknown ZAP Alert"
    assert finding.severity == Severity.INFORMATIONAL

def test_zap_service_disabled(mock_settings):
    mock_settings.zap_enabled = False
    with patch("app.zap.service.get_settings", return_value=mock_settings):
        service = ZAPService()
        findings = service.run_scan("http://localhost/")
        assert len(findings) == 0

def test_zap_service_run_scan(mock_settings, mock_zap_client):
    mock_zap_client.check_connection.return_value = True
    mock_zap_client.start_spider.return_value = "1"
    mock_zap_client.wait_for_spider.return_value = True
    mock_zap_client.start_active_scan.return_value = "2"
    mock_zap_client.wait_for_active_scan.return_value = True
    
    mock_zap_client.get_alerts.return_value = [{
        "name": "Cross Site Scripting",
        "risk": "High",
        "confidence": "Medium"
    }]
    
    with patch("app.zap.service.get_settings", return_value=mock_settings):
        service = ZAPService()
        service.client = mock_zap_client
        findings = service.run_scan("http://localhost/")
        
        assert len(findings) == 1
        assert findings[0].title == "Cross Site Scripting"
        assert findings[0].severity == Severity.HIGH

def test_zap_service_out_of_scope(mock_settings, mock_zap_client):
    mock_settings.allowed_domains = ["example.com"]
    
    with patch("app.zap.service.get_settings", return_value=mock_settings):
        service = ZAPService()
        service.client = mock_zap_client
        with pytest.raises(ValueError, match="Domain not in allowed list"):
            service.run_scan("http://outofscope.com")

def test_zap_service_spider_timeout(mock_settings, mock_zap_client):
    mock_zap_client.check_connection.return_value = True
    mock_zap_client.start_spider.return_value = "1"
    mock_zap_client.wait_for_spider.return_value = False
    
    with patch("app.zap.service.get_settings", return_value=mock_settings):
        service = ZAPService()
        service.client = mock_zap_client
        with pytest.raises(TimeoutError, match="ZAP Spider timed out."):
            service.run_scan("http://localhost/")

def test_zap_service_active_scan_timeout(mock_settings, mock_zap_client):
    mock_zap_client.check_connection.return_value = True
    mock_zap_client.start_spider.return_value = "1"
    mock_zap_client.wait_for_spider.return_value = True
    mock_zap_client.start_active_scan.return_value = "2"
    mock_zap_client.wait_for_active_scan.return_value = False
    
    with patch("app.zap.service.get_settings", return_value=mock_settings):
        service = ZAPService()
        service.client = mock_zap_client
        with pytest.raises(TimeoutError, match="ZAP Active Scan timed out."):
            service.run_scan("http://localhost/")

def test_http_timeout_configuration(mock_settings):
    mock_settings.request_timeout = 5
    with patch("requests.Session.request") as mock_request:
        mock_response = MagicMock()
        mock_response.json.return_value = {"version": "2.14.0"}
        mock_request.return_value = mock_response
        
        with patch("app.zap.client.get_settings", return_value=mock_settings):
            client = ZAPClient()
            client.check_connection()
            mock_request.assert_called_with('GET', 'http://127.0.0.1:8080/JSON/core/view/version/', params={}, timeout=5)
