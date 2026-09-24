import pytest
import responses
from app.http.response import NormalizedResponse, CookieInfo
from app.findings.models import Finding, Severity, Confidence
from app.analyzers.headers import SecurityHeaderAnalyzer
from app.analyzers.cookies import CookieAnalyzer
from app.analyzers.runner import AnalyzerRunner
from app.http.client import HTTPClient
import time

def test_finding_model():
    # Test Finding fields and enums
    f = Finding(
        title="Test Finding",
        category="Test",
        url="http://test.com",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        evidence="evidence",
        description="description",
        remediation="remediation",
        scanner_source="test_source"
    )
    assert f.severity.value == "LOW"
    assert f.confidence.value == "HIGH"
    assert f.id is not None
    assert f.timestamp is not None

def test_headers_all_present():
    headers = {
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': "max-age=31536000",
        'x-content-type-options': "nosniff",
        'referrer-policy': "strict-origin",
        'permissions-policy': "geolocation=()",
        'x-frame-options': "DENY"
    }
    resp = NormalizedResponse(
        url="https://example.com",
        status_code=200,
        headers=headers,
        cookies=[],
        body="",
        time=0.1,
        method="GET"
    )
    
    analyzer = SecurityHeaderAnalyzer()
    findings = analyzer.analyze(resp)
    
    assert len(findings) == 0

def test_headers_missing():
    headers = {}
    resp = NormalizedResponse(
        url="https://example.com",
        status_code=200,
        headers=headers,
        cookies=[],
        body="",
        time=0.1,
        method="GET"
    )
    
    analyzer = SecurityHeaderAnalyzer()
    findings = analyzer.analyze(resp)
    
    titles = [f.title for f in findings]
    
    assert "Missing Content-Security-Policy" in titles
    assert "Missing Strict-Transport-Security (HSTS)" in titles
    assert "Missing or Incorrect X-Content-Type-Options" in titles
    assert "Missing Referrer-Policy" in titles
    assert "Missing Permissions-Policy" in titles
    assert "Missing Clickjacking Protection" in titles

def test_hsts_ignored_on_http():
    headers = {}
    resp = NormalizedResponse(
        url="http://example.com", # HTTP, not HTTPS
        status_code=200,
        headers=headers,
        cookies=[],
        body="",
        time=0.1,
        method="GET"
    )
    
    analyzer = SecurityHeaderAnalyzer()
    findings = analyzer.analyze(resp)
    
    titles = [f.title for f in findings]
    assert "Missing Strict-Transport-Security (HSTS)" not in titles

def test_csp_frame_ancestors():
    headers = {
        'content-security-policy': "frame-ancestors 'none'",
    }
    resp = NormalizedResponse(
        url="http://example.com",
        status_code=200,
        headers=headers,
        cookies=[],
        body="",
        time=0.1,
        method="GET"
    )
    
    analyzer = SecurityHeaderAnalyzer()
    findings = analyzer.analyze(resp)
    
    titles = [f.title for f in findings]
    assert "Missing Clickjacking Protection" not in titles

def test_cookies_analyzer():
    # Session cookie missing HttpOnly (High Severity)
    c1 = CookieInfo(name="sessionid", secure=True, httponly=False, samesite="Strict", is_session_likely=True)
    # Non-session cookie missing Secure on HTTPS (Low Severity)
    c2 = CookieInfo(name="pref", secure=False, httponly=True, samesite="Lax", is_session_likely=False)
    # Session cookie missing SameSite (Medium Severity)
    c3 = CookieInfo(name="auth", secure=True, httponly=True, samesite="", is_session_likely=True)
    # Good cookie
    c4 = CookieInfo(name="good", secure=True, httponly=True, samesite="Strict", is_session_likely=False)
    
    resp = NormalizedResponse(
        url="https://example.com",
        status_code=200,
        headers={},
        cookies=[c1, c2, c3, c4],
        body="",
        time=0.1,
        method="GET"
    )
    
    analyzer = CookieAnalyzer()
    findings = analyzer.analyze(resp)
    
    assert len(findings) == 3
    
    httponly_finding = next(f for f in findings if "Missing HttpOnly" in f.title)
    assert httponly_finding.severity == Severity.HIGH
    assert "sessionid" in httponly_finding.evidence
    
    secure_finding = next(f for f in findings if "Missing Secure" in f.title)
    assert secure_finding.severity == Severity.LOW
    assert "pref" in secure_finding.evidence
    
    samesite_finding = next(f for f in findings if "SameSite" in f.title)
    assert samesite_finding.severity == Severity.MEDIUM
    assert "auth" in samesite_finding.evidence

@responses.activate
def test_scan_manager_integration():
    responses.add(responses.GET, 'http://localhost:3000', status=200, headers={'Content-Type': 'text/html'})
    
    client = HTTPClient()
    response, metadata = client.get('http://localhost:3000')
    normalized = response.normalized()
    
    manager = AnalyzerRunner()
    manager.register_analyzer(SecurityHeaderAnalyzer())
    manager.register_analyzer(CookieAnalyzer())
    
    findings = manager.analyze_response(normalized)
    
    # Should find missing headers
    assert len(findings) > 0
    assert any(f.category == "Security Headers" for f in findings)
