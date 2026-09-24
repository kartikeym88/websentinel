from typing import List
from app.analyzers.base import BaseAnalyzer
from app.http.response import NormalizedResponse
from app.findings.models import Finding, Severity, Confidence

class CookieAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "CookieAnalyzer"

    def analyze(self, response: NormalizedResponse) -> List[Finding]:
        findings = []
        url = response.url

        for cookie in response.cookies:
            # Check Secure flag
            if not cookie.secure:
                if response.url.startswith("https://"):
                    severity = Severity.LOW
                    if cookie.is_session_likely:
                        severity = Severity.MEDIUM
                        
                    findings.append(Finding(
                        title=f"Insecure Cookie (Missing Secure Flag): {cookie.name}",
                        category="Cookie Security",
                        url=url,
                        method=response.method,
                        severity=severity,
                        confidence=Confidence.HIGH,
                        evidence=f"Cookie '{cookie.name}' lacks the 'Secure' attribute.",
                        description="Cookies without the Secure flag can be transmitted over unencrypted HTTP connections.",
                        remediation="Add the 'Secure' attribute to the cookie.",
                        scanner_source=self.name
                    ))

            # Check HttpOnly flag
            if not cookie.httponly:
                severity = Severity.LOW
                if cookie.is_session_likely:
                    severity = Severity.HIGH  # High risk for session cookies missing HttpOnly

                findings.append(Finding(
                    title=f"Cookie Missing HttpOnly Flag: {cookie.name}",
                    category="Cookie Security",
                    url=url,
                    method=response.method,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence=f"Cookie '{cookie.name}' lacks the 'HttpOnly' attribute.",
                    description="Cookies without HttpOnly can be accessed via client-side scripts (e.g., JavaScript), increasing XSS risks.",
                    remediation="Add the 'HttpOnly' attribute to the cookie.",
                    scanner_source=self.name
                ))

            # Check SameSite flag
            if not cookie.samesite or cookie.samesite.lower() == 'none':
                # If SameSite=None, it MUST have Secure flag. If not, it's a finding but handled by Secure check? 
                # Modern browsers require Secure if SameSite=None.
                severity = Severity.LOW
                if cookie.is_session_likely:
                    severity = Severity.MEDIUM

                findings.append(Finding(
                    title=f"Permissive SameSite Attribute: {cookie.name}",
                    category="Cookie Security",
                    url=url,
                    method=response.method,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence=f"Cookie '{cookie.name}' has SameSite='{cookie.samesite or 'missing'}'.",
                    description="Without an appropriate SameSite attribute, the application may be vulnerable to CSRF attacks.",
                    remediation="Set the 'SameSite' attribute to 'Lax' or 'Strict'.",
                    scanner_source=self.name
                ))

        return findings
