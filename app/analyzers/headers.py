from typing import List
from app.analyzers.base import BaseAnalyzer
from app.http.response import NormalizedResponse
from app.findings.models import Finding, Severity, Confidence

class SecurityHeaderAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "SecurityHeaderAnalyzer"

    def analyze(self, response: NormalizedResponse) -> List[Finding]:
        findings = []
        headers = response.headers # lowercase keys
        url = response.url
        is_https = url.startswith("https://")

        # 1. Content-Security-Policy
        csp = headers.get('content-security-policy')
        if not csp:
            findings.append(Finding(
                title="Missing Content-Security-Policy",
                category="Security Headers",
                url=url,
                method=response.method,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence="The 'Content-Security-Policy' header is missing from the response.",
                description="CSP is an added layer of security that helps to detect and mitigate certain types of attacks, including XSS and data injection attacks.",
                remediation="Configure a Content-Security-Policy header with appropriate directives.",
                scanner_source=self.name
            ))

        # 2. Strict-Transport-Security (HSTS)
        if is_https:
            hsts = headers.get('strict-transport-security')
            if not hsts:
                findings.append(Finding(
                    title="Missing Strict-Transport-Security (HSTS)",
                    category="Security Headers",
                    url=url,
                    method=response.method,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence="The 'Strict-Transport-Security' header is missing from the HTTPS response.",
                    description="HSTS ensures that connections to the server are always established over HTTPS.",
                    remediation="Add the 'Strict-Transport-Security' header to all HTTPS responses.",
                    scanner_source=self.name
                ))

        # 3. X-Content-Type-Options
        xcto = headers.get('x-content-type-options')
        if not xcto or xcto.lower() != 'nosniff':
            findings.append(Finding(
                title="Missing or Incorrect X-Content-Type-Options",
                category="Security Headers",
                url=url,
                method=response.method,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=f"Found: {xcto}" if xcto else "Header is missing.",
                description="The X-Content-Type-Options header protects against MIME sniffing vulnerabilities.",
                remediation="Set the 'X-Content-Type-Options' header to 'nosniff'.",
                scanner_source=self.name
            ))

        # 4. Referrer-Policy
        rp = headers.get('referrer-policy')
        if not rp:
            findings.append(Finding(
                title="Missing Referrer-Policy",
                category="Security Headers",
                url=url,
                method=response.method,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                evidence="The 'Referrer-Policy' header is missing.",
                description="Referrer-Policy controls how much referrer information is included with requests.",
                remediation="Set an appropriate Referrer-Policy such as 'strict-origin-when-cross-origin'.",
                scanner_source=self.name
            ))

        # 5. Permissions-Policy
        pp = headers.get('permissions-policy')
        if not pp:
            findings.append(Finding(
                title="Missing Permissions-Policy",
                category="Security Headers",
                url=url,
                method=response.method,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                evidence="The 'Permissions-Policy' header is missing.",
                description="Permissions-Policy allows control over which web features and APIs can be used in the browser.",
                remediation="Configure a Permissions-Policy header to restrict sensitive APIs.",
                scanner_source=self.name
            ))

        # 6. Frame Protection (X-Frame-Options or CSP frame-ancestors)
        xfo = headers.get('x-frame-options')
        has_csp_frame_ancestors = csp and 'frame-ancestors' in csp.lower()
        
        if not xfo and not has_csp_frame_ancestors:
            findings.append(Finding(
                title="Missing Clickjacking Protection",
                category="Security Headers",
                url=url,
                method=response.method,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence="Neither 'X-Frame-Options' nor 'Content-Security-Policy: frame-ancestors' were found.",
                description="Without frame protection, the site may be vulnerable to Clickjacking attacks.",
                remediation="Set 'X-Frame-Options: DENY' or use CSP 'frame-ancestors'.",
                scanner_source=self.name
            ))

        return findings
