from typing import List, Dict, Tuple
from app.findings.models import Finding
from app.core.logger import setup_logger
import hashlib

class FindingAggregator:
    def __init__(self):
        self.logger = setup_logger(__name__)
        self.findings: List[Finding] = []

    def add_findings(self, new_findings: List[Finding]):
        self.findings.extend(new_findings)

    def _generate_fingerprint(self, finding: Finding) -> str:
        """
        Creates a deterministic fingerprint based on:
        - category
        - url (normalized to base path without fragments)
        - method
        - parameter
        - title
        """
        url = finding.url.split('#')[0]
        components = [
            finding.category,
            url,
            finding.method,
            finding.parameter or "",
            finding.title
        ]
        raw = "|".join(components).encode('utf-8')
        return hashlib.md5(raw).hexdigest()

    def get_deduplicated_findings(self) -> List[Finding]:
        """
        Deduplicates findings using the fingerprint.
        If a finding has multiple scanner_sources, it concatenates them.
        """
        unique_map: Dict[str, Finding] = {}
        
        for finding in self.findings:
            fingerprint = self._generate_fingerprint(finding)
            
            if fingerprint in unique_map:
                existing = unique_map[fingerprint]
                # Combine scanner sources if they are different
                sources = set(existing.scanner_source.split(','))
                new_sources = set(finding.scanner_source.split(','))
                combined = sorted(list(sources | new_sources))
                existing.scanner_source = ",".join(combined)
            else:
                unique_map[fingerprint] = finding
                
        return list(unique_map.values())
