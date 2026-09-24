from typing import List
from app.http.response import NormalizedResponse
from app.findings.models import Finding
from app.analyzers.base import BaseAnalyzer
from app.core.logger import setup_logger

class AnalyzerRunner:
    def __init__(self):
        self.analyzers: List[BaseAnalyzer] = []
        self.logger = setup_logger(__name__)

    def register_analyzer(self, analyzer: BaseAnalyzer):
        self.analyzers.append(analyzer)

    def analyze_response(self, response: NormalizedResponse) -> List[Finding]:
        all_findings = []
        for analyzer in self.analyzers:
            self.logger.info(f"Running analyzer: {analyzer.name}")
            try:
                findings = analyzer.analyze(response)
                all_findings.extend(findings)
                self.logger.info(f"Analyzer {analyzer.name} completed. Found {len(findings)} issues.")
            except Exception as e:
                self.logger.error(f"Analyzer {analyzer.name} failed: {e}")
                
        return all_findings
