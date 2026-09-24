import time
from app.core.logger import setup_logger
from app.http.client import HTTPClient
from app.crawler.spider import Spider
from app.analyzers.runner import AnalyzerRunner
from app.findings.aggregator import FindingAggregator
from app.database.session import get_engine, get_session_factory
from app.database.repository import Repository
from app.analyzers.headers import SecurityHeaderAnalyzer
from app.analyzers.cookies import CookieAnalyzer
from app.zap.service import ZAPService

class ScanManager:
    def __init__(self):
        self.logger = setup_logger(__name__)
        self.engine = get_engine()
        self.session_factory = get_session_factory(self.engine)
        
    def run_scan(self, target: str) -> str:
        self.logger.info(f"Starting scan for {target}")
        start_time = time.time()
        
        with self.session_factory() as db_session:
            repo = Repository(db_session)
            repo.init_db(self.engine)
            
            # 1. Create Scan in DB
            scan_id = repo.create_scan(target)
            repo.update_scan(scan_id, status="QUEUED")
            
            try:
                repo.update_scan(scan_id, status="RUNNING")
                # 2. Run Crawler
                repo.update_scan(scan_id, status="CRAWLING")
                client = HTTPClient()
                spider = Spider(client, target)
                crawl_result = spider.crawl()
                
                # 3. Analyze Responses
                repo.update_scan(scan_id, status="ANALYZING")
                analyzer_runner = AnalyzerRunner()
                analyzer_runner.register_analyzer(SecurityHeaderAnalyzer())
                analyzer_runner.register_analyzer(CookieAnalyzer())
                
                aggregator = FindingAggregator()
                
                pages_success = 0
                pages_failed = 0
                zap_failed = False
                
                # Bulk add pages?
                for page in crawl_result.pages:
                    repo.add_page(
                        scan_id=scan_id, 
                        url=page.url, 
                        status_code=page.status_code, 
                        content_type=page.content_type, 
                        depth=page.depth
                    )
                    
                    if 200 <= page.status_code < 400:
                        pages_success += 1
                        findings = analyzer_runner.analyze_response(page.response)
                        aggregator.add_findings(findings)
                    else:
                        pages_failed += 1
                        
                # 3.5 Run ZAP Scan
                repo.update_scan(scan_id, status="ZAP_SCANNING")
                try:
                    zap_service = ZAPService()
                    zap_findings = zap_service.run_scan(target)
                    aggregator.add_findings(zap_findings)
                except Exception as e:
                    zap_failed = True
                    self.logger.error(f"ZAP scan failed, continuing: {e}")
                
                # 4. Deduplicate Findings
                repo.update_scan(scan_id, status="AGGREGATING")
                final_findings = aggregator.get_deduplicated_findings()
                
                # 5. Persist Findings
                for f in final_findings:
                    repo.add_finding(scan_id, f)
                    
                # 6. Update Scan Statistics
                duration = time.time() - start_time
                status = "COMPLETED" if (pages_failed == 0 and not zap_failed) else "COMPLETED_WITH_WARNINGS"
                
                repo.update_scan(
                    scan_id=scan_id,
                    status=status,
                    pages_discovered=len(crawl_result.pages),
                    requests_made=len(spider.visited),
                    findings_count=len(final_findings)
                )
                self.logger.info(f"Scan completed in {duration:.2f}s. Found {len(final_findings)} issues.")
                
            except Exception as e:
                self.logger.error(f"Scan failed: {e}")
                repo.update_scan(scan_id, status="FAILED")
                
            return scan_id
