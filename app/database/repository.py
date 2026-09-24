from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from datetime import datetime
import uuid

from app.database.models import ScanModel, FindingModel, PageModel
from app.findings.models import Finding

class Repository:
    """
    Data access layer for scans, findings, and pages.
    Keeps SQLAlchemy imports out of the business logic.
    """
    
    def __init__(self, session: Session):
        self.session = session
        
    def init_db(self, engine):
        """Create tables if they don't exist."""
        from app.database.models import Base
        Base.metadata.create_all(engine)

    def create_scan(self, target: str) -> str:
        scan_id = str(uuid.uuid4())
        scan = ScanModel(
            scan_id=scan_id,
            target=target,
            status="IN_PROGRESS"
        )
        self.session.add(scan)
        self.session.commit()
        return scan_id

    def update_scan(self, scan_id: str, status: Optional[str] = None, 
                    pages_discovered: Optional[int] = None, 
                    requests_made: Optional[int] = None,
                    findings_count: Optional[int] = None):
        
        scan = self.session.get(ScanModel, scan_id)
        if not scan:
            return
            
        if status:
            scan.status = status
            if status in ["COMPLETED", "FAILED"]:
                scan.completed_at = datetime.utcnow()
                
        if pages_discovered is not None:
            scan.pages_discovered = pages_discovered
            
        if requests_made is not None:
            scan.requests_made = requests_made
            
        if findings_count is not None:
            scan.findings_count = findings_count
            
        self.session.commit()

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        scan = self.session.get(ScanModel, scan_id)
        if not scan:
            return None
        return {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "status": scan.status,
            "pages_discovered": scan.pages_discovered,
            "requests_made": scan.requests_made,
            "findings_count": scan.findings_count
        }

    def list_scans(self, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        stmt = select(ScanModel).order_by(ScanModel.started_at.desc()).limit(limit).offset(offset)
        result = self.session.execute(stmt)
        scans = result.scalars().all()
        return [self.get_scan(scan.scan_id) for scan in scans]

    def add_finding(self, scan_id: str, finding: Finding) -> bool:
        """
        Adds a finding directly. Deduplication is handled by FindingAggregator.
        """
        finding_model = FindingModel(
            finding_id=finding.id,
            scan_id=scan_id,
            title=finding.title,
            category=finding.category,
            url=finding.url,
            method=finding.method,
            parameter=finding.parameter,
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            evidence=finding.evidence,
            description=finding.description,
            remediation=finding.remediation,
            scanner_source=finding.scanner_source,
            timestamp=finding.timestamp
        )
        self.session.add(finding_model)
        self.session.commit()
        return True

    def get_scan_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        stmt = select(FindingModel).where(FindingModel.scan_id == scan_id)
        findings = self.session.execute(stmt).scalars().all()
        return [{
            "id": f.finding_id,
            "title": f.title,
            "category": f.category,
            "url": f.url,
            "method": f.method,
            "parameter": f.parameter,
            "severity": f.severity,
            "confidence": f.confidence,
            "evidence": f.evidence,
            "scanner_source": f.scanner_source,
            "timestamp": f.timestamp
        } for f in findings]

    def add_page(self, scan_id: str, url: str, status_code: int, content_type: str, depth: int):
        page_id = str(uuid.uuid4())
        page_model = PageModel(
            page_id=page_id,
            scan_id=scan_id,
            url=url,
            status_code=status_code,
            content_type=content_type,
            depth=depth
        )
        self.session.add(page_model)
        self.session.commit()

    def get_scan_statistics(self, scan_id: str) -> Dict[str, Any]:
        """Aggregate stats for a scan."""
        # Count findings by severity
        stmt = select(FindingModel.severity, func.count()).where(FindingModel.scan_id == scan_id).group_by(FindingModel.severity)
        severity_counts = {sev: count for sev, count in self.session.execute(stmt).all()}
        
        # Get overall scan data
        scan = self.get_scan(scan_id)
        
        return {
            "scan": scan,
            "severity_counts": severity_counts,
            "total_findings": sum(severity_counts.values()) if severity_counts else 0
        }
