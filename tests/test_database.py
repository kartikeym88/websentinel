import pytest
from app.database.session import get_session_factory
from app.database.repository import Repository
from app.database.models import Base
from app.findings.models import Finding, Severity, Confidence
from sqlalchemy import create_engine

@pytest.fixture
def db_repo():
    # Use in-memory SQLite for tests
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    
    with session_factory() as session:
        repo = Repository(session)
        yield repo

def test_create_and_get_scan(db_repo):
    scan_id = db_repo.create_scan("http://localhost")
    scan = db_repo.get_scan(scan_id)
    assert scan is not None
    assert scan['target'] == "http://localhost"
    assert scan['status'] == "IN_PROGRESS"

def test_update_scan(db_repo):
    scan_id = db_repo.create_scan("http://localhost")
    db_repo.update_scan(scan_id, status="COMPLETED", pages_discovered=5)
    scan = db_repo.get_scan(scan_id)
    assert scan['status'] == "COMPLETED"
    assert scan['pages_discovered'] == 5
    assert scan['completed_at'] is not None

def test_add_and_get_findings(db_repo):
    scan_id = db_repo.create_scan("http://localhost")
    
    finding1 = Finding(
        title="Test Finding 1",
        category="Test",
        url="http://localhost",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence="Test",
        description="Test",
        remediation="Test",
        scanner_source="test_source"
    )
    
    # Adding finding
    added = db_repo.add_finding(scan_id, finding1)
    assert added is True
    
    findings = db_repo.get_scan_findings(scan_id)
    assert len(findings) == 1
    assert findings[0]['title'] == "Test Finding 1"

def test_get_scan_statistics(db_repo):
    scan_id = db_repo.create_scan("http://localhost")
    
    db_repo.add_finding(scan_id, Finding(
        title="F1", category="Cat", url="http://local", 
        severity=Severity.HIGH, confidence=Confidence.HIGH, 
        evidence="Ev", description="Desc", remediation="Rem", scanner_source="Src"
    ))
    db_repo.add_finding(scan_id, Finding(
        title="F2", category="Cat", url="http://local", 
        severity=Severity.LOW, confidence=Confidence.HIGH, 
        evidence="Ev", description="Desc", remediation="Rem", scanner_source="Src"
    ))
    
    stats = db_repo.get_scan_statistics(scan_id)
    assert stats['total_findings'] == 2
    assert stats['severity_counts']['HIGH'] == 1
    assert stats['severity_counts']['LOW'] == 1

def test_add_page(db_repo):
    scan_id = db_repo.create_scan("http://localhost")
    db_repo.add_page(scan_id, "http://localhost/page", 200, "text/html", 1)
    # The page functionality just verifies it doesn't crash, 
    # we can optionally test retrieval if we added a getter.
