import pytest
import threading
import time
from app.core.scan_manager import ScanManager
from app.database.session import get_engine, get_session_factory
from app.database.repository import Repository
from tests.fixtures.test_site.app import app, run_server
import sqlalchemy

@pytest.fixture(scope="module")
def test_server():
    server_thread = threading.Thread(target=run_server, kwargs={'port': 5002})
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(1)
    
    yield "http://127.0.0.1:5002"

@pytest.fixture
def scan_manager(monkeypatch):
    # Patch get_engine to use in-memory DB for test
    engine = sqlalchemy.create_engine("sqlite:///:memory:")
    monkeypatch.setattr('app.database.session.get_engine', lambda: engine)
    
    manager = ScanManager()
    return manager

def test_end_to_end_scan(scan_manager, test_server):
    # Run the scan
    scan_id = scan_manager.run_scan(test_server)
    
    # Retrieve from DB
    engine = scan_manager.engine
    session_factory = get_session_factory(engine)
    
    with session_factory() as db_session:
        repo = Repository(db_session)
        
        scan = repo.get_scan(scan_id)
        assert scan is not None
        assert scan['status'] == "COMPLETED"
        assert scan['pages_discovered'] > 0
        
        findings = repo.get_scan_findings(scan_id)
        assert len(findings) > 0
        
        # Verify deduplication (forms deduplicated across multiple pages should result in fewer total findings than if just blindly added)
        # We can just verify there are no duplicate URLs/titles in the findings
        fingerprints = set()
        for f in findings:
            fp = f"{f['category']}|{f['url']}|{f['title']}|{f['parameter']}"
            assert fp not in fingerprints, f"Duplicate found: {fp}"
            fingerprints.add(fp)
            
        # Verify pages are persisted
        pages_count = len(repo.session.execute(sqlalchemy.text(f"SELECT * FROM pages WHERE scan_id = '{scan_id}'")).all())
        assert pages_count > 0
