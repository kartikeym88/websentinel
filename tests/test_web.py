import pytest
from app.web import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_security_headers_present(client):
    response = client.get('/')
    assert response.status_code == 200
    
    headers = response.headers
    assert 'Content-Security-Policy' in headers
    assert "default-src 'self'" in headers['Content-Security-Policy']
    assert 'X-Content-Type-Options' in headers
    assert headers['X-Content-Type-Options'] == 'nosniff'
    assert 'Referrer-Policy' in headers
    assert headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
    assert 'Permissions-Policy' in headers
    assert 'geolocation=()' in headers['Permissions-Policy']
    assert 'X-Frame-Options' in headers
    assert headers['X-Frame-Options'] == 'SAMEORIGIN'

def test_robots_txt(client):
    response = client.get('/robots.txt')
    assert response.status_code == 200
    text = response.data.decode('utf-8')
    assert 'User-agent: *' in text
    assert 'Disallow: /scan/' in text
    assert 'Disallow: /report/' in text

def test_format_datetime_ist():
    from app.web.__init__ import format_datetime_ist
    from datetime import datetime, timezone
    
    # Test datetime without timezone (should assume UTC and convert to IST +5:30)
    dt_utc = datetime(2023, 1, 1, 12, 0, 0)
    ist_str = format_datetime_ist(dt_utc)
    assert ist_str == "2023-01-01 17:30:00 IST"
    
    # Test datetime with timezone
    dt_aware = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    ist_str_aware = format_datetime_ist(dt_aware)
    assert ist_str_aware == "2023-01-01 17:30:00 IST"
    
    # Test string (ISO format without Z)
    ist_str_from_iso = format_datetime_ist("2023-01-01T12:00:00")
    assert ist_str_from_iso == "2023-01-01 17:30:00 IST"
