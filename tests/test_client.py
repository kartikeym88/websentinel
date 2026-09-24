import pytest
import responses
from app.http.client import HTTPClient
from requests.exceptions import RequestException

@responses.activate
def test_successful_request():
    responses.add(responses.GET, 'http://localhost:3000', json={'status': 'ok'}, status=200)
    
    client = HTTPClient()
    response, metadata = client.get('http://localhost:3000')
    
    assert response.status_code == 200
    assert metadata['status_code'] == 200
    assert 'time' in metadata

def test_forbidden_domain():
    client = HTTPClient()
    
    with pytest.raises(ValueError) as excinfo:
        client.get('http://example.com')
        
    assert "Domain not in allowed list" in str(excinfo.value)
