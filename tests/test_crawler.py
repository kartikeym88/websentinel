import pytest
import threading
import time
from app.http.client import HTTPClient
from app.crawler.spider import Spider
from tests.fixtures.test_site.app import app, run_server

@pytest.fixture(scope="module")
def test_server():
    # Start the Flask app in a background thread
    server_thread = threading.Thread(target=run_server, kwargs={'port': 5001})
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for the server to start
    time.sleep(1)
    
    yield "http://127.0.0.1:5001"
    
    # Thread will be killed when tests finish (daemon)

def test_crawler(test_server):
    client = HTTPClient()
    spider = Spider(client, test_server, max_depth=2)
    spider.crawl()
    
    # Verify internal links are discovered
    assert f"{test_server}/page1" in spider.links
    assert f"{test_server}/nested/page2" in spider.links
    
    # Verify external links are excluded (should not be in links)
    assert "https://example.com" not in spider.links
    
    # Verify duplicate URLs are removed
    assert len(spider.visited) == len(set(spider.visited))
    
    # Verify forms are discovered
    assert len(spider.forms) >= 1
    form_actions = [f['action'] for f in spider.forms]
    assert f"{test_server}/submit" in form_actions
    form = spider.forms[0]
    assert form['method'] == "POST"
    assert "username" in form['inputs']
    assert "password" in form['inputs']
    
    # Verify parameters are discovered
    assert "param" in spider.parameters
    
    # Verify non-HTML resources are handled correctly (skipped from crawling/parsing)
    assert f"{test_server}/resource.txt" in spider.visited # It's visited but parsed as non-HTML
