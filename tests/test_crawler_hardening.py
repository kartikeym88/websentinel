import pytest
import responses
from app.http.client import HTTPClient
from app.crawler.spider import Spider

@responses.activate
def test_url_normalization():
    # 1. URL normalization (fragments removed, duplicates handled)
    responses.add(responses.GET, 'http://localhost:3000/', body='<a href="/page#fragment">1</a> <a href="/page">2</a>', status=200, headers={'Content-Type': 'text/html'})
    responses.add(responses.GET, 'http://localhost:3000/page', body='<html></html>', status=200, headers={'Content-Type': 'text/html'})
    
    client = HTTPClient()
    spider = Spider(client, 'http://localhost:3000/')
    spider.crawl()
    
    assert 'http://localhost:3000/page' in spider.visited
    assert 'http://localhost:3000/page#fragment' not in spider.visited
    assert len(spider.visited) == 2 # root and /page

@responses.activate
def test_crawl_depth():
    # 2. Crawl depth (0, 1, 2)
    responses.add(responses.GET, 'http://localhost:3000/', body='<a href="/1">1</a>', status=200, headers={'Content-Type': 'text/html'})
    responses.add(responses.GET, 'http://localhost:3000/1', body='<a href="/2">2</a>', status=200, headers={'Content-Type': 'text/html'})
    responses.add(responses.GET, 'http://localhost:3000/2', body='<a href="/3">3</a>', status=200, headers={'Content-Type': 'text/html'})
    
    # Test depth 0
    spider_depth0 = Spider(HTTPClient(), 'http://localhost:3000/', max_depth=0)
    spider_depth0.crawl()
    assert 'http://localhost:3000/' in spider_depth0.visited
    assert 'http://localhost:3000/1' not in spider_depth0.visited
    
    # Test depth 1
    spider_depth1 = Spider(HTTPClient(), 'http://localhost:3000/', max_depth=1)
    spider_depth1.crawl()
    assert 'http://localhost:3000/1' in spider_depth1.visited
    assert 'http://localhost:3000/2' not in spider_depth1.visited

@responses.activate
def test_domain_restriction():
    # 3. Domain restriction (internal accepted, external rejected)
    responses.add(responses.GET, 'http://localhost:3000/', body='<a href="/internal">1</a> <a href="http://external.com">2</a> <a href="http://sub.localhost:3000">3</a>', status=200, headers={'Content-Type': 'text/html'})
    responses.add(responses.GET, 'http://localhost:3000/internal', body='', status=200, headers={'Content-Type': 'text/html'})
    
    spider = Spider(HTTPClient(), 'http://localhost:3000/')
    spider.crawl()
    
    assert 'http://localhost:3000/internal' in spider.visited
    assert 'http://external.com' not in spider.visited
    assert 'http://sub.localhost:3000' not in spider.visited # Strict domain matching

@responses.activate
def test_forms():
    # 4. Forms
    html = '''
    <form action="/get" method="GET">
        <input type="text" name="q">
    </form>
    <form action="/post" method="POST">
        <input type="text" name="user">
        <textarea name="desc"></textarea>
        <select name="choice"></select>
    </form>
    '''
    responses.add(responses.GET, 'http://localhost:3000/', body=html, status=200, headers={'Content-Type': 'text/html'})
    
    spider = Spider(HTTPClient(), 'http://localhost:3000/')
    spider.crawl()
    
    assert len(spider.forms) == 2
    
    get_form = next(f for f in spider.forms if f['method'] == 'GET')
    assert get_form['action'] == 'http://localhost:3000/get'
    assert 'q' in get_form['inputs']
    
    post_form = next(f for f in spider.forms if f['method'] == 'POST')
    assert post_form['action'] == 'http://localhost:3000/post'
    assert set(post_form['inputs']) == {'user', 'desc', 'choice'}

@responses.activate
def test_error_handling():
    # 5. Error handling
    responses.add(responses.GET, 'http://localhost:3000/', body='<a href="/404">1</a> <a href="/error">2</a>', status=200, headers={'Content-Type': 'text/html'})
    responses.add(responses.GET, 'http://localhost:3000/404', body='not found', status=404, headers={'Content-Type': 'text/html'})
    # /error will not be registered, raising a connection error in responses
    
    spider = Spider(HTTPClient(), 'http://localhost:3000/')
    spider.crawl()
    
    # Should not crash and should visit the root
    assert 'http://localhost:3000/' in spider.visited
    assert 'http://localhost:3000/404' in spider.visited

@responses.activate
def test_content_types():
    # 6. Content types
    responses.add(responses.GET, 'http://localhost:3000/', body='<a href="/text">1</a> <a href="/bin">2</a>', status=200, headers={'Content-Type': 'text/html'})
    responses.add(responses.GET, 'http://localhost:3000/text', body='just text', status=200, headers={'Content-Type': 'text/plain'})
    responses.add(responses.GET, 'http://localhost:3000/bin', body=b'\x00\x01', status=200, headers={'Content-Type': 'application/octet-stream'})
    
    spider = Spider(HTTPClient(), 'http://localhost:3000/')
    spider.crawl()
    
    assert 'http://localhost:3000/text' in spider.visited
    assert 'http://localhost:3000/bin' in spider.visited

@responses.activate
def test_crawl_limits():
    # 7. Crawl limits
    responses.add(responses.GET, 'http://localhost:3000/', body='<a href="/1">1</a>', status=200, headers={'Content-Type': 'text/html'})
    responses.add(responses.GET, 'http://localhost:3000/1', body='<a href="/2">2</a>', status=200, headers={'Content-Type': 'text/html'})
    responses.add(responses.GET, 'http://localhost:3000/2', body='<a href="/3">3</a>', status=200, headers={'Content-Type': 'text/html'})
    
    spider = Spider(HTTPClient(), 'http://localhost:3000/', max_pages=2)
    spider.crawl()
    
    assert len(spider.visited) == 2
    assert 'http://localhost:3000/2' not in spider.visited
