from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from collections import deque
from app.http.client import HTTPClient
from app.core.logger import setup_logger

logger = setup_logger(__name__)

class Spider:
    def __init__(self, client: HTTPClient, base_url: str, max_depth: int = 3, max_pages: int = 100):
        self.client = client
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.base_domain = urlparse(base_url).netloc
        
        self.visited = set()
        self.forms = []
        self.parameters = set()
        self.links = set()

    def _is_internal(self, url: str) -> bool:
        domain = urlparse(url).netloc
        return domain == self.base_domain or domain == ''

    def crawl(self) -> 'app.crawler.models.CrawlResult':
        from app.crawler.models import CrawlResult, CrawledPage
        
        queue = deque([(self.base_url, 0)])
        crawled_pages = []
        
        while queue:
            if len(self.visited) >= self.max_pages:
                logger.info(f"Reached max pages limit ({self.max_pages})")
                break
                
            url, depth = queue.popleft()
            
            if url in self.visited or depth > self.max_depth:
                continue
                
            self.visited.add(url)
            logger.info(f"Crawling: {url} (Depth: {depth})")
            
            try:
                response, metadata = self.client.get(url)
                
                # Handle non-HTML resources
                content_type = metadata.get('content_type', '')
                if 'text/html' not in content_type:
                    logger.info(f"Skipping non-HTML resource: {url}")
                    crawled_pages.append(CrawledPage(
                        url=url, depth=depth, status_code=metadata.get('status_code', 200),
                        content_type=content_type, response=response.normalized()
                    ))
                    continue
                    
                self._parse_page(response.text, url, depth, queue)
                crawled_pages.append(CrawledPage(
                    url=url, depth=depth, status_code=metadata.get('status_code', 200),
                    content_type=content_type, response=response.normalized()
                ))
            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")
                
        return CrawlResult(
            pages=crawled_pages,
            forms=self.forms,
            parameters=self.parameters
        )

    def _parse_page(self, html: str, current_url: str, depth: int, queue: deque):
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(current_url, href)
            
            # Extract parameters
            parsed = urlparse(full_url)
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        self.parameters.add(param.split('=')[0])
            
            # Clean URL for deduplication
            clean_url = full_url.split('#')[0]
            
            if self._is_internal(clean_url):
                self.links.add(clean_url)
                if clean_url not in self.visited:
                    queue.append((clean_url, depth + 1))
            else:
                logger.debug(f"Skipping external link: {full_url}")

        # Extract forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = []
            
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                if name:
                    inputs.append(name)
                    
            self.forms.append({
                'action': urljoin(current_url, action),
                'method': method,
                'inputs': inputs
            })
