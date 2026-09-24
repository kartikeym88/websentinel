import requests
from requests.exceptions import RequestException
import time
from urllib.parse import urlparse
from app.core.config import get_settings
from app.core.logger import setup_logger

logger = setup_logger(__name__)

class HTTPClient:
    def __init__(self):
        self.settings = get_settings()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.settings.user_agent})
        
    def is_allowed_domain(self, url: str) -> bool:
        try:
            domain = urlparse(url).hostname
            if not domain:
                return False
            
            # Simple exact match for now
            return domain in self.settings.allowed_domains
        except Exception:
            return False

    def request(self, method: str, url: str, **kwargs):
        if not self.is_allowed_domain(url):
            logger.warning(f"Attempted to access forbidden domain: {url}")
            raise ValueError(f"Domain not in allowed list: {url}")
            
        kwargs.setdefault('timeout', self.settings.request_timeout)
        kwargs.setdefault('allow_redirects', True)
        
        start_time = time.time()
        try:
            response = self.session.request(method, url, **kwargs)
            elapsed = time.time() - start_time
            
            logger.info(f"{method} {url} - Status: {response.status_code} - Time: {elapsed:.3f}s")
            
            # Simple metadata extraction
            metadata = {
                "url": url,
                "status_code": response.status_code,
                "time": elapsed,
                "content_type": response.headers.get('Content-Type', 'unknown')
            }
            
            # For backward compatibility, attach a method to get normalized response
            response.normalized = lambda: self._normalize_response(response, url, method, elapsed)
            
            return response, metadata
            
        except RequestException as e:
            elapsed = time.time() - start_time
            logger.error(f"{method} {url} - Error: {str(e)} - Time: {elapsed:.3f}s")
            raise

    def get(self, url: str, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request('POST', url, **kwargs)

    def _normalize_response(self, response: requests.Response, url: str, method: str, elapsed: float):
        from app.http.response import NormalizedResponse, CookieInfo
        
        cookies_info = []
        for cookie in response.cookies:
            name_lower = cookie.name.lower()
            is_session = any(k in name_lower for k in ['session', 'token', 'auth', 'sid'])
            
            secure = cookie.secure
            httponly = False
            samesite = ""
            
            if hasattr(cookie, 'has_nonstandard_attr'):
                if cookie.has_nonstandard_attr('HttpOnly'):
                    httponly = True
                if cookie.has_nonstandard_attr('SameSite'):
                    samesite = cookie.get_nonstandard_attr('SameSite')
            
            cookies_info.append(CookieInfo(
                name=cookie.name,
                secure=secure,
                httponly=httponly,
                samesite=str(samesite),
                is_session_likely=is_session
            ))
            
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        return NormalizedResponse(
            url=url,
            status_code=response.status_code,
            headers=headers_lower,
            cookies=cookies_info,
            body=response.text,
            time=elapsed,
            method=method
        )
