from typing import List, Dict, Any, Set
from pydantic import BaseModel
from app.http.response import NormalizedResponse

class CrawledPage(BaseModel):
    url: str
    depth: int
    status_code: int
    content_type: str
    response: NormalizedResponse  # Keep the normalized response for analyzers

class CrawlResult(BaseModel):
    pages: List[CrawledPage]
    forms: List[Dict[str, Any]]
    parameters: Set[str]
