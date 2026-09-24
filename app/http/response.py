from typing import Dict, Any, List
from pydantic import BaseModel
import requests

class CookieInfo(BaseModel):
    name: str
    secure: bool
    httponly: bool
    samesite: str
    is_session_likely: bool

class NormalizedResponse(BaseModel):
    url: str
    status_code: int
    headers: Dict[str, str]
    cookies: List[CookieInfo]
    body: str
    time: float
    method: str
