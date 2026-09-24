import os
from app.core.config import get_settings

def test_default_config():
    settings = get_settings()
    assert settings.target_url == "http://localhost:3000"
    assert "localhost" in settings.allowed_domains
    assert settings.request_timeout == 10
