from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    target_url: str = "http://localhost:3000"
    allowed_domains: List[str] = ["localhost", "127.0.0.1"]
    
    crawl_depth: int = 3
    max_pages: int = 100
    
    request_timeout: int = 10
    concurrency: int = 5
    rate_limit: int = 10
    user_agent: str = "SecurityScanner/1.0"
    
    report_dir: str = "reports"
    database_path: str = "data/scanner.db"
    log_dir: str = "logs"
    
    zap_enabled: bool = False
    zap_host: str = "127.0.0.1"
    zap_port: int = 8080
    zap_api_key: str = ""
    zap_timeout: int = 300

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

def get_settings() -> Settings:
    return Settings()
