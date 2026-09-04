from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    APP_NAME: str = "CVE Explorer"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite+aiosqlite:///./cve_explorer.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    CIRCL_API: str = "https://cve.circl.lu/api"
    NVD_API: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API: str = "https://api.first.org/data/v1/epss"
    KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_TTL_CVE: int = 86400
    CACHE_TTL_EPSS: int = 21600
    CACHE_TTL_KEV: int = 43200

    class Config:
        env_file = ".env"

@lru_cache
def get_settings() -> Settings:
    return Settings()
