"""Configuration management"""

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class ClassifierConfig(BaseModel):
    confidence_threshold: float = 0.7


class SanitizerConfig(BaseModel):
    redact_pii: bool = True
    redact_placeholder: str = "[REDACTED]"


class SecurityConfig(BaseModel):
    block_severity: List[str] = ["CRITICAL", "HIGH"]
    sanitize_severity: List[str] = ["MEDIUM", "LOW"]
    classifier: ClassifierConfig = ClassifierConfig()
    sanitizer: SanitizerConfig = SanitizerConfig()


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class LLMConfig(BaseModel):
    provider: str = "dummy"
    timeout: int = 30


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


class AppConfig(BaseModel):
    name: str = "VeilArmor"
    version: str = "1.0.0"
    debug: bool = False


class Settings(BaseSettings):
    """Application settings"""
    
    app: AppConfig = AppConfig()
    server: ServerConfig = ServerConfig()
    security: SecurityConfig = SecurityConfig()
    llm: LLMConfig = LLMConfig()
    logging: LoggingConfig = LoggingConfig()
    
    class Config:
        env_prefix = "VEIL_ARMOR_"
    
    @classmethod
    def from_yaml(cls, path: str = "config/settings.yaml") -> "Settings":
        """Load settings from YAML file"""
        config_path = Path(path)
        
        if config_path.exists():
            with open(config_path) as f:
                config_data = yaml.safe_load(f)
                return cls(**config_data)
        
        return cls()


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings.from_yaml()