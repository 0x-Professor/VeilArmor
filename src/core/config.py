"""
VeilArmor - Configuration Management

Handles loading and validation of application configuration
from YAML files and environment variables.
"""

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# -----------------------------------------------------------------------------
# Nested Configuration Models
# -----------------------------------------------------------------------------

class ClassifierConfig(BaseModel):
    """Classifier configuration."""
    confidence_threshold: float = 0.7
    parallel_execution: bool = True
    enabled_classifiers: List[str] = Field(default_factory=lambda: [
        "prompt_injection", "jailbreak", "pii", "harmful_content"
    ])


class SanitizerConfig(BaseModel):
    """Sanitizer configuration."""
    redact_pii: bool = True
    remove_pii: bool = True  # Alias for redact_pii
    remove_urls: bool = True
    normalize_unicode: bool = True
    redact_placeholder: str = "[REDACTED]"
    max_length: int = 32000


class PipelineConfig(BaseModel):
    """Pipeline configuration."""
    stages: List[str] = Field(default_factory=lambda: [
        "input_processing",
        "input_classification", 
        "decision",
        "input_sanitization",
        "llm_call",
        "output_classification",
        "output_sanitization",
    ])
    block_threshold: str = "HIGH"
    sanitize_threshold: str = "MEDIUM"
    fail_open: bool = False


class SecurityConfig(BaseModel):
    """Security configuration."""
    block_severity: List[str] = Field(default_factory=lambda: ["CRITICAL", "HIGH"])
    sanitize_severity: List[str] = Field(default_factory=lambda: ["MEDIUM", "LOW"])
    classifier: ClassifierConfig = Field(default_factory=ClassifierConfig)
    sanitizer: SanitizerConfig = Field(default_factory=SanitizerConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)


class ServerConfig(BaseModel):
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    cors_enabled: bool = True
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])


class LLMProviderConfig(BaseModel):
    """LLM provider configuration."""
    enabled: bool = True
    api_key: str = ""
    model: str = "gpt-4"
    base_url: Optional[str] = None
    priority: int = 1


class CircuitBreakerConfig(BaseModel):
    """Circuit breaker configuration."""
    enabled: bool = True
    failure_threshold: int = 5
    recovery_timeout: int = 60


class LoadBalancingConfig(BaseModel):
    """Load balancing configuration."""
    strategy: str = "round_robin"
    health_check_interval: int = 30


class LLMConfig(BaseModel):
    """LLM configuration."""
    default_provider: str = "dummy"
    timeout: int = 30
    max_retries: int = 3
    providers: Dict[str, Any] = Field(default_factory=dict)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    load_balancing: LoadBalancingConfig = Field(default_factory=LoadBalancingConfig)


class CacheConfig(BaseModel):
    """Cache configuration."""
    enabled: bool = False
    backend: str = "memory"
    ttl: int = 3600
    similarity_threshold: float = 0.95
    max_entries: int = 10000


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""
    enabled: bool = True
    strategy: str = "sliding_window"
    requests_per_minute: int = 60
    requests_per_hour: int = 1000


class AuthConfig(BaseModel):
    """Authentication configuration."""
    enabled: bool = False
    method: str = "api_key"
    api_keys: List[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    format: str = "json"


class ValidationConfig(BaseModel):
    """Validation configuration."""
    enabled: bool = True
    mode: str = "normal"


class ConversationConfig(BaseModel):
    """Conversation configuration."""
    enabled: bool = True
    storage: str = "memory"
    max_history: int = 50
    ttl: int = 86400


class AppConfig(BaseModel):
    """Application configuration."""
    name: str = "VeilArmor"
    version: str = "2.0.0"
    environment: str = "development"
    debug: bool = False


class Settings(BaseSettings):
    """
    Main application settings.
    
    Settings are loaded from:
    1. Default values
    2. YAML configuration file (config/settings.yaml)
    3. Environment variables (VEILARMOR_ prefix)
    """
    
    app: AppConfig = Field(default_factory=AppConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    conversation: ConversationConfig = Field(default_factory=ConversationConfig)
    
    class Config:
        env_prefix = "VEILARMOR_"
        extra = "ignore"  # Ignore extra fields from YAML
    
    @classmethod
    def from_yaml(cls, path: str = "config/settings.yaml") -> "Settings":
        """Load settings from YAML file."""
        config_path = Path(path)
        
        if config_path.exists():
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}
            
            # Map flat YAML fields to nested structure
            mapped_data = cls._map_config(config_data)
            return cls(**mapped_data)
        
        return cls()
    
    @classmethod
    def _map_config(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map YAML config to Settings structure."""
        result = {}
        
        # Map app settings
        result["app"] = {
            "name": data.get("app_name", "VeilArmor"),
            "version": data.get("version", "2.0.0"),
            "environment": data.get("environment", "development"),
            "debug": data.get("debug", False),
        }
        
        # Map server settings
        if "server" in data:
            result["server"] = data["server"]
        
        # Map security settings
        security = {}
        if "security" in data:
            security = data["security"]
        
        # Map classifiers to security.classifier
        if "classifiers" in data:
            classifier_config = data["classifiers"]
            security.setdefault("classifier", {})
            security["classifier"]["parallel_execution"] = classifier_config.get(
                "parallel_execution", True
            )
        
        if security:
            result["security"] = security
        
        # Map LLM settings
        if "llm" in data:
            result["llm"] = data["llm"]
        
        # Map cache settings
        if "cache" in data:
            result["cache"] = data["cache"]
        
        # Map rate limiting
        if "rate_limit" in data:
            result["rate_limiting"] = data["rate_limit"]
        
        # Map auth
        if "auth" in data:
            result["auth"] = data["auth"]
        
        # Map logging
        if "logging" in data:
            result["logging"] = data["logging"]
        
        # Map validation
        if "validation" in data:
            result["validation"] = data["validation"]
        
        # Map conversation
        if "conversation" in data:
            result["conversation"] = data["conversation"]
        
        return result


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings.from_yaml()


def reload_settings() -> Settings:
    """Reload settings (clears cache)."""
    get_settings.cache_clear()
    return get_settings()
