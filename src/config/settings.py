"""
VeilArmor v2.0 - Settings Management

Centralized configuration management with support for:
- Environment variables
- YAML configuration files
- Runtime configuration updates
- Configuration validation
"""

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Application environment."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class LogLevel(str, Enum):
    """Log level enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class CacheBackend(str, Enum):
    """Cache backend types."""
    MEMORY = "memory"
    REDIS = "redis"
    DISK = "disk"


# =============================================================================
# Configuration Models
# =============================================================================

class ClassifierConfig(BaseModel):
    """Configuration for a single classifier."""
    
    name: str
    enabled: bool = True
    weight: float = Field(default=1.0, ge=0.0, le=10.0)
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    timeout_seconds: float = Field(default=5.0, gt=0)
    options: Dict[str, Any] = Field(default_factory=dict)


class ClassifiersConfig(BaseModel):
    """Configuration for all classifiers."""
    
    # Input classifiers
    prompt_injection: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="prompt_injection", weight=2.0)
    )
    jailbreak: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="jailbreak", weight=2.0)
    )
    pii_detector: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="pii_detector", weight=1.5)
    )
    sensitive_content: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="sensitive_content", weight=1.0)
    )
    system_prompt_leak: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="system_prompt_leak", weight=2.0)
    )
    adversarial_attack: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="adversarial_attack", weight=1.5)
    )
    toxicity: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="toxicity", weight=1.0)
    )
    
    # Output classifiers
    content_safety: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="content_safety", weight=1.5)
    )
    pii_leakage: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="pii_leakage", weight=1.5)
    )
    injection_check: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="injection_check", weight=1.0)
    )
    hallucination: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="hallucination", weight=1.0, enabled=False)
    )
    bias_detector: ClassifierConfig = Field(
        default_factory=lambda: ClassifierConfig(name="bias_detector", weight=0.8, enabled=False)
    )
    
    # Parallel execution settings
    parallel_execution: bool = True
    max_concurrent: int = Field(default=10, ge=1)
    fail_fast: bool = False  # Stop on first high-severity threat


class ProviderConfig(BaseModel):
    """Configuration for an LLM provider."""
    
    name: str
    enabled: bool = True
    model: str = "gpt-3.5-turbo"
    api_key_env: str = ""  # Environment variable name for API key
    api_base: Optional[str] = None
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0)
    priority: int = Field(default=1, ge=1)  # Lower is higher priority
    options: Dict[str, Any] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    """Configuration for LLM providers."""
    
    default_provider: str = "openai"
    providers: Dict[str, ProviderConfig] = Field(default_factory=lambda: {
        "openai": ProviderConfig(
            name="openai",
            model="gpt-3.5-turbo",
            api_key_env="OPENAI_API_KEY",
            priority=1
        ),
        "anthropic": ProviderConfig(
            name="anthropic",
            model="claude-3-sonnet-20240229",
            api_key_env="ANTHROPIC_API_KEY",
            enabled=False,
            priority=2
        ),
        "gemini": ProviderConfig(
            name="gemini",
            model="gemini-pro",
            api_key_env="GOOGLE_API_KEY",
            enabled=False,
            priority=3
        ),
    })
    
    # Failover settings
    enable_failover: bool = True
    failover_retries: int = Field(default=2, ge=0)
    
    # Cost tracking
    track_costs: bool = True
    max_cost_per_request: Optional[float] = None


class CacheConfig(BaseModel):
    """Configuration for caching."""
    
    enabled: bool = True
    backend: CacheBackend = CacheBackend.MEMORY
    
    # Redis settings
    redis_url: str = "redis://localhost:6379/0"
    redis_password_env: str = "REDIS_PASSWORD"
    
    # Memory cache settings
    memory_max_size: int = Field(default=10000, ge=100)
    
    # Disk cache settings
    disk_path: str = ".cache/veilarmor"
    disk_max_size_mb: int = Field(default=1000, ge=100)
    
    # TTL settings
    exact_match_ttl_seconds: int = Field(default=3600, ge=60)  # 1 hour
    semantic_cache_ttl_seconds: int = Field(default=1800, ge=60)  # 30 minutes
    
    # Semantic cache settings
    semantic_enabled: bool = True
    semantic_similarity_threshold: float = Field(default=0.95, ge=0.5, le=1.0)
    embedding_model: str = "all-MiniLM-L6-v2"


class ThresholdConfig(BaseModel):
    """Configuration for decision thresholds."""
    
    # Main decision thresholds
    block_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    sanitize_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    
    # Severity thresholds per threat type
    threat_thresholds: Dict[str, float] = Field(default_factory=lambda: {
        "PROMPT_INJECTION": 0.6,
        "JAILBREAK": 0.6,
        "PII_EXPOSURE": 0.5,
        "SENSITIVE_CONTENT": 0.4,
        "SYSTEM_PROMPT_LEAK": 0.5,
        "ADVERSARIAL_ATTACK": 0.6,
        "TOXICITY": 0.5,
        "CONTENT_SAFETY": 0.5,
        "PII_LEAKAGE": 0.5,
        "INJECTION_OUTPUT": 0.5,
        "HALLUCINATION": 0.7,
        "BIAS": 0.6,
    })
    
    @field_validator("sanitize_threshold")
    @classmethod
    def validate_sanitize_below_block(cls, v: float, info) -> float:
        """Ensure sanitize threshold is below block threshold."""
        block = info.data.get("block_threshold", 0.7)
        if v >= block:
            raise ValueError("sanitize_threshold must be less than block_threshold")
        return v


class SanitizationStrategyConfig(BaseModel):
    """Configuration for a sanitization strategy."""
    
    enabled: bool = True
    priority: int = Field(default=1, ge=1)
    options: Dict[str, Any] = Field(default_factory=dict)


class SanitizationConfig(BaseModel):
    """Configuration for sanitization."""
    
    # Score-based strategy selection
    low_score_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    medium_score_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    
    # Strategies
    strategies: Dict[str, SanitizationStrategyConfig] = Field(default_factory=lambda: {
        "pattern_removal": SanitizationStrategyConfig(priority=1),
        "context_injection": SanitizationStrategyConfig(priority=2),
        "redaction": SanitizationStrategyConfig(priority=3),
        "escaping": SanitizationStrategyConfig(priority=4),
        "token_filtering": SanitizationStrategyConfig(priority=5, enabled=False),
        "rewriting": SanitizationStrategyConfig(priority=6, enabled=False),
    })
    
    # PII redaction settings
    pii_placeholder: str = "[REDACTED]"
    preserve_format: bool = True
    
    # Context injection settings
    safety_context: str = "Please provide a helpful and safe response."


class LoggingConfig(BaseModel):
    """Configuration for logging."""
    
    level: LogLevel = LogLevel.INFO
    format: str = "console"  # console, json, text
    enable_colors: bool = True
    
    # File logging
    log_file: Optional[str] = None
    json_log_file: Optional[str] = None
    log_dir: str = "logs"
    max_file_size_mb: int = Field(default=100, ge=1)
    backup_count: int = Field(default=5, ge=1)
    
    # Component-specific levels
    component_levels: Dict[str, LogLevel] = Field(default_factory=dict)
    
    # Sensitive data handling
    mask_sensitive_data: bool = True
    truncate_long_values: bool = True
    max_value_length: int = Field(default=500, ge=50)


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting."""
    
    enabled: bool = True
    
    # Global limits
    global_requests_per_minute: int = Field(default=1000, ge=1)
    global_requests_per_hour: int = Field(default=10000, ge=1)
    
    # Per-user limits
    user_requests_per_minute: int = Field(default=60, ge=1)
    user_requests_per_hour: int = Field(default=500, ge=1)
    
    # Per-IP limits
    ip_requests_per_minute: int = Field(default=100, ge=1)


class AuthConfig(BaseModel):
    """Configuration for authentication."""
    
    enabled: bool = False
    
    # API key auth
    api_key_header: str = "X-API-Key"
    api_keys_env: str = "VEILARMOR_API_KEYS"  # Comma-separated list
    
    # JWT auth
    jwt_enabled: bool = False
    jwt_secret_env: str = "VEILARMOR_JWT_SECRET"
    jwt_algorithm: str = "HS256"
    jwt_expiry_hours: int = Field(default=24, ge=1)


class ConversationConfig(BaseModel):
    """Configuration for conversation management."""
    
    enabled: bool = True
    
    # Storage
    storage_backend: str = "memory"  # memory, redis, disk
    max_conversations: int = Field(default=10000, ge=100)
    
    # Context management
    max_context_turns: int = Field(default=20, ge=1)
    max_context_tokens: int = Field(default=4000, ge=100)
    summarize_on_overflow: bool = True
    
    # Retention
    conversation_ttl_hours: int = Field(default=24, ge=1)
    auto_archive: bool = True


class ServerConfig(BaseModel):
    """Configuration for the API server."""
    
    host: str = "0.0.0.0"
    port: int = Field(default=8000, ge=1, le=65535)
    workers: int = Field(default=4, ge=1)
    
    # CORS
    cors_enabled: bool = True
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])
    cors_methods: List[str] = Field(default_factory=lambda: ["*"])
    cors_headers: List[str] = Field(default_factory=lambda: ["*"])
    
    # Request handling
    max_request_size_mb: int = Field(default=10, ge=1)
    request_timeout_seconds: float = Field(default=60.0, gt=0)


# =============================================================================
# Main Settings Class
# =============================================================================

class Settings(BaseSettings):
    """
    Main application settings.
    
    Settings are loaded in the following order (later sources override earlier):
    1. Default values
    2. YAML configuration file
    3. Environment variables
    """
    
    model_config = SettingsConfigDict(
        env_prefix="VEILARMOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    # Application metadata
    app_name: str = "VeilArmor"
    version: str = "2.0.0"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    
    # Configuration file path
    config_file: str = "config/settings.yaml"
    
    # Sub-configurations
    server: ServerConfig = Field(default_factory=ServerConfig)
    classifiers: ClassifiersConfig = Field(default_factory=ClassifiersConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    sanitization: SanitizationConfig = Field(default_factory=SanitizationConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    conversation: ConversationConfig = Field(default_factory=ConversationConfig)
    
    def __init__(self, **kwargs: Any) -> None:
        """Initialize settings, loading from YAML if available."""
        # Load YAML config first
        yaml_config = self._load_yaml_config(kwargs.get("config_file", "config/settings.yaml"))
        
        # Merge YAML config with kwargs (kwargs take precedence)
        merged = {**yaml_config, **kwargs}
        
        super().__init__(**merged)
    
    @staticmethod
    def _load_yaml_config(config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        config_file = Path(config_path)
        if not config_file.exists():
            return {}
        
        try:
            with open(config_file, "r") as f:
                config = yaml.safe_load(f) or {}
            return config
        except Exception:
            return {}
    
    def get_api_key(self, env_var: str) -> Optional[str]:
        """Get API key from environment variable."""
        return os.environ.get(env_var)
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION
    
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == Environment.DEVELOPMENT
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary (excluding secrets)."""
        data = self.model_dump()
        # Remove sensitive fields
        for provider in data.get("llm", {}).get("providers", {}).values():
            provider.pop("api_key_env", None)
        return data


# =============================================================================
# Global Settings Instance
# =============================================================================

_settings: Optional[Settings] = None


@lru_cache()
def get_settings() -> Settings:
    """
    Get the global settings instance.
    
    Returns:
        Settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings(config_file: Optional[str] = None) -> Settings:
    """
    Reload settings from configuration.
    
    Args:
        config_file: Optional path to configuration file
        
    Returns:
        New Settings instance
    """
    global _settings
    get_settings.cache_clear()
    
    if config_file:
        _settings = Settings(config_file=config_file)
    else:
        _settings = Settings()
    
    return _settings
