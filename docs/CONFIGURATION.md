# VeilArmor - Configuration Reference

## Overview

VeilArmor uses a hierarchical configuration system that supports:

1. YAML configuration files (`config/settings.yaml`)
2. Environment variables (override file settings)
3. Programmatic configuration (highest priority)

## Configuration File Structure

### config/settings.yaml

```yaml
# =============================================================================
# VeilArmor Configuration
# =============================================================================

app:
  name: "VeilArmor"
  version: "2.0.0"
  environment: "production"  # development, staging, production
  debug: false

# -----------------------------------------------------------------------------
# API Server Configuration
# -----------------------------------------------------------------------------
api:
  host: "0.0.0.0"
  port: 8000
  workers: 4                 # Number of worker processes
  reload: false              # Auto-reload on file changes
  cors:
    enabled: true
    origins: ["*"]
    methods: ["GET", "POST", "PUT", "DELETE"]
    headers: ["*"]

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------
security:
  # Classifier settings
  classifier:
    enabled: true
    confidence_threshold: 0.7    # 0.0 to 1.0
    parallel_execution: true     # Run classifiers in parallel
    enabled_classifiers:
      - prompt_injection
      - jailbreak
      - pii
      - harmful_content
      - sensitive_data
    
    # ML classifier settings
    ml_classifier:
      enabled: true
      model_path: "models/classifier.pkl"
      threshold: 0.8
  
  # Sanitizer settings
  sanitizer:
    enabled: true
    remove_pii: true
    remove_urls: true
    normalize_unicode: true
    max_length: 32000            # Maximum input length
    
    # PII patterns to detect
    pii_patterns:
      ssn: true
      credit_card: true
      email: true
      phone: true
      address: false
    
    # URL handling
    url_handling: "remove"       # remove, mask, allow
  
  # Pipeline settings
  pipeline:
    stages:
      - input_processing
      - input_classification
      - decision
      - input_sanitization
      - cache_check
      - llm_call
      - output_classification
      - output_validation
      - output_sanitization
    
    block_threshold: "HIGH"      # NONE, LOW, MEDIUM, HIGH, CRITICAL
    sanitize_threshold: "MEDIUM"
    fail_open: false             # If true, allow on errors
    collect_metrics: true

# -----------------------------------------------------------------------------
# LLM Provider Configuration
# -----------------------------------------------------------------------------
llm:
  default_provider: "openai"
  timeout: 30                    # Request timeout in seconds
  max_retries: 3
  retry_delay: 1.0               # Initial retry delay
  
  # Provider configurations
  providers:
    openai:
      enabled: true
      api_key: "${OPENAI_API_KEY}"
      model: "gpt-4"
      base_url: null             # Custom endpoint
      priority: 1
      
    anthropic:
      enabled: true
      api_key: "${ANTHROPIC_API_KEY}"
      model: "claude-3-sonnet-20240229"
      priority: 2
      
    google:
      enabled: false
      api_key: "${GOOGLE_API_KEY}"
      model: "gemini-pro"
      priority: 3
      
    azure:
      enabled: false
      api_key: "${AZURE_OPENAI_KEY}"
      model: "gpt-4"
      base_url: "${AZURE_OPENAI_ENDPOINT}"
      api_version: "2024-02-15-preview"
      priority: 4
      
    ollama:
      enabled: false
      base_url: "http://localhost:11434"
      model: "llama2"
      priority: 5
  
  # Circuit breaker settings
  circuit_breaker:
    enabled: true
    failure_threshold: 5         # Failures before opening
    recovery_timeout: 60         # Seconds before retry
    half_open_requests: 3        # Test requests in half-open
  
  # Load balancing
  load_balancing:
    strategy: "round_robin"      # round_robin, random, least_latency, priority
    health_check_interval: 30    # Seconds between health checks

# -----------------------------------------------------------------------------
# Cache Configuration
# -----------------------------------------------------------------------------
cache:
  enabled: true
  backend: "memory"              # memory, redis, file
  ttl: 3600                      # Cache TTL in seconds
  max_entries: 10000
  
  # Semantic cache settings
  semantic:
    enabled: true
    similarity_threshold: 0.95   # 0.0 to 1.0
    embedding_model: "all-MiniLM-L6-v2"
    embedding_dimension: 384
  
  # Redis settings (if backend: redis)
  redis:
    url: "${REDIS_URL:redis://localhost:6379}"
    db: 0
    password: "${REDIS_PASSWORD:}"
    ssl: false
    
  # File cache settings (if backend: file)
  file:
    path: "/tmp/veilarmor_cache"

# -----------------------------------------------------------------------------
# Validation Configuration
# -----------------------------------------------------------------------------
validation:
  enabled: true
  mode: "normal"                 # minimal, normal, strict
  
  rules:
    length:
      min: 1
      max: 32000
    
    content:
      forbidden_patterns:
        - "password"
        - "secret"
        - "private_key"
    
    format:
      check_json: true
      check_structure: true
    
    quality:
      min_word_count: 3
      check_coherence: true
      coherence_threshold: 0.5

# -----------------------------------------------------------------------------
# Rate Limiting Configuration
# -----------------------------------------------------------------------------
rate_limiting:
  enabled: true
  strategy: "sliding_window"     # fixed_window, sliding_window, token_bucket
  
  # Limits per strategy
  limits:
    requests_per_minute: 60
    requests_per_hour: 1000
    tokens_per_minute: 100000
    burst_size: 10
  
  # Key extraction
  key_by: "ip"                   # ip, api_key, user_id
  
  # Rate limit bypass
  bypass_keys: []                # API keys that bypass limits

# -----------------------------------------------------------------------------
# Authentication Configuration
# -----------------------------------------------------------------------------
auth:
  enabled: false
  method: "api_key"              # api_key, bearer, hmac
  
  # API key settings
  api_key:
    header: "X-API-Key"
    keys: ["${API_KEY}"]
  
  # Bearer token settings
  bearer:
    secret: "${JWT_SECRET}"
    algorithm: "HS256"
    expiry: 3600
  
  # HMAC settings
  hmac:
    secret: "${HMAC_SECRET}"
    algorithm: "sha256"
    timestamp_tolerance: 300

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
logging:
  level: "INFO"                  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "json"                 # json, text
  
  # Output destinations
  outputs:
    console: true
    file:
      enabled: true
      path: "logs/veilarmor.log"
      max_size: "100MB"
      backup_count: 5
  
  # Log filtering
  include_request_body: false    # Privacy: don't log request bodies
  include_response_body: false
  redact_sensitive: true         # Redact PII from logs

# -----------------------------------------------------------------------------
# Metrics Configuration
# -----------------------------------------------------------------------------
metrics:
  enabled: true
  
  # Prometheus metrics
  prometheus:
    enabled: true
    path: "/metrics"
  
  # Custom metrics
  custom:
    request_duration: true
    classification_duration: true
    cache_hit_rate: true
    threat_counts: true
    provider_latency: true

# -----------------------------------------------------------------------------
# Conversation Management
# -----------------------------------------------------------------------------
conversation:
  enabled: true
  storage: "memory"              # memory, redis, file
  max_history: 50                # Max messages per conversation
  ttl: 86400                     # Conversation TTL (24 hours)
  
  # Redis storage settings
  redis:
    url: "${REDIS_URL:redis://localhost:6379}"
    prefix: "conv:"
```

## Environment Variables

All configuration values can be overridden with environment variables using the format:

```
VEILARMOR_<SECTION>_<KEY>=value
```

### Common Environment Variables

```bash
# Application
VEILARMOR_ENV=production
VEILARMOR_DEBUG=false
VEILARMOR_LOG_LEVEL=INFO

# API
VEILARMOR_API_HOST=0.0.0.0
VEILARMOR_API_PORT=8000

# LLM Providers
OPENAI_API_KEY=sk-xxx
ANTHROPIC_API_KEY=sk-ant-xxx
GOOGLE_API_KEY=xxx
AZURE_OPENAI_KEY=xxx
AZURE_OPENAI_ENDPOINT=https://xxx.openai.azure.com

# Cache
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=secret

# Security
API_KEY=your-api-key
JWT_SECRET=your-jwt-secret
HMAC_SECRET=your-hmac-secret

# Thresholds
VEILARMOR_SECURITY_CLASSIFIER_CONFIDENCE_THRESHOLD=0.7
VEILARMOR_SECURITY_PIPELINE_BLOCK_THRESHOLD=HIGH
```

## Programmatic Configuration

```python
from src.core.config import Settings

# Load default settings
settings = Settings()

# Override specific values
settings.security.classifier.confidence_threshold = 0.8
settings.llm.timeout = 60

# Create pipeline with settings
from src.core.pipeline import create_pipeline
pipeline = create_pipeline(settings)
```

## Configuration Profiles

### Development

```yaml
app:
  environment: development
  debug: true

security:
  pipeline:
    fail_open: true

logging:
  level: DEBUG
  include_request_body: true
```

### Production

```yaml
app:
  environment: production
  debug: false

security:
  pipeline:
    fail_open: false

cache:
  enabled: true
  backend: redis

logging:
  level: INFO
  format: json
  redact_sensitive: true
```

### High Security

```yaml
security:
  classifier:
    confidence_threshold: 0.5
    parallel_execution: true
    enabled_classifiers:
      - prompt_injection
      - jailbreak
      - pii
      - harmful_content
      - sensitive_data
      - adversarial

  pipeline:
    block_threshold: MEDIUM
    sanitize_threshold: LOW
    fail_open: false

validation:
  mode: strict
```

## Validation

Configuration is validated on load. Invalid configurations will raise `ConfigurationError` with details about the issue.

```python
from src.core.config import Settings, ConfigurationError

try:
    settings = Settings()
except ConfigurationError as e:
    print(f"Configuration error: {e}")
```
