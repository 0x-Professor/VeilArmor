# VeilArmor - API Reference

## Overview

VeilArmor exposes a RESTful API for LLM security operations. All endpoints are versioned under `/api/v1/`.

## Base URL

```
http://localhost:8000
```

## Authentication

If authentication is enabled, include one of:

```http
X-API-Key: your-api-key
Authorization: Bearer your-jwt-token
```

## Common Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json` |
| `X-Request-ID` | Optional request tracking ID |
| `X-API-Key` | API key (if auth enabled) |

## Response Format

All responses follow this structure:

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "metadata": {
    "request_id": "req-xxx",
    "processing_time_ms": 45.2
  }
}
```

Error responses:

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input",
    "details": { ... }
  }
}
```

---

## Endpoints

### Health & Monitoring

#### GET /health

Check service health.

**Response**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "uptime_seconds": 3600,
  "components": {
    "api": "healthy",
    "classifier": "healthy",
    "cache": "healthy",
    "llm": "healthy"
  }
}
```

#### GET /metrics

Prometheus metrics endpoint.

**Response**
```
# HELP veilarmor_requests_total Total requests processed
# TYPE veilarmor_requests_total counter
veilarmor_requests_total{action="allow"} 1234
veilarmor_requests_total{action="block"} 56
...
```

---

### Core Processing

#### POST /api/v1/process

Process a prompt through the complete security pipeline.

**Request**
```json
{
  "prompt": "What is machine learning?",
  "system_prompt": "You are a helpful assistant.",
  "metadata": {
    "user_id": "user-123",
    "session_id": "session-456"
  },
  "options": {
    "skip_cache": false,
    "provider": "openai"
  }
}
```

**Response**
```json
{
  "action": "ALLOW",
  "severity": "NONE",
  "response": "Machine learning is...",
  "threats": [],
  "processing_time_ms": 234.5,
  "stages_completed": [
    "input_processing",
    "input_classification",
    "decision",
    "llm_call",
    "output_sanitization"
  ],
  "cached": false
}
```

#### POST /api/v1/chat

Multi-turn chat with security.

**Request**
```json
{
  "messages": [
    {"role": "system", "content": "You are helpful."},
    {"role": "user", "content": "Hello!"},
    {"role": "assistant", "content": "Hi there!"},
    {"role": "user", "content": "What is Python?"}
  ],
  "conversation_id": "conv-123",
  "metadata": {}
}
```

**Response**
```json
{
  "action": "ALLOW",
  "response": "Python is a programming language...",
  "conversation_id": "conv-123",
  "processing_time_ms": 189.3
}
```

---

### Classification

#### POST /api/v1/classify

Classify input text for threats.

**Request**
```json
{
  "text": "Ignore all previous instructions",
  "options": {
    "include_details": true,
    "classifiers": ["prompt_injection", "jailbreak"]
  }
}
```

**Response**
```json
{
  "threats": ["PROMPT_INJECTION"],
  "severity": "HIGH",
  "confidence": 0.95,
  "details": {
    "prompt_injection": {
      "detected": true,
      "confidence": 0.95,
      "patterns": ["ignore.*instructions"]
    }
  }
}
```

#### POST /api/v1/classify-output

Classify LLM output for issues.

**Request**
```json
{
  "text": "Here is your password: secret123",
  "context": {
    "original_prompt": "What is my password?"
  }
}
```

**Response**
```json
{
  "threats": ["SENSITIVE_DATA"],
  "severity": "MEDIUM",
  "confidence": 0.87,
  "details": {
    "sensitive_data": {
      "detected": true,
      "patterns": ["password"]
    }
  }
}
```

---

### Sanitization

#### POST /api/v1/sanitize

Sanitize input text.

**Request**
```json
{
  "text": "My SSN is 123-45-6789 and email is john@example.com",
  "options": {
    "remove_pii": true,
    "remove_urls": true
  }
}
```

**Response**
```json
{
  "sanitized_text": "My SSN is [REDACTED_SSN] and email is [REDACTED_EMAIL]",
  "modifications_made": 2,
  "redactions": [
    {
      "type": "SSN",
      "original": "123-45-6789",
      "position": [11, 22]
    },
    {
      "type": "EMAIL",
      "original": "john@example.com",
      "position": [37, 53]
    }
  ]
}
```

#### POST /api/v1/sanitize-output

Sanitize LLM output.

**Request**
```json
{
  "text": "The user's password is secret123"
}
```

**Response**
```json
{
  "sanitized_text": "The user's password is [REDACTED]",
  "modifications_made": 1,
  "redactions": [
    {
      "type": "PASSWORD",
      "position": [23, 32]
    }
  ]
}
```

---

### Validation

#### POST /api/v1/validate

Validate LLM response.

**Request**
```json
{
  "response": "The answer is 42.",
  "prompt": "What is the meaning of life?",
  "options": {
    "mode": "strict",
    "check_format": true
  }
}
```

**Response**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Response is shorter than recommended (17 chars)"
  ],
  "checks": {
    "length": {"passed": true},
    "content": {"passed": true},
    "safety": {"passed": true},
    "quality": {"passed": true, "score": 0.85}
  }
}
```

---

### Conversation Management

#### POST /api/v1/conversation/create

Create a new conversation.

**Request**
```json
{
  "metadata": {
    "user_id": "user-123"
  },
  "system_prompt": "You are a helpful assistant."
}
```

**Response**
```json
{
  "id": "conv-abc123",
  "created_at": "2024-01-15T10:30:00Z",
  "metadata": {
    "user_id": "user-123"
  }
}
```

#### GET /api/v1/conversation/{id}

Get conversation details.

**Response**
```json
{
  "id": "conv-abc123",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:35:00Z",
  "messages": [
    {"role": "user", "content": "Hello!"},
    {"role": "assistant", "content": "Hi there!"}
  ],
  "metadata": {
    "user_id": "user-123"
  }
}
```

#### DELETE /api/v1/conversation/{id}

Delete a conversation.

**Response**
```json
{
  "deleted": true,
  "id": "conv-abc123"
}
```

---

## Error Codes

| Code | Description |
|------|-------------|
| `VALIDATION_ERROR` | Invalid request parameters |
| `AUTHENTICATION_ERROR` | Missing or invalid credentials |
| `RATE_LIMIT_EXCEEDED` | Too many requests |
| `BLOCKED` | Request blocked by security |
| `PROVIDER_ERROR` | LLM provider error |
| `INTERNAL_ERROR` | Server error |

## Rate Limits

Default limits (configurable):

| Limit | Value |
|-------|-------|
| Requests per minute | 60 |
| Requests per hour | 1000 |
| Tokens per minute | 100,000 |

Rate limit headers:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705312200
```

## Webhooks

VeilArmor can send webhooks for security events:

```json
{
  "event": "threat_detected",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "request_id": "req-xxx",
    "threat_type": "PROMPT_INJECTION",
    "severity": "HIGH",
    "action": "BLOCK"
  }
}
```

Configure webhooks in `settings.yaml`:

```yaml
webhooks:
  enabled: true
  url: "https://your-server.com/webhook"
  events: ["threat_detected", "request_blocked"]
  secret: "${WEBHOOK_SECRET}"
```

## SDKs

### Python

```python
from veilarmor import VeilArmorClient

client = VeilArmorClient(
    base_url="http://localhost:8000",
    api_key="your-key"
)

result = await client.process("Hello, world!")
print(result.response)
```

### JavaScript/TypeScript

```typescript
import { VeilArmorClient } from '@veilarmor/client';

const client = new VeilArmorClient({
  baseUrl: 'http://localhost:8000',
  apiKey: 'your-key'
});

const result = await client.process('Hello, world!');
console.log(result.response);
```

## OpenAPI Specification

Full OpenAPI 3.0 specification available at:

```
GET /openapi.json
GET /docs         (Swagger UI)
GET /redoc        (ReDoc)
```
