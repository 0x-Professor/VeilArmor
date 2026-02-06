# Pydantic request/response models
"""
VeilArmor - API Models

Pydantic models for API requests and responses.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


# ---------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------

class ActionType(str, Enum):
    """Action taken on request."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SANITIZE = "SANITIZE"


class SeverityLevel(str, Enum):
    """Threat severity level."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------

class PromptRequest(BaseModel):
    """Request model for prompt processing."""
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=100000,
        description="User prompt to process",
    )
    user_id: Optional[str] = Field(
        None,
        description="Optional user identifier for tracking",
    )
    conversation_id: Optional[str] = Field(
        None,
        description="Conversation ID for multi-turn context",
    )
    system_prompt: Optional[str] = Field(
        None,
        description="Optional system prompt override",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "prompt": "What is the capital of France?",
                "user_id": "user_123",
                "conversation_id": "conv_456",
            }
        }


class ChatMessage(BaseModel):
    """Chat message model."""
    role: str = Field(..., description="Message role (user, assistant, system)")
    content: str = Field(..., description="Message content")


class ChatRequest(BaseModel):
    """Chat completion request."""
    messages: List[ChatMessage] = Field(
        ...,
        description="List of messages in the conversation",
    )
    user_id: Optional[str] = Field(None, description="User identifier")
    conversation_id: Optional[str] = Field(None, description="Conversation ID")
    model: Optional[str] = Field(None, description="Model to use")
    temperature: float = Field(0.7, ge=0, le=2, description="Sampling temperature")
    max_tokens: Optional[int] = Field(None, description="Maximum tokens in response")
    stream: bool = Field(False, description="Stream response")
    
    class Config:
        json_schema_extra = {
            "example": {
                "messages": [
                    {"role": "user", "content": "Hello, how are you?"}
                ],
                "temperature": 0.7,
            }
        }


class ClassifyRequest(BaseModel):
    """Classification request."""
    text: str = Field(..., description="Text to classify")
    classifiers: Optional[List[str]] = Field(
        None,
        description="Specific classifiers to use",
    )


class SanitizeRequest(BaseModel):
    """Sanitization request."""
    text: str = Field(..., description="Text to sanitize")
    mode: str = Field("normal", description="Sanitization mode")


class ValidateRequest(BaseModel):
    """Validation request."""
    text: str = Field(..., description="Text to validate")
    mode: str = Field("normal", description="Validation mode")


# ---------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------

class PromptResponse(BaseModel):
    """Response model for prompt processing."""
    success: bool = Field(..., description="Whether the request was successful")
    action: ActionType = Field(..., description="Action taken")
    response: Optional[str] = Field(None, description="LLM response (if not blocked)")
    threats_detected: List[str] = Field(
        default_factory=list,
        description="List of detected threats",
    )
    severity: SeverityLevel = Field(
        SeverityLevel.NONE,
        description="Overall threat severity",
    )
    message: Optional[str] = Field(None, description="Additional message")
    request_id: Optional[str] = Field(None, description="Request tracking ID")
    processing_time_ms: Optional[float] = Field(
        None,
        description="Processing time in milliseconds",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "action": "ALLOW",
                "response": "The capital of France is Paris.",
                "threats_detected": [],
                "severity": "NONE",
                "message": "Request processed successfully",
                "request_id": "req_abc123",
                "processing_time_ms": 150.5,
            }
        }


class ClassifyResponse(BaseModel):
    """Classification response."""
    text_preview: str = Field(..., description="Preview of classified text")
    threats: List[str] = Field(default_factory=list, description="Detected threats")
    severity: SeverityLevel = Field(..., description="Overall severity")
    confidence: float = Field(..., description="Classification confidence")
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed classification results",
    )


class SanitizeResponse(BaseModel):
    """Sanitization response."""
    original: str = Field(..., description="Original text")
    sanitized: str = Field(..., description="Sanitized text")
    modifications: List[str] = Field(
        default_factory=list,
        description="List of modifications made",
    )


class ValidateResponse(BaseModel):
    """Validation response."""
    is_valid: bool = Field(..., description="Whether validation passed")
    violations: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Validation violations",
    )
    error_count: int = Field(0, description="Number of errors")
    warning_count: int = Field(0, description="Number of warnings")


class ChatResponse(BaseModel):
    """Chat completion response."""
    id: str = Field(..., description="Response ID")
    content: str = Field(..., description="Response content")
    role: str = Field("assistant", description="Message role")
    finish_reason: Optional[str] = Field(None, description="Finish reason")
    usage: Optional[Dict[str, int]] = Field(None, description="Token usage")
    security: Optional[Dict[str, Any]] = Field(
        None,
        description="Security analysis results",
    )


# ---------------------------------------------------------------------
# System Response Models
# ---------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field("healthy", description="Overall status")
    version: str = Field(..., description="Application version")
    components: Dict[str, str] = Field(
        default_factory=dict,
        description="Component health status",
    )
    uptime_seconds: Optional[float] = Field(None, description="Uptime in seconds")


class MetricsResponse(BaseModel):
    """Metrics response."""
    requests: Dict[str, Any] = Field(..., description="Request metrics")
    classification: Dict[str, Any] = Field(..., description="Classification metrics")
    sanitization: Dict[str, Any] = Field(..., description="Sanitization metrics")
    cache: Dict[str, Any] = Field(..., description="Cache metrics")


class ErrorResponse(BaseModel):
    """Error response model."""
    success: bool = Field(False, description="Always false for errors")
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    request_id: Optional[str] = Field(None, description="Request ID for tracking")


class RateLimitResponse(BaseModel):
    """Rate limit exceeded response."""
    error: str = Field("rate_limit_exceeded", description="Error type")
    message: str = Field(..., description="Error message")
    retry_after: int = Field(..., description="Seconds until retry allowed")