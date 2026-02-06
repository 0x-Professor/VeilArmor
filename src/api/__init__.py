"""
VeilArmor - API Module

FastAPI server with middleware, routes, and models.
"""

from .server import app, create_app
from .routes import router
from .models import (
    PromptRequest,
    PromptResponse,
    ChatRequest,
    ChatResponse,
    ClassifyRequest,
    ClassifyResponse,
    SanitizeRequest,
    SanitizeResponse,
    ValidateRequest,
    ValidateResponse,
    HealthResponse,
    MetricsResponse,
    ErrorResponse,
    ActionType,
    SeverityLevel,
)
from .middleware import (
    setup_middleware,
    RateLimiter,
    RateLimitConfig,
    RateLimitMiddleware,
    Authenticator,
    AuthConfig,
    AuthMethod,
    AuthMiddleware,
    RequestTracker,
    RequestTrackingMiddleware,
    SecurityHeadersMiddleware,
)

__all__ = [
    # Server
    "app",
    "create_app",
    "router",
    # Request Models
    "PromptRequest",
    "ChatRequest",
    "ClassifyRequest",
    "SanitizeRequest",
    "ValidateRequest",
    # Response Models
    "PromptResponse",
    "ChatResponse",
    "ClassifyResponse",
    "SanitizeResponse",
    "ValidateResponse",
    "HealthResponse",
    "MetricsResponse",
    "ErrorResponse",
    # Enums
    "ActionType",
    "SeverityLevel",
    # Middleware
    "setup_middleware",
    "RateLimiter",
    "RateLimitConfig",
    "RateLimitMiddleware",
    "Authenticator",
    "AuthConfig",
    "AuthMethod",
    "AuthMiddleware",
    "RequestTracker",
    "RequestTrackingMiddleware",
    "SecurityHeadersMiddleware",
]