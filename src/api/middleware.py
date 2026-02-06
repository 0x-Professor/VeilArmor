"""
VeilArmor v2.0 - API Middleware

Middleware for rate limiting, authentication, and request tracking.
"""

import asyncio
import hashlib
import hmac
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------

class RateLimitStrategy(str, Enum):
    """Rate limiting strategy."""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_size: int = 10
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW


@dataclass
class RateLimitState:
    """Rate limit state for a client."""
    minute_count: int = 0
    minute_reset: float = 0.0
    hour_count: int = 0
    hour_reset: float = 0.0
    day_count: int = 0
    day_reset: float = 0.0
    tokens: float = 0.0
    last_refill: float = 0.0


class RateLimiter:
    """
    Rate limiter with multiple strategies.
    
    Features:
    - Fixed window limiting
    - Sliding window limiting
    - Token bucket algorithm
    - Per-client tracking
    """
    
    def __init__(
        self,
        config: RateLimitConfig = None,
        key_func: Callable[[Request], str] = None,
    ):
        """
        Initialize rate limiter.
        
        Args:
            config: Rate limit configuration
            key_func: Function to extract client key from request
        """
        self.config = config or RateLimitConfig()
        self.key_func = key_func or self._default_key_func
        
        self._states: Dict[str, RateLimitState] = defaultdict(RateLimitState)
        self._lock = asyncio.Lock()
        
        logger.info(
            "Rate limiter initialized",
            strategy=self.config.strategy.value,
            rpm=self.config.requests_per_minute,
        )
    
    def _default_key_func(self, request: Request) -> str:
        """Default key function using client IP."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    
    async def is_allowed(self, request: Request) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed.
        
        Args:
            request: FastAPI request
            
        Returns:
            Tuple of (allowed, headers)
        """
        key = self.key_func(request)
        now = time.time()
        
        async with self._lock:
            state = self._states[key]
            
            if self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
                return await self._check_token_bucket(state, now)
            elif self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
                return await self._check_sliding_window(state, now)
            else:
                return await self._check_fixed_window(state, now)
    
    async def _check_fixed_window(
        self,
        state: RateLimitState,
        now: float,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Fixed window rate limiting."""
        # Reset windows if expired
        if now >= state.minute_reset:
            state.minute_count = 0
            state.minute_reset = now + 60
        
        if now >= state.hour_reset:
            state.hour_count = 0
            state.hour_reset = now + 3600
        
        if now >= state.day_reset:
            state.day_count = 0
            state.day_reset = now + 86400
        
        # Check limits
        if state.minute_count >= self.config.requests_per_minute:
            return False, self._make_headers(state, "minute")
        
        if state.hour_count >= self.config.requests_per_hour:
            return False, self._make_headers(state, "hour")
        
        if state.day_count >= self.config.requests_per_day:
            return False, self._make_headers(state, "day")
        
        # Increment counters
        state.minute_count += 1
        state.hour_count += 1
        state.day_count += 1
        
        return True, self._make_headers(state, "minute")
    
    async def _check_sliding_window(
        self,
        state: RateLimitState,
        now: float,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Sliding window rate limiting."""
        # Decay old counts based on elapsed time
        if state.last_refill > 0:
            elapsed = now - state.last_refill
            decay_factor = max(0, 1 - (elapsed / 60))
            state.minute_count = int(state.minute_count * decay_factor)
        
        state.last_refill = now
        state.minute_reset = now + 60
        
        # Also decay and check hour/day windows
        if state.hour_reset == 0.0 or now >= state.hour_reset:
            state.hour_count = 0
            state.hour_reset = now + 3600
        if state.day_reset == 0.0 or now >= state.day_reset:
            state.day_count = 0
            state.day_reset = now + 86400
        
        # Check all limits
        if state.minute_count >= self.config.requests_per_minute:
            return False, self._make_headers(state, "minute")
        
        if state.hour_count >= self.config.requests_per_hour:
            return False, self._make_headers(state, "hour")
        
        if state.day_count >= self.config.requests_per_day:
            return False, self._make_headers(state, "day")
        
        state.minute_count += 1
        state.hour_count += 1
        state.day_count += 1
        
        return True, self._make_headers(state, "minute")
    
    async def _check_token_bucket(
        self,
        state: RateLimitState,
        now: float,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Token bucket rate limiting."""
        # Calculate refill
        if state.last_refill > 0:
            elapsed = now - state.last_refill
            refill_rate = self.config.requests_per_minute / 60
            state.tokens = min(
                self.config.burst_size,
                state.tokens + (elapsed * refill_rate),
            )
        else:
            state.tokens = self.config.burst_size
        
        state.last_refill = now
        
        # Check if tokens available
        if state.tokens < 1:
            return False, {"X-RateLimit-Remaining": "0"}
        
        state.tokens -= 1
        
        return True, {"X-RateLimit-Remaining": str(int(state.tokens))}
    
    def _make_headers(
        self,
        state: RateLimitState,
        window: str,
    ) -> Dict[str, str]:
        """Create rate limit headers."""
        if window == "minute":
            remaining = max(0, self.config.requests_per_minute - state.minute_count)
            reset = int(state.minute_reset)
        elif window == "hour":
            remaining = max(0, self.config.requests_per_hour - state.hour_count)
            reset = int(state.hour_reset)
        else:
            remaining = max(0, self.config.requests_per_day - state.day_count)
            reset = int(state.day_reset)
        
        return {
            "X-RateLimit-Limit": str(self.config.requests_per_minute),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset),
        }


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""
    
    def __init__(
        self,
        app: FastAPI,
        limiter: RateLimiter = None,
        exclude_paths: List[str] = None,
    ):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI application
            limiter: Rate limiter instance
            exclude_paths: Paths to exclude from limiting
        """
        super().__init__(app)
        self.limiter = limiter or RateLimiter()
        self.exclude_paths = exclude_paths or ["/health", "/docs", "/redoc", "/openapi.json"]
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request through rate limiter."""
        # Skip excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        allowed, headers = await self.limiter.is_allowed(request)
        
        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                client=self.limiter.key_func(request),
                path=request.url.path,
            )
            
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                },
                headers=headers,
            )
        
        response = await call_next(request)
        
        # Add rate limit headers to response
        for key, value in headers.items():
            response.headers[key] = value
        
        return response


# ---------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------

class AuthMethod(str, Enum):
    """Authentication method."""
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    HMAC = "hmac"
    NONE = "none"


@dataclass
class AuthConfig:
    """Authentication configuration."""
    method: AuthMethod = AuthMethod.API_KEY
    api_keys: Dict[str, str] = field(default_factory=dict)  # key -> user_id
    secret_key: str = ""  # For HMAC
    token_header: str = "Authorization"
    api_key_header: str = "X-API-Key"


class Authenticator:
    """
    Request authenticator.
    
    Supports multiple authentication methods.
    """
    
    def __init__(self, config: AuthConfig = None):
        """
        Initialize authenticator.
        
        Args:
            config: Authentication configuration
        """
        self.config = config or AuthConfig()
        
        logger.info(
            "Authenticator initialized",
            method=self.config.method.value,
        )
    
    async def authenticate(self, request: Request) -> Tuple[bool, Optional[str], str]:
        """
        Authenticate request.
        
        Args:
            request: FastAPI request
            
        Returns:
            Tuple of (authenticated, user_id, error_message)
        """
        if self.config.method == AuthMethod.NONE:
            return True, None, ""
        
        if self.config.method == AuthMethod.API_KEY:
            return await self._auth_api_key(request)
        
        if self.config.method == AuthMethod.BEARER_TOKEN:
            return await self._auth_bearer(request)
        
        if self.config.method == AuthMethod.HMAC:
            return await self._auth_hmac(request)
        
        return False, None, "Unknown authentication method"
    
    async def _auth_api_key(self, request: Request) -> Tuple[bool, Optional[str], str]:
        """API key authentication."""
        api_key = request.headers.get(self.config.api_key_header)
        
        if not api_key:
            return False, None, "API key required"
        
        user_id = self.config.api_keys.get(api_key)
        
        if not user_id:
            return False, None, "Invalid API key"
        
        return True, user_id, ""
    
    async def _auth_bearer(self, request: Request) -> Tuple[bool, Optional[str], str]:
        """Bearer token authentication."""
        auth_header = request.headers.get(self.config.token_header)
        
        if not auth_header:
            return False, None, "Authorization header required"
        
        if not auth_header.startswith("Bearer "):
            return False, None, "Invalid authorization format"
        
        token = auth_header[7:]
        
        # Validate token (implement your token validation logic)
        user_id = self.config.api_keys.get(token)
        
        if not user_id:
            return False, None, "Invalid token"
        
        return True, user_id, ""
    
    async def _auth_hmac(self, request: Request) -> Tuple[bool, Optional[str], str]:
        """HMAC signature authentication."""
        signature = request.headers.get("X-Signature")
        timestamp = request.headers.get("X-Timestamp")
        
        if not signature or not timestamp:
            return False, None, "Signature and timestamp required"
        
        # Verify timestamp (prevent replay attacks)
        try:
            ts = int(timestamp)
            if abs(time.time() - ts) > 300:  # 5 minute window
                return False, None, "Timestamp expired"
        except ValueError:
            return False, None, "Invalid timestamp"
        
        # Verify signature
        # Note: request.body() returns cached body if already read by FastAPI
        body = await request.body()
        message = f"{timestamp}{request.method}{request.url.path}{body.decode()}"
        
        expected = hmac.HMAC(
            self.config.secret_key.encode(),
            message.encode(),
            hashlib.sha256,
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected):
            return False, None, "Invalid signature"
        
        return True, None, ""


class AuthMiddleware(BaseHTTPMiddleware):
    """Authentication middleware."""
    
    def __init__(
        self,
        app: FastAPI,
        authenticator: Authenticator = None,
        exclude_paths: List[str] = None,
    ):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI application
            authenticator: Authenticator instance
            exclude_paths: Paths to exclude from auth
        """
        super().__init__(app)
        self.authenticator = authenticator or Authenticator()
        self.exclude_paths = exclude_paths or ["/health", "/docs", "/redoc", "/openapi.json"]
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request through authenticator."""
        # Skip excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        authenticated, user_id, error = await self.authenticator.authenticate(request)
        
        if not authenticated:
            logger.warning(
                "Authentication failed",
                path=request.url.path,
                error=error,
            )
            
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Authentication failed",
                    "message": error,
                },
            )
        
        # Add user_id to request state
        request.state.user_id = user_id
        
        return await call_next(request)


# ---------------------------------------------------------------------
# Request Tracking
# ---------------------------------------------------------------------

class RequestTracker:
    """Tracks request metrics and correlation."""
    
    def __init__(self):
        """Initialize request tracker."""
        self._requests: Dict[str, Dict[str, Any]] = {}
        self._metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_duration_ms": 0.0,
        }
    
    def start_request(self, request_id: str, request: Request) -> None:
        """Start tracking a request."""
        self._requests[request_id] = {
            "start_time": time.time(),
            "method": request.method,
            "path": request.url.path,
            "client": request.client.host if request.client else "unknown",
        }
        self._metrics["total_requests"] += 1
    
    def end_request(
        self,
        request_id: str,
        status_code: int,
    ) -> float:
        """End tracking a request."""
        if request_id not in self._requests:
            return 0.0
        
        data = self._requests.pop(request_id)
        duration_ms = (time.time() - data["start_time"]) * 1000
        
        self._metrics["total_duration_ms"] += duration_ms
        
        if 200 <= status_code < 400:
            self._metrics["successful_requests"] += 1
        else:
            self._metrics["failed_requests"] += 1
        
        return duration_ms
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get request metrics."""
        total = self._metrics["total_requests"]
        return {
            **self._metrics,
            "avg_duration_ms": (
                self._metrics["total_duration_ms"] / total
                if total > 0 else 0
            ),
            "success_rate": (
                self._metrics["successful_requests"] / total
                if total > 0 else 0
            ),
        }


class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Request tracking middleware."""
    
    def __init__(
        self,
        app: FastAPI,
        tracker: RequestTracker = None,
        header_name: str = "X-Request-ID",
    ):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI application
            tracker: Request tracker instance
            header_name: Request ID header name
        """
        super().__init__(app)
        self.tracker = tracker or RequestTracker()
        self.header_name = header_name
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Track request."""
        # Get or generate request ID
        request_id = request.headers.get(self.header_name) or str(uuid.uuid4())
        
        # Store in request state
        request.state.request_id = request_id
        
        # Start tracking
        self.tracker.start_request(request_id, request)
        
        try:
            response = await call_next(request)
            
            # End tracking
            duration_ms = self.tracker.end_request(request_id, response.status_code)
            
            # Add headers
            response.headers[self.header_name] = request_id
            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
            
            logger.info(
                "Request completed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=duration_ms,
            )
            
            return response
            
        except Exception as e:
            self.tracker.end_request(request_id, 500)
            logger.error(
                "Request failed",
                request_id=request_id,
                error=str(e),
            )
            raise


# ---------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to responses."""
    
    def __init__(
        self,
        app: FastAPI,
        headers: Dict[str, str] = None,
    ):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI application
            headers: Custom security headers
        """
        super().__init__(app)
        
        self.headers = headers or {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
    
    # Paths that serve browser UI and need relaxed CSP to load
    # external JS/CSS (Swagger UI, ReDoc from cdn.jsdelivr.net).
    _DOCS_PATHS = {"/docs", "/redoc", "/openapi.json"}

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Add security headers."""
        response = await call_next(request)
        
        for key, value in self.headers.items():
            # Relax CSP for API docs pages so Swagger UI / ReDoc
            # can load JS & CSS from the CDN.
            if key == "Content-Security-Policy" and request.url.path in self._DOCS_PATHS:
                response.headers[key] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                    "img-src 'self' data: https://fastapi.tiangolo.com; "
                    "worker-src 'self' blob:"
                )
            else:
                response.headers[key] = value
        
        return response


# ---------------------------------------------------------------------
# Setup Functions
# ---------------------------------------------------------------------

def setup_middleware(
    app: FastAPI,
    rate_limit: bool = True,
    rate_limit_config: RateLimitConfig = None,
    auth: bool = False,
    auth_config: AuthConfig = None,
    tracking: bool = True,
    security_headers: bool = True,
) -> None:
    """
    Setup all middleware for the application.
    
    Args:
        app: FastAPI application
        rate_limit: Enable rate limiting
        rate_limit_config: Rate limit configuration
        auth: Enable authentication
        auth_config: Authentication configuration
        tracking: Enable request tracking
        security_headers: Enable security headers
    """
    if security_headers:
        app.add_middleware(SecurityHeadersMiddleware)
    
    if tracking:
        tracker = RequestTracker()
        app.add_middleware(RequestTrackingMiddleware, tracker=tracker)
        app.state.request_tracker = tracker
    
    if rate_limit:
        limiter = RateLimiter(config=rate_limit_config)
        app.add_middleware(RateLimitMiddleware, limiter=limiter)
    
    if auth:
        authenticator = Authenticator(config=auth_config)
        app.add_middleware(AuthMiddleware, authenticator=authenticator)
    
    logger.info(
        "Middleware configured",
        rate_limit=rate_limit,
        auth=auth,
        tracking=tracking,
        security_headers=security_headers,
    )
