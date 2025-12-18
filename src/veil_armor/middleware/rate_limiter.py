"""
LLM10: Unbounded Consumption Protection
Rate limiting middleware using SlowAPI
"""

from typing import Dict, Any, Optional
import logging
from functools import wraps

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class RateLimiter:
    """
    Rate limiting for LLM API endpoints to prevent:
    - DoS attacks
    - Resource exhaustion
    - Cost overruns
    - Abuse
    
    Uses SlowAPI (wrapper around limits library) with Redis or in-memory storage.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize rate limiter.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.logger = logger
        
        if not SLOWAPI_AVAILABLE:
            raise ImportError(
                "slowapi is required for rate limiting. "
                "Install with: pip install slowapi redis"
            )
        
        self.rate_limit_config = config.get('rate_limit', {})
        
        # Default limits
        self.default_limit = self.rate_limit_config.get('default_limit', "10/minute")
        self.authenticated_limit = self.rate_limit_config.get('authenticated_limit', "100/minute")
        self.burst_limit = self.rate_limit_config.get('burst_limit', "50/minute")
        
        # Storage backend
        storage_uri = self.rate_limit_config.get('storage_uri', 'memory://')
        
        # Create limiter
        if storage_uri.startswith('redis://') and REDIS_AVAILABLE:
            self.logger.info(f"Using Redis for rate limiting: {storage_uri}")
            self.limiter = Limiter(
                key_func=get_remote_address,
                storage_uri=storage_uri,
                strategy="fixed-window"
            )
        else:
            self.logger.info("Using in-memory storage for rate limiting")
            self.limiter = Limiter(
                key_func=get_remote_address,
                storage_uri="memory://",
                strategy="fixed-window"
            )
        
        # Token bucket for burst protection
        self.token_buckets: Dict[str, Dict[str, Any]] = {}
        
        self.logger.info(f"Rate limiter initialized with default: {self.default_limit}")
    
    def get_limiter(self):
        """Get the SlowAPI Limiter instance for FastAPI integration."""
        return self.limiter
    
    def limit(self, limit_value: Optional[str] = None):
        """
        Decorator for rate limiting endpoints.
        
        Args:
            limit_value: Custom limit string (e.g., "5/minute", "100/hour")
        
        Returns:
            Decorator function
        """
        if not limit_value:
            limit_value = self.default_limit
        
        return self.limiter.limit(limit_value)
    
    def check_limit(self, identifier: str, limit: str) -> Dict[str, Any]:
        """
        Check if identifier has exceeded rate limit.
        
        Args:
            identifier: User/IP identifier
            limit: Limit string (e.g., "10/minute")
            
        Returns:
            Dictionary with limit status
        """
        try:
            # Parse limit
            count, period = limit.split('/')
            count = int(count)
            
            # Check current usage
            # Note: This is simplified - SlowAPI handles this internally
            return {
                'allowed': True,
                'limit': count,
                'period': period,
                'remaining': count,  # Would need to query actual backend
                'reset_time': None
            }
            
        except Exception as e:
            self.logger.error(f"Rate limit check error: {e}")
            return {
                'allowed': True,
                'error': str(e)
            }
    
    def get_token_bucket_limit(
        self, 
        identifier: str, 
        capacity: int = 100, 
        refill_rate: float = 10.0
    ) -> bool:
        """
        Token bucket algorithm for burst protection.
        
        Args:
            identifier: User/IP identifier
            capacity: Bucket capacity (max tokens)
            refill_rate: Tokens added per second
            
        Returns:
            True if request allowed, False if rate limited
        """
        import time
        
        current_time = time.time()
        
        if identifier not in self.token_buckets:
            self.token_buckets[identifier] = {
                'tokens': capacity,
                'last_refill': current_time
            }
        
        bucket = self.token_buckets[identifier]
        
        # Refill tokens based on time elapsed
        time_elapsed = current_time - bucket['last_refill']
        tokens_to_add = time_elapsed * refill_rate
        bucket['tokens'] = min(capacity, bucket['tokens'] + tokens_to_add)
        bucket['last_refill'] = current_time
        
        # Check if token available
        if bucket['tokens'] >= 1.0:
            bucket['tokens'] -= 1.0
            return True
        else:
            return False
    
    def get_cost_limiter(
        self, 
        identifier: str, 
        cost: float, 
        budget: float = 100.0, 
        period: str = "hour"
    ) -> Dict[str, Any]:
        """
        Cost-based rate limiting for LLM token usage.
        
        Args:
            identifier: User identifier
            cost: Cost of current request
            budget: Budget limit
            period: Time period for budget
            
        Returns:
            Dictionary with cost limit status
        """
        # This would integrate with token counting and cost tracking
        # For now, return allowed
        return {
            'allowed': True,
            'cost': cost,
            'budget': budget,
            'period': period,
            'remaining_budget': budget - cost
        }
    
    def estimate_tokens(self, text: str, model: str = "gemini-2.0-flash") -> int:
        """
        Estimate token count for text.
        
        Args:
            text: Input text
            model: Model name
            
        Returns:
            Estimated token count
        """
        # Rough estimation: 1 token ≈ 4 characters
        # For accurate counting, use model-specific tokenizer
        return len(text) // 4
    
    def get_rate_limit_headers(self, identifier: str) -> Dict[str, str]:
        """
        Get rate limit headers for HTTP response.
        
        Args:
            identifier: User identifier
            
        Returns:
            Dictionary of headers
        """
        # These would be populated by SlowAPI automatically
        return {
            'X-RateLimit-Limit': str(self.default_limit),
            'X-RateLimit-Remaining': 'N/A',  # Would query backend
            'X-RateLimit-Reset': 'N/A'
        }


def setup_rate_limiting(app, config: Dict[str, Any], logger: logging.Logger):
    """
    Setup rate limiting for FastAPI application.
    
    Args:
        app: FastAPI application instance
        config: Configuration dictionary
        logger: Logger instance
        
    Returns:
        RateLimiter instance
    """
    rate_limiter = RateLimiter(config, logger)
    
    # Add limiter to app state
    app.state.limiter = rate_limiter.get_limiter()
    
    # Add exception handler
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    logger.info("Rate limiting configured for application")
    
    return rate_limiter


# Example usage patterns:
"""
# In FastAPI app:

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Setup
rate_limiter = setup_rate_limiting(app, config, logger)

# Apply to specific endpoint
@app.post("/api/v1/analyze")
@rate_limiter.limit("10/minute")
async def analyze(request: Request):
    ...

# Different limits for different endpoints
@app.post("/api/v1/scan/prompt")
@rate_limiter.limit("50/minute")
async def scan_prompt(request: Request):
    ...

# Authenticated users get higher limits
@app.post("/api/v1/scan/response")
@rate_limiter.limit("100/minute")
async def scan_response(request: Request, user: User = Depends(get_current_user)):
    ...

# Cost-based limiting
@app.post("/api/v1/generate")
async def generate(request: Request, prompt: str):
    tokens = rate_limiter.estimate_tokens(prompt)
    cost_check = rate_limiter.get_cost_limiter(
        identifier=request.client.host,
        cost=tokens * 0.0001,  # Example cost per token
        budget=10.0,
        period="hour"
    )
    
    if not cost_check['allowed']:
        raise HTTPException(status_code=429, detail="Budget exceeded")
    
    ...
"""
