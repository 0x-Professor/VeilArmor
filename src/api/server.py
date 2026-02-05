# FastAPI main server
"""
VeilArmor v2.0 - FastAPI Server

Main server application with middleware and lifecycle management.
"""

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .routes import router
from .middleware import (
    setup_middleware,
    RateLimitConfig,
    AuthConfig,
    AuthMethod,
)
from src.core.config import get_settings
from src.core.pipeline import SecurityPipeline
from src.utils.logger import setup_logging, get_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    settings = get_settings()
    setup_logging(level=settings.logging.level)
    logger = get_logger(__name__)
    
    logger.info("=" * 60)
    logger.info(f"Starting {settings.app.name} v{settings.app.version}")
    logger.info("=" * 60)
    
    # Record start time
    app.state.start_time = time.time()
    
    # Initialize pipeline
    try:
        app.state.pipeline = SecurityPipeline(settings)
        logger.info("Security pipeline initialized")
    except Exception as e:
        logger.error(f"Failed to initialize pipeline: {e}")
        raise
    
    logger.info("VeilArmor ready to accept requests")
    
    yield
    
    # Shutdown
    logger.info("Shutting down VeilArmor...")
    
    # Cleanup resources
    if hasattr(app.state, 'pipeline'):
        # Add any cleanup needed
        pass
    
    logger.info("VeilArmor shutdown complete")


def create_app(
    enable_rate_limit: bool = True,
    enable_auth: bool = False,
    api_keys: dict = None,
) -> FastAPI:
    """
    Create and configure FastAPI application.
    
    Args:
        enable_rate_limit: Enable rate limiting middleware
        enable_auth: Enable authentication middleware
        api_keys: API keys for authentication (key -> user_id)
        
    Returns:
        Configured FastAPI application
    """
    settings = get_settings()
    
    app = FastAPI(
        title=settings.app.name,
        description="""
## VeilArmor - Enterprise LLM Security Framework

Protect your AI applications from:
- **Prompt Injection** attacks
- **Jailbreak** attempts
- **PII Leakage**
- **Credential Exposure**
- **Adversarial Inputs**

### Features
- Multi-layer security pipeline
- Real-time threat classification
- Automatic content sanitization
- Semantic caching
- Multi-turn conversation support
        """,
        version=settings.app.version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_tags=[
            {"name": "System", "description": "Health and metrics endpoints"},
            {"name": "Security", "description": "Main security processing endpoints"},
            {"name": "Chat", "description": "Chat completion endpoints"},
            {"name": "Classification", "description": "Threat classification endpoints"},
            {"name": "Sanitization", "description": "Content sanitization endpoints"},
            {"name": "Validation", "description": "Content validation endpoints"},
            {"name": "Conversation", "description": "Conversation management endpoints"},
        ],
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.server.allowed_origins if hasattr(settings.server, 'allowed_origins') else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Setup security middleware
    rate_limit_config = None
    if enable_rate_limit:
        rate_limit_config = RateLimitConfig(
            requests_per_minute=60,
            requests_per_hour=1000,
            requests_per_day=10000,
        )
    
    auth_config = None
    if enable_auth and api_keys:
        auth_config = AuthConfig(
            method=AuthMethod.API_KEY,
            api_keys=api_keys,
        )
    
    setup_middleware(
        app,
        rate_limit=enable_rate_limit,
        rate_limit_config=rate_limit_config,
        auth=enable_auth,
        auth_config=auth_config,
        tracking=True,
        security_headers=True,
    )
    
    # Include routes
    app.include_router(router)
    
    # Exception handlers
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger = get_logger(__name__)
        logger.error(
            "Unhandled exception",
            path=request.url.path,
            error=str(exc),
        )
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": "internal_error",
                "message": "An unexpected error occurred",
            },
        )
    
    return app


# Create default app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "src.api.server:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.app.debug,
        workers=1,
        log_level="info",
    )