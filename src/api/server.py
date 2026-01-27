# FastAPI main server
"""FastAPI server"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import router
from src.core.config import get_settings
from src.core.pipeline import SecurityPipeline
from src.utils.logger import setup_logging, get_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    settings = get_settings()
    setup_logging(level=settings.logging.level)
    logger = get_logger(__name__)
    
    logger.info("=" * 60)
    logger.info(f"Starting {settings.app.name} v{settings.app.version}")
    logger.info("=" * 60)
    
    # Initialize pipeline
    app.state.pipeline = SecurityPipeline(settings)
    logger.info("Security pipeline initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down VeilArmor...")


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    settings = get_settings()
    
    app = FastAPI(
        title=settings.app.name,
        description="LLM Security Framework - Protect your AI applications",
        version=settings.app.version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routes
    app.include_router(router)
    
    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "src.api.server:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.app.debug
    )