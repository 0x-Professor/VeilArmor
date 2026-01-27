# API endpoints
"""API routes"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional

from .models import PromptRequest, PromptResponse, HealthResponse, ErrorResponse
from src.core.pipeline import SecurityPipeline
from src.core.config import Settings, get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()

# Global pipeline instance (initialized on startup)
_pipeline: Optional[SecurityPipeline] = None


def get_pipeline() -> SecurityPipeline:
    """Dependency to get the security pipeline"""
    global _pipeline
    if _pipeline is None:
        _pipeline = SecurityPipeline()
    return _pipeline


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check(settings: Settings = Depends(get_settings)):
    """
    Health check endpoint.
    Returns the status of the service and its components.
    """
    return HealthResponse(
        status="healthy",
        version=settings.app.version,
        components={
            "api": "healthy",
            "classifier": "healthy",
            "sanitizer": "healthy",
            "llm": "healthy"
        }
    )


@router.post(
    "/api/v1/process",
    response_model=PromptResponse,
    responses={
        200: {"description": "Request processed successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    tags=["Security"]
)
async def process_prompt(
    request: PromptRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """
    Process a user prompt through the security pipeline.
    
    The pipeline will:
    1. Classify the prompt for threats
    2. Decide to BLOCK, SANITIZE, or PASS
    3. If not blocked, send to LLM and return response
    4. Analyze and sanitize the response before returning
    """
    try:
        logger.info(f"Processing request from user: {request.user_id or 'anonymous'}")
        
        result = await pipeline.process(
            prompt=request.prompt,
            user_id=request.user_id
        )
        
        return PromptResponse(**result.to_dict())
    
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@router.post(
    "/api/v1/classify",
    tags=["Security"]
)
async def classify_only(
    request: PromptRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """
    Classify a prompt without processing through LLM.
    Useful for testing and analysis.
    """
    try:
        classification = pipeline.classifier.classify(request.prompt)
        
        return {
            "prompt": request.prompt[:100] + "..." if len(request.prompt) > 100 else request.prompt,
            "threats": classification.threats,
            "severity": classification.severity,
            "confidence": classification.confidence,
            "details": classification.details
        }
    
    except Exception as e:
        logger.error(f"Error classifying request: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )