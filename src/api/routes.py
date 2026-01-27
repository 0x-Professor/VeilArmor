# API endpoints
"""API routes"""

from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Optional

from .models import PromptRequest, PromptResponse, HealthResponse, ErrorResponse
from src.core.pipeline import SecurityPipeline
from src.core.config import Settings, get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()


def get_pipeline(request: Request) -> SecurityPipeline:
    """
    Dependency to get the security pipeline from app state.
    Uses the pipeline initialized during app lifespan (server.py).
    """
    pipeline = getattr(request.app.state, "pipeline", None)
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail="Security pipeline not initialized. Server is starting up."
        )
    return pipeline


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



# /process: Full pipeline (classify → sanitize → LLM → classify output → sanitize output)
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
    Full pipeline: classify → sanitize → LLM → classify output → sanitize output
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



# /sanitize: Only runs the sanitizer on the prompt (optionally, after classification)
@router.post(
    "/api/v1/sanitize",
    tags=["Security"]
)
async def sanitize_prompt(
    request: PromptRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """
    Sanitize a prompt (redact/cut malicious or sensitive parts).
    """
    try:
        sanitized = pipeline.input_sanitizer.sanitize(request.prompt)
        return {
            "original": request.prompt,
            "sanitized": sanitized
        }
    except Exception as e:
        logger.error(f"Error sanitizing request: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

# /classify-output: Classifies the LLM output for sensitive data disclosure
@router.post(
    "/api/v1/classify-output",
    tags=["Security"]
)
async def classify_output(
    request: PromptRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """
    Classify LLM output for sensitive data disclosure (no LLM call).
    """
    try:
        classification = pipeline.classifier.classify(request.prompt)
        return {
            "output": request.prompt[:100] + "..." if len(request.prompt) > 100 else request.prompt,
            "threats": classification.threats,
            "severity": classification.severity,
            "confidence": classification.confidence,
            "details": classification.details
        }
    except Exception as e:
        logger.error(f"Error classifying output: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

# /sanitize-output: Sanitizes the LLM output
@router.post(
    "/api/v1/sanitize-output",
    tags=["Security"]
)
async def sanitize_output(
    request: PromptRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """
    Sanitize LLM output (redact/cut sensitive parts).
    """
    try:
        sanitized = pipeline.output_sanitizer.sanitize(request.prompt)
        return {
            "original": request.prompt,
            "sanitized": sanitized
        }
    except Exception as e:
        logger.error(f"Error sanitizing output: {str(e)}")
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