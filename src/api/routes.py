# API endpoints
"""
VeilArmor - API Routes

Comprehensive API endpoints for the security framework.
"""

import time
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Request, BackgroundTasks
from fastapi.responses import StreamingResponse

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
from src.core.pipeline import SecurityPipeline
from src.core.config import Settings, get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _format_change(change: dict) -> str:
    """
    Format a sanitization change dict into a human-readable string.
    
    Change dicts from strategies use keys like 'type', 'pii_type',
    'replacement', 'category', 'action', 'original_preview', etc.
    """
    change_type = change.get("type", "unknown")
    
    # Build a descriptive label based on the change type
    if change_type == "pii_redaction":
        pii_type = change.get("pii_type", "unknown")
        replacement = change.get("replacement", "[REDACTED]")
        return f"pii_redaction: {pii_type} replaced with {replacement}"
    elif change_type == "injection_neutralization":
        category = change.get("category", "injection")
        return f"injection_neutralization: {category} pattern neutralized"
    elif change_type == "normalization":
        action = change.get("action", "normalized")
        return f"normalization: {action}"
    elif change_type == "toxicity_removal":
        category = change.get("category", "toxic content")
        return f"toxicity_removal: {category} removed"
    elif change_type == "html_escape":
        return "html_escape: special characters escaped"
    elif change_type == "masking":
        return f"masking: sensitive content masked"
    else:
        return f"{change_type}: content modified"


# ---------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------

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


def get_request_id(request: Request) -> Optional[str]:
    """Get request ID from state."""
    return getattr(request.state, "request_id", None)


def get_user_id(request: Request) -> Optional[str]:
    """Get user ID from state (set by auth middleware)."""
    return getattr(request.state, "user_id", None)


# ---------------------------------------------------------------------
# System Endpoints
# ---------------------------------------------------------------------

@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health Check",
)
async def health_check(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """
    Health check endpoint.
    Returns the status of the service and its components.
    """
    uptime = None
    if hasattr(request.app.state, "start_time"):
        uptime = time.time() - request.app.state.start_time
    
    return HealthResponse(
        status="healthy",
        version=settings.app.version,
        components={
            "api": "healthy",
            "classifier": "healthy",
            "sanitizer": "healthy",
            "llm": "healthy",
        },
        uptime_seconds=uptime,
    )


@router.get(
    "/metrics",
    response_model=MetricsResponse,
    tags=["System"],
    summary="Get Metrics",
)
async def get_metrics(
    request: Request,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Get system metrics.
    Returns detailed metrics about requests, classification, and caching.
    """
    # Get request tracker metrics
    request_metrics = {}
    if hasattr(request.app.state, "request_tracker"):
        request_metrics = request.app.state.request_tracker.get_metrics()
    
    # Get pipeline metrics
    pipeline_metrics = pipeline.get_metrics()
    
    return MetricsResponse(
        requests={**request_metrics, **pipeline_metrics},
        classification={
            "total_classified": pipeline_metrics.get("total_requests", 0),
            "blocked": pipeline_metrics.get("blocked_requests", 0),
            "block_rate": pipeline_metrics.get("block_rate", 0),
        },
        sanitization={
            "sanitized_requests": pipeline_metrics.get("sanitized_requests", 0),
        },
        cache={
            "cache_hits": pipeline_metrics.get("cache_hits", 0),
            "cache_hit_rate": pipeline_metrics.get("cache_hit_rate", 0),
        },
    )


# ---------------------------------------------------------------------
# Main Processing Endpoints
# ---------------------------------------------------------------------

@router.post(
    "/api/v1/process",
    response_model=PromptResponse,
    responses={
        200: {"description": "Request processed successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        429: {"description": "Rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
    tags=["Security"],
    summary="Process Prompt",
)
async def process_prompt(
    request_body: PromptRequest,
    request: Request,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Full security pipeline processing.
    
    Steps:
    1. Input classification (threat detection)
    2. Input sanitization (if needed)
    3. LLM processing
    4. Output classification
    5. Output sanitization
    
    Returns the processed response with security metadata.
    """
    start_time = time.time()
    request_id = get_request_id(request)
    
    try:
        logger.info(
            "Processing request",
            request_id=request_id,
            user_id=request_body.user_id,
        )
        
        result = await pipeline.process(
            prompt=request_body.prompt,
            user_id=request_body.user_id,
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        return PromptResponse(
            success=result.success,
            action=ActionType(result.action.value),
            response=result.response,
            threats_detected=result.threats_detected,
            severity=SeverityLevel(result.severity.value),
            message=result.message or "Processed successfully",
            request_id=request_id,
            processing_time_ms=processing_time,
        )
        
    except Exception as e:
        logger.error(
            "Error processing request",
            request_id=request_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


@router.post(
    "/api/v1/chat",
    response_model=ChatResponse,
    responses={
        200: {"description": "Chat completed successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
    tags=["Chat"],
    summary="Chat Completion",
)
async def chat_completion(
    request_body: ChatRequest,
    request: Request,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Chat completion with security.
    
    Processes a chat conversation through the security pipeline
    and returns the model's response.
    """
    request_id = get_request_id(request)
    
    try:
        # Get the last user message for processing
        user_messages = [m for m in request_body.messages if m.role == "user"]
        if not user_messages:
            raise HTTPException(
                status_code=400,
                detail="No user message found in request",
            )
        
        last_message = user_messages[-1].content
        
        result = await pipeline.process(
            prompt=last_message,
            user_id=request_body.user_id,
        )
        
        return ChatResponse(
            id=request_id or "chat_response",
            content=result.response or result.message or "",
            role="assistant",
            finish_reason="stop" if result.success else "content_filter",
            security={
                "threats_detected": result.threats_detected,
                "action": result.action.value,
                "severity": result.severity.value,
            },
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error in chat completion",
            request_id=request_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ---------------------------------------------------------------------
# Classification Endpoints
# ---------------------------------------------------------------------

@router.post(
    "/api/v1/classify",
    response_model=ClassifyResponse,
    tags=["Classification"],
    summary="Classify Text",
)
async def classify_text(
    request_body: ClassifyRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Classify text for security threats.
    
    Analyzes text without processing through LLM.
    Useful for testing and pre-screening content.
    """
    try:
        classification = await pipeline.classifier.classify_input(request_body.text)
        
        threats = [r.threat_type for r in classification.get_threats()]
        
        return ClassifyResponse(
            text_preview=request_body.text[:100] + "..." if len(request_body.text) > 100 else request_body.text,
            threats=threats,
            severity=SeverityLevel(SecurityPipeline._map_severity(classification.max_severity).value),
            confidence=classification.aggregated_score,
            details=classification.to_dict(),
        )
        
    except Exception as e:
        logger.error("Error classifying text", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


@router.post(
    "/api/v1/classify-output",
    response_model=ClassifyResponse,
    tags=["Classification"],
    summary="Classify Output",
)
async def classify_output(
    request_body: ClassifyRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Classify LLM output for sensitive data disclosure.
    
    Specifically designed for analyzing model outputs
    for PII leakage, credential exposure, etc.
    """
    try:
        classification = await pipeline.classifier.classify_output(request_body.text)
        
        threats = [r.threat_type for r in classification.get_threats()]
        
        return ClassifyResponse(
            text_preview=request_body.text[:100] + "..." if len(request_body.text) > 100 else request_body.text,
            threats=threats,
            severity=SeverityLevel(SecurityPipeline._map_severity(classification.max_severity).value),
            confidence=classification.aggregated_score,
            details=classification.to_dict(),
        )
        
    except Exception as e:
        logger.error("Error classifying output", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ---------------------------------------------------------------------
# Sanitization Endpoints
# ---------------------------------------------------------------------

@router.post(
    "/api/v1/sanitize",
    response_model=SanitizeResponse,
    tags=["Sanitization"],
    summary="Sanitize Input",
)
async def sanitize_input(
    request_body: SanitizeRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Sanitize input text.
    
    Removes or redacts malicious or sensitive content
    from the input before processing.
    """
    try:
        result = pipeline.input_sanitizer.sanitize(request_body.text)
        
        return SanitizeResponse(
            original=request_body.text,
            sanitized=result.sanitized_text,
            modifications=[
                _format_change(c) for c in result.changes
            ] if result.changes else [],
        )
        
    except Exception as e:
        logger.error("Error sanitizing input", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


@router.post(
    "/api/v1/sanitize-output",
    response_model=SanitizeResponse,
    tags=["Sanitization"],
    summary="Sanitize Output",
)
async def sanitize_output(
    request_body: SanitizeRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Sanitize LLM output.
    
    Removes sensitive data from model responses
    before returning to the user.
    """
    try:
        result = pipeline.output_sanitizer.sanitize(request_body.text)
        
        return SanitizeResponse(
            original=request_body.text,
            sanitized=result.sanitized_text,
            modifications=[
                _format_change(c) for c in result.changes
            ] if result.changes else [],
        )
        
    except Exception as e:
        logger.error("Error sanitizing output", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ---------------------------------------------------------------------
# Validation Endpoints
# ---------------------------------------------------------------------

@router.post(
    "/api/v1/validate",
    response_model=ValidateResponse,
    tags=["Validation"],
    summary="Validate Text",
)
async def validate_text(
    request_body: ValidateRequest,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Validate text against security rules.
    
    Checks for format, content, and safety violations
    without modifying the text.
    """
    try:
        # validation_engine is a property that returns None if unavailable
        engine = pipeline.validation_engine
        if engine is not None:
            result = await engine.validate(request_body.text)
            
            return ValidateResponse(
                is_valid=result.is_valid,
                violations=[
                    {
                        "rule": v.rule_name,
                        "message": v.message,
                        "severity": v.severity.value,
                    }
                    for v in result.violations
                ],
                error_count=result.error_count,
                warning_count=result.warning_count,
            )
        else:
            logger.warning("Validation engine not available")
            raise HTTPException(
                status_code=501,
                detail="Validation engine not available in current configuration",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error validating text", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ---------------------------------------------------------------------
# Conversation Endpoints
# ---------------------------------------------------------------------

@router.post(
    "/api/v1/conversation/create",
    tags=["Conversation"],
    summary="Create Conversation",
)
async def create_conversation(
    system_prompt: Optional[str] = None,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Create a new conversation.
    
    Returns a conversation ID for multi-turn interactions.
    """
    try:
        if pipeline.conversation_manager is not None:
            conv = pipeline.conversation_manager.create_conversation(
                system_prompt=system_prompt,
            )
            return {"conversation_id": conv.id}
        else:
            raise HTTPException(
                status_code=501,
                detail="Conversation management not enabled",
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error creating conversation", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


@router.get(
    "/api/v1/conversation/{conversation_id}",
    tags=["Conversation"],
    summary="Get Conversation",
)
async def get_conversation(
    conversation_id: str,
    pipeline: SecurityPipeline = Depends(get_pipeline),
):
    """
    Get conversation details.
    
    Returns the conversation history and metadata.
    """
    try:
        if pipeline.conversation_manager is not None:
            conv = await pipeline.conversation_manager.get_conversation(conversation_id)
            if conv is None:
                raise HTTPException(
                    status_code=404,
                    detail="Conversation not found",
                )
            return conv.to_dict()
        else:
            raise HTTPException(
                status_code=501,
                detail="Conversation management not enabled",
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting conversation", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )