# Pydantic request/response models
"""Pydantic models for API requests and responses"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class PromptRequest(BaseModel):
    """Request model for prompt processing"""
    prompt: str = Field(..., min_length=1, max_length=10000, description="User prompt")
    user_id: Optional[str] = Field(None, description="Optional user identifier")
    
    class Config:
        json_schema_extra = {
            "example": {
                "prompt": "What is the capital of France?",
                "user_id": "user_123"
            }
        }


class PromptResponse(BaseModel):
    """Response model for prompt processing"""
    success: bool = Field(..., description="Whether the request was successful")
    action: str = Field(..., description="Action taken: PASS, SANITIZE, or BLOCK")
    response: Optional[str] = Field(None, description="LLM response (if not blocked)")
    threats_detected: List[str] = Field(default_factory=list, description="List of detected threats")
    severity: str = Field("NONE", description="Threat severity level")
    message: Optional[str] = Field(None, description="Additional message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "action": "PASS",
                "response": "The capital of France is Paris.",
                "threats_detected": [],
                "severity": "NONE",
                "message": "Request processed successfully"
            }
        }


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    version: str
    components: Dict[str, str]


class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = False
    error: str
    detail: Optional[str] = None