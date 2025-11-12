"""
Modal Armor REST API Server
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import argparse
from typing import Dict, Any

from modal_armor import ModalArmor
from modal_armor.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    CanaryAddRequest,
    CanaryAddResponse,
    CanaryCheckRequest,
    CanaryCheckResponse
)


# Initialize FastAPI app
app = FastAPI(
    title="Modal Armor API",
    description="LLM Security Framework - Protect against prompt injections, jailbreaks, and data leakage",
    version="1.0.0"
)

# Global Modal Armor instance
armor: ModalArmor = None


@app.on_event("startup")
async def startup_event():
    """Initialize Modal Armor on startup"""
    global armor
    
    # Load config path from command line or use default
    config_path = getattr(app.state, 'config_path', 'config/server.conf')
    
    print(f"Loading Modal Armor with config: {config_path}")
    armor = ModalArmor.from_config(config_path)
    print("Modal Armor initialized successfully")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Modal Armor API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "armor_initialized": armor is not None
    }


@app.post("/api/v1/analyze/prompt", response_model=None)
async def analyze_prompt(request: Dict[str, Any]):
    """
    Analyze a prompt for security threats.
    
    Request body:
        - prompt (str): The prompt to analyze
        - metadata (dict, optional): Additional metadata
        
    Returns:
        Scan result with threat detection details
    """
    if not armor:
        raise HTTPException(status_code=503, detail="Modal Armor not initialized")
    
    try:
        prompt = request.get('prompt')
        metadata = request.get('metadata')
        
        if not prompt:
            raise HTTPException(status_code=400, detail="prompt field is required")
        
        # Scan the prompt
        result = armor.scan_input(prompt, metadata)
        
        return {
            "status": "success",
            "result": result.to_dict()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/analyze/response", response_model=None)
async def analyze_response(request: Dict[str, Any]):
    """
    Analyze an LLM response for security threats.
    
    Request body:
        - prompt (str): The original prompt
        - response (str): The LLM response
        - metadata (dict, optional): Additional metadata
        
    Returns:
        Scan result with threat detection details
    """
    if not armor:
        raise HTTPException(status_code=503, detail="Modal Armor not initialized")
    
    try:
        prompt = request.get('prompt')
        response = request.get('response')
        metadata = request.get('metadata')
        
        if not prompt or not response:
            raise HTTPException(
                status_code=400,
                detail="prompt and response fields are required"
            )
        
        # Scan the response
        result = armor.scan_output(prompt, response, metadata)
        
        return {
            "status": "success",
            "result": result.to_dict()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/canary/add", response_model=None)
async def add_canary(request: Dict[str, Any]):
    """
    Add a canary token to a prompt.
    
    Request body:
        - prompt (str): The prompt to protect
        - always (bool, optional): Always include canary in response
        - length (int, optional): Canary token length
        - header (str, optional): Custom header format
        
    Returns:
        Protected prompt with embedded canary token
    """
    if not armor:
        raise HTTPException(status_code=503, detail="Modal Armor not initialized")
    
    try:
        prompt = request.get('prompt')
        always = request.get('always', False)
        length = request.get('length', 16)
        header = request.get('header')
        
        if not prompt:
            raise HTTPException(status_code=400, detail="prompt field is required")
        
        # Add canary
        protected_prompt = armor.add_canary(prompt, always, length, header)
        
        return {
            "status": "success",
            "prompt": protected_prompt,
            "original_length": len(prompt),
            "protected_length": len(protected_prompt)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/canary/check", response_model=None)
async def check_canary(request: Dict[str, Any]):
    """
    Check if text contains a canary token.
    
    Request body:
        - text (str): The text to check
        
    Returns:
        Canary detection result
    """
    if not armor:
        raise HTTPException(status_code=503, detail="Modal Armor not initialized")
    
    try:
        text = request.get('text')
        
        if not text:
            raise HTTPException(status_code=400, detail="text field is required")
        
        # Check for canary
        result = armor.canary_manager.check(text)
        
        return {
            "status": "success",
            "result": result.to_dict()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stats")
async def get_stats():
    """
    Get scanner statistics.
    
    Returns:
        Statistics about scanner performance
    """
    if not armor:
        raise HTTPException(status_code=503, detail="Modal Armor not initialized")
    
    try:
        stats = armor.get_stats()
        canary_stats = armor.canary_manager.get_stats()
        
        return {
            "status": "success",
            "scanner_stats": stats,
            "canary_stats": canary_stats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/config")
async def get_config():
    """
    Get current configuration (sensitive fields redacted).
    
    Returns:
        Configuration summary
    """
    if not armor:
        raise HTTPException(status_code=503, detail="Modal Armor not initialized")
    
    # Redact sensitive information
    safe_config = {
        "scanners": armor.config.get('scanners', {}),
        "logging": {
            "level": armor.config.get('logging', {}).get('level'),
            "format": armor.config.get('logging', {}).get('format')
        },
        "vectordb": {
            "type": armor.config.get('vectordb', {}).get('type'),
            "model": armor.config.get('vectordb', {}).get('embedding_model'),
            "threshold": armor.config.get('vectordb', {}).get('similarity_threshold')
        }
    }
    
    return {
        "status": "success",
        "config": safe_config
    }


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Modal Armor REST API Server')
    parser.add_argument(
        '--config',
        type=str,
        default='config/server.conf',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host to bind to'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind to'
    )
    parser.add_argument(
        '--reload',
        action='store_true',
        help='Enable auto-reload for development'
    )
    
    args = parser.parse_args()
    
    # Store config path in app state
    app.state.config_path = args.config
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Run server
    print("="*70)
    print("🛡️  Modal Armor REST API Server")
    print("="*70)
    print(f"Config: {args.config}")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Docs: http://{args.host}:{args.port}/docs")
    print("="*70)
    
    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )


if __name__ == "__main__":
    main()
