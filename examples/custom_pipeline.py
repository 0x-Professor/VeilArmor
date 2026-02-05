#!/usr/bin/env python3
"""
VeilArmor v2.0 - Custom Pipeline Example

This example demonstrates how to create custom pipelines
with specific configurations and hooks.
"""

import asyncio
from src.core.config import Settings
from src.core.pipeline import (
    SecurityPipeline,
    PipelineConfig,
    PipelineHooks,
    PipelineStage,
    PipelineContext,
    Severity,
    create_pipeline,
)


async def main():
    """Demonstrate custom pipeline configuration."""
    
    print("=" * 60)
    print("VeilArmor v2.0 - Custom Pipeline Example")
    print("=" * 60)
    
    settings = Settings()
    
    # Example 1: Minimal Pipeline (fast, basic checks)
    print("\n[1] Minimal Pipeline")
    print("    Only essential stages for fastest processing")
    
    minimal_config = PipelineConfig(
        stages=[
            PipelineStage.INPUT_PROCESSING,
            PipelineStage.INPUT_CLASSIFICATION,
            PipelineStage.DECISION,
            PipelineStage.LLM_CALL,
        ],
        block_threshold=Severity.CRITICAL,  # Only block critical threats
        sanitize_threshold=Severity.HIGH,
        fail_open=False,
    )
    
    minimal_pipeline = SecurityPipeline(settings, config=minimal_config)
    result = await minimal_pipeline.process("What is 2 + 2?")
    print(f"    Result: {result.action.value}, Time: {result.processing_time:.2f}ms")
    
    # Example 2: Strict Pipeline (thorough, all checks)
    print("\n[2] Strict Pipeline")
    print("    All stages with strict thresholds")
    
    strict_config = PipelineConfig(
        stages=[
            PipelineStage.INPUT_PROCESSING,
            PipelineStage.INPUT_CLASSIFICATION,
            PipelineStage.DECISION,
            PipelineStage.INPUT_SANITIZATION,
            PipelineStage.CACHE_CHECK,
            PipelineStage.LLM_CALL,
            PipelineStage.OUTPUT_CLASSIFICATION,
            PipelineStage.OUTPUT_VALIDATION,
            PipelineStage.OUTPUT_SANITIZATION,
        ],
        block_threshold=Severity.MEDIUM,  # Block medium and above
        sanitize_threshold=Severity.LOW,  # Sanitize anything suspicious
        fail_open=False,
        collect_metrics=True,
    )
    
    strict_pipeline = SecurityPipeline(settings, config=strict_config)
    result = await strict_pipeline.process("Tell me about Python")
    print(f"    Result: {result.action.value}, Time: {result.processing_time:.2f}ms")
    
    # Example 3: Pipeline with Hooks
    print("\n[3] Pipeline with Custom Hooks")
    print("    Add logging and custom logic at each stage")
    
    class CustomHooks(PipelineHooks):
        """Custom hooks for pipeline stages."""
        
        async def pre_stage(self, stage: PipelineStage, context: PipelineContext):
            """Called before each stage."""
            print(f"      -> Starting stage: {stage.value}")
        
        async def post_stage(self, stage: PipelineStage, context: PipelineContext, result):
            """Called after each stage."""
            print(f"      <- Completed stage: {stage.value}")
        
        async def on_block(self, context: PipelineContext, reason: str):
            """Called when a request is blocked."""
            print(f"      [!] Request blocked: {reason}")
        
        async def on_error(self, stage: PipelineStage, error: Exception):
            """Called on error."""
            print(f"      [X] Error in {stage.value}: {error}")
    
    hooks = CustomHooks()
    pipeline_with_hooks = create_pipeline(settings)
    pipeline_with_hooks.hooks = hooks
    
    result = await pipeline_with_hooks.process("Explain quantum computing")
    print(f"    Final result: {result.action.value}")
    
    # Example 4: Fail-Open Pipeline
    print("\n[4] Fail-Open Pipeline")
    print("    Allows requests through on errors (for high availability)")
    
    failopen_config = PipelineConfig(
        stages=[
            PipelineStage.INPUT_PROCESSING,
            PipelineStage.INPUT_CLASSIFICATION,
            PipelineStage.DECISION,
            PipelineStage.LLM_CALL,
        ],
        block_threshold=Severity.HIGH,
        fail_open=True,  # Allow through on errors
        collect_metrics=True,
    )
    
    failopen_pipeline = SecurityPipeline(settings, config=failopen_config)
    result = await failopen_pipeline.process("Hello world!")
    print(f"    Result: {result.action.value} (fail_open: True)")
    
    # Example 5: Cache-Enabled Pipeline
    print("\n[5] Cache-Enabled Pipeline")
    print("    Uses semantic caching for repeated queries")
    
    cache_config = PipelineConfig(
        stages=[
            PipelineStage.INPUT_PROCESSING,
            PipelineStage.CACHE_CHECK,  # Check cache first
            PipelineStage.INPUT_CLASSIFICATION,
            PipelineStage.DECISION,
            PipelineStage.INPUT_SANITIZATION,
            PipelineStage.LLM_CALL,
            PipelineStage.OUTPUT_SANITIZATION,
        ],
        block_threshold=Severity.HIGH,
        collect_metrics=True,
    )
    
    cache_pipeline = SecurityPipeline(settings, config=cache_config)
    
    # First request (cache miss)
    result1 = await cache_pipeline.process("What is the capital of Japan?")
    print(f"    First request: {result1.processing_time:.2f}ms (cache miss)")
    
    # Second request (should be cache hit)
    result2 = await cache_pipeline.process("What is the capital of Japan?")
    print(f"    Second request: {result2.processing_time:.2f}ms (cache hit)")
    
    print("\n" + "=" * 60)
    print("Custom pipeline example completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
