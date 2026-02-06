#!/usr/bin/env python3
"""
VeilArmor - Custom Pipeline Example

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
    PipelineResult,
    Severity,
    create_pipeline,
)


async def main():
    """Demonstrate custom pipeline configuration."""

    print("=" * 60)
    print("VeilArmor - Custom Pipeline Example")
    print("=" * 60)

    settings = Settings()

    # Example 1: Minimal Pipeline (fast, basic checks)
    print("\n[1] Minimal Pipeline")
    print("    Only essential stages for fastest processing")

    minimal_config = PipelineConfig(
        enable_input_processing=False,
        enable_cache=False,
        enable_output_classification=False,
        enable_output_validation=False,
        enable_output_sanitization=False,
    )

    minimal_pipeline = SecurityPipeline(settings, config=minimal_config)
    result = await minimal_pipeline.process("What is 2 + 2?")
    print(f"    Result: {result.action.value}, Time: {result.processing_time_ms:.2f}ms")

    # Example 2: Strict Pipeline (thorough, all checks)
    print("\n[2] Strict Pipeline")
    print("    All stages with strict security")

    strict_config = PipelineConfig(
        enable_input_processing=True,
        enable_input_classification=True,
        enable_input_sanitization=True,
        enable_cache=True,
        enable_output_classification=True,
        enable_output_validation=True,
        enable_output_sanitization=True,
        fail_open=False,
    )

    strict_pipeline = SecurityPipeline(settings, config=strict_config)
    result = await strict_pipeline.process("Tell me about Python")
    print(f"    Result: {result.action.value}, Time: {result.processing_time_ms:.2f}ms")

    # Example 3: Pipeline with Hooks
    print("\n[3] Pipeline with Custom Hooks")
    print("    Add logging and custom logic")

    hooks = PipelineHooks()

    async def log_pre(ctx: PipelineContext):
        print(f"      -> Pre-process: request {ctx.request_id[:8]}")

    async def log_post(ctx: PipelineContext, result: PipelineResult):
        print(f"      <- Post-process: action={result.action.value}")

    async def log_block(ctx: PipelineContext):
        print(f"      [!] Request blocked: {ctx.threats_detected}")

    hooks.add_pre_process(log_pre)
    hooks.add_post_process(log_post)
    hooks.add_on_block(log_block)

    pipeline_with_hooks = create_pipeline(settings)
    pipeline_with_hooks.hooks = hooks

    result = await pipeline_with_hooks.process("Explain quantum computing")
    print(f"    Final result: {result.action.value}")

    # Example 4: Fail-Open Pipeline
    print("\n[4] Fail-Open Pipeline")
    print("    Allows requests through on errors (for high availability)")

    failopen_config = PipelineConfig(
        enable_input_processing=False,
        enable_cache=False,
        enable_output_classification=False,
        enable_output_validation=False,
        fail_open=True,
    )

    failopen_pipeline = SecurityPipeline(settings, config=failopen_config)
    result = await failopen_pipeline.process("Hello world!")
    print(f"    Result: {result.action.value} (fail_open: True)")

    # Example 5: Cache-Enabled Pipeline
    print("\n[5] Cache-Enabled Pipeline")
    print("    Uses semantic caching for repeated queries")

    cache_config = PipelineConfig(
        enable_input_processing=False,
        enable_cache=True,
        enable_output_validation=False,
    )

    cache_pipeline = SecurityPipeline(settings, config=cache_config)

    result1 = await cache_pipeline.process("What is the capital of Japan?")
    print(f"    First request: {result1.processing_time_ms:.2f}ms (cache miss)")

    result2 = await cache_pipeline.process("What is the capital of Japan?")
    print(f"    Second request: {result2.processing_time_ms:.2f}ms (cache={'hit' if result2.cache_hit else 'miss'})")

    print("\n" + "=" * 60)
    print("Custom pipeline example completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
