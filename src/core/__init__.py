"""
VeilArmor - Core Module

Pipeline orchestration and configuration.

Note: Imports are done lazily to avoid circular import issues.
"""

from .config import Settings, get_settings, reload_settings


# Lazy imports - these are available but imported on first use
def __getattr__(name):
    """Lazy import for pipeline components."""
    if name in (
        "SecurityPipeline", "PipelineConfig", "PipelineContext", 
        "PipelineResult", "PipelineHooks", "PipelineStage", 
        "StageResult", "Action", "Severity",
        "create_pipeline", "create_minimal_pipeline", "create_strict_pipeline"
    ):
        from . import pipeline
        return getattr(pipeline, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Config
    "Settings",
    "get_settings",
    "reload_settings",
    # Pipeline (lazy loaded)
    "SecurityPipeline",
    "PipelineConfig",
    "PipelineContext",
    "PipelineResult",
    "PipelineHooks",
    "PipelineStage",
    "StageResult",
    "Action",
    "Severity",
    "create_pipeline",
    "create_minimal_pipeline", 
    "create_strict_pipeline",
]
