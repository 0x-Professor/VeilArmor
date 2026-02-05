"""
VeilArmor v2.0 - Logging Module

Enterprise-grade logging system with correlation IDs, structured logging,
colored console output, and comprehensive layer-based tracking.
"""

from src.logging.config import configure_logging, get_logger, LogConfig
from src.logging.correlation import (
    CorrelationContext,
    get_correlation_id,
    set_correlation_id,
    correlation_context,
)
from src.logging.metrics import MetricsCollector, get_metrics

__all__ = [
    "configure_logging",
    "get_logger",
    "LogConfig",
    "CorrelationContext",
    "get_correlation_id",
    "set_correlation_id",
    "correlation_context",
    "MetricsCollector",
    "get_metrics",
]
