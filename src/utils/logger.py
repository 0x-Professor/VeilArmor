# Logging utility
"""Logging utility"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_format: Optional[str] = None,
    log_file: Optional[str] = None
) -> None:
    """
    Setup application logging.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_format: Custom log format
        log_file: Optional file path for logging
    """
    if log_format is None:
        log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    
    # Create logs directory if logging to file
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=log_format,
        handlers=handlers
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)