"""
Logging utilities
"""

import logging
import sys
from pathlib import Path
from typing import Dict, Any
from logging.handlers import RotatingFileHandler


def setup_logger(config: Dict[str, Any]) -> logging.Logger:
    """
    Setup logger with configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Configured logger instance
    """
    log_config = config.get('logging', {})
    
    # Get settings
    log_level = log_config.get('level', 'INFO')
    log_format = log_config.get('format', 'text')
    log_file = log_config.get('file', 'logs/modal_armor.log')
    max_size_mb = log_config.get('max_file_size_mb', 100)
    backup_count = log_config.get('backup_count', 5)
    
    # Create logger
    logger = logging.getLogger('modal_armor')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Choose format
    if log_format == 'json':
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"module": "%(name)s", "message": "%(message)s"}'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        # Create log directory
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger
