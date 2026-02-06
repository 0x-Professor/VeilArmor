# Logging utility
"""
VeilArmor - Logging Utility

Provides structured logging with colored output.
"""

import logging
import sys
from pathlib import Path
from typing import Optional, Any


class StructuredLogger(logging.Logger):
    """
    Logger that supports keyword arguments for structured logging.
    Formats kwargs as key=value pairs appended to the message.
    """
    
    def _log_with_extras(
        self, 
        level: int, 
        msg: str, 
        args: tuple,
        exc_info: Any = None,
        extra: dict = None,
        stack_info: bool = False,
        stacklevel: int = 2,
        **kwargs
    ) -> None:
        """Log with extra keyword arguments formatted into the message."""
        if kwargs:
            extras = " | ".join(f"{k}={v}" for k, v in kwargs.items())
            msg = f"{msg} | {extras}"
        super()._log(level, msg, args, exc_info, extra, stack_info, stacklevel)
    
    def info(self, msg: str, *args, **kwargs) -> None:
        if self.isEnabledFor(logging.INFO):
            self._log_with_extras(logging.INFO, msg, args, **kwargs)
    
    def debug(self, msg: str, *args, **kwargs) -> None:
        if self.isEnabledFor(logging.DEBUG):
            self._log_with_extras(logging.DEBUG, msg, args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs) -> None:
        if self.isEnabledFor(logging.WARNING):
            self._log_with_extras(logging.WARNING, msg, args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs) -> None:
        if self.isEnabledFor(logging.ERROR):
            self._log_with_extras(logging.ERROR, msg, args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs) -> None:
        if self.isEnabledFor(logging.CRITICAL):
            self._log_with_extras(logging.CRITICAL, msg, args, **kwargs)


# Register custom logger class
logging.setLoggerClass(StructuredLogger)


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"


class ColoredFormatter(logging.Formatter):
    """
    Colored log formatter for terminal output.
    """
    
    LEVEL_COLORS = {
        "DEBUG": Colors.CYAN,
        "INFO": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "CRITICAL": Colors.BRIGHT_RED + Colors.BOLD,
    }
    
    def format(self, record: logging.LogRecord) -> str:
        # Get color for level
        color = self.LEVEL_COLORS.get(record.levelname, "")
        reset = Colors.RESET
        
        # Format level with color
        original_levelname = record.levelname
        record.levelname = f"{color}{record.levelname:<8}{reset}"
        
        # Format name with dim color
        original_name = record.name
        record.name = f"{Colors.DIM}{record.name}{reset}"
        
        result = super().format(record)
        
        # Restore original values
        record.levelname = original_levelname
        record.name = original_name
        
        return result


def setup_logging(
    level: str = "INFO",
    log_format: Optional[str] = None,
    log_file: Optional[str] = None,
    use_colors: bool = True
) -> None:
    """
    Setup application logging.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_format: Custom log format
        log_file: Optional file path for logging
        use_colors: Enable colored output for terminal
    """
    if log_format is None:
        log_format = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    
    # Create logs directory if logging to file
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers = []
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    
    if use_colors and sys.stdout.isatty():
        console_handler.setFormatter(ColoredFormatter(log_format))
    else:
        console_handler.setFormatter(logging.Formatter(log_format))
    
    root_logger.addHandler(console_handler)
    
    # File handler (no colors)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        file_handler.setFormatter(logging.Formatter(log_format))
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> StructuredLogger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        StructuredLogger instance with keyword argument support
    """
    # Ensure our custom logger class is set (structlog may override it)
    logging.setLoggerClass(StructuredLogger)
    logger = logging.getLogger(name)
    # Patch existing loggers that were created before setLoggerClass
    if not isinstance(logger, StructuredLogger):
        logger.__class__ = StructuredLogger
    return logger