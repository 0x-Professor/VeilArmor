"""
VeilArmor - Stream Logging Handler

Provides console/stream logging with optional color support.
"""

import logging
import sys
from typing import Any, Dict, Optional, TextIO

from src.logging.correlation import get_correlation_id


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright foreground colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


# Log level to color mapping
LEVEL_COLORS: Dict[str, str] = {
    "DEBUG": Colors.DIM + Colors.CYAN,
    "INFO": Colors.GREEN,
    "WARNING": Colors.YELLOW,
    "ERROR": Colors.RED,
    "CRITICAL": Colors.BOLD + Colors.BG_RED + Colors.WHITE,
}

# Layer to color mapping
LAYER_COLORS: Dict[str, str] = {
    "API_GATEWAY": Colors.BRIGHT_BLUE,
    "INPUT_PROCESSING": Colors.CYAN,
    "CLASSIFICATION_ENGINE": Colors.MAGENTA,
    "DECISION_ENGINE": Colors.BRIGHT_MAGENTA,
    "SANITIZATION": Colors.YELLOW,
    "LLM_PROVIDER": Colors.BRIGHT_GREEN,
    "OUTPUT_VALIDATION": Colors.BLUE,
    "OUTPUT_SANITIZATION": Colors.CYAN,
    "CONVERSATION": Colors.GREEN,
    "CACHE": Colors.DIM + Colors.WHITE,
}


class StreamHandler(logging.StreamHandler):
    """
    Enhanced stream handler with configurable formatting.
    """
    
    def __init__(
        self,
        stream: Optional[TextIO] = None,
        include_timestamp: bool = True,
        include_logger_name: bool = True,
        include_correlation_id: bool = True,
    ) -> None:
        """
        Initialize stream handler.
        
        Args:
            stream: Output stream (defaults to sys.stderr)
            include_timestamp: Include timestamp in output
            include_logger_name: Include logger name in output
            include_correlation_id: Include correlation ID in output
        """
        super().__init__(stream or sys.stderr)
        self.include_timestamp = include_timestamp
        self.include_logger_name = include_logger_name
        self.include_correlation_id = include_correlation_id
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log string
        """
        parts = []
        
        if self.include_timestamp:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            parts.append(timestamp)
        
        parts.append(f"[{record.levelname:8}]")
        
        if self.include_correlation_id:
            correlation_id = get_correlation_id()
            if correlation_id:
                parts.append(f"[{correlation_id}]")
        
        if self.include_logger_name:
            parts.append(f"[{record.name}]")
        
        parts.append(record.getMessage())
        
        return " ".join(parts)


class ColoredStreamHandler(StreamHandler):
    """
    Stream handler with colored output for terminals.
    """
    
    def __init__(
        self,
        stream: Optional[TextIO] = None,
        force_colors: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Initialize colored stream handler.
        
        Args:
            stream: Output stream (defaults to sys.stderr)
            force_colors: Force color output even if not a TTY
            **kwargs: Additional arguments passed to StreamHandler
        """
        super().__init__(stream, **kwargs)
        self.force_colors = force_colors
    
    @property
    def use_colors(self) -> bool:
        """Check if colors should be used."""
        if self.force_colors:
            return True
        
        # Check if output is a TTY
        if hasattr(self.stream, "isatty"):
            return self.stream.isatty()
        
        return False
    
    def colorize(self, text: str, color: str) -> str:
        """
        Apply color to text.
        
        Args:
            text: Text to colorize
            color: ANSI color code
            
        Returns:
            Colorized text if colors enabled, otherwise original text
        """
        if self.use_colors and color:
            return f"{color}{text}{Colors.RESET}"
        return text
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with colors.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted and colorized log string
        """
        parts = []
        
        if self.include_timestamp:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            parts.append(self.colorize(timestamp, Colors.DIM))
        
        # Colorized level
        level_color = LEVEL_COLORS.get(record.levelname, "")
        level_str = f"[{record.levelname:8}]"
        parts.append(self.colorize(level_str, level_color))
        
        if self.include_correlation_id:
            correlation_id = get_correlation_id()
            if correlation_id:
                parts.append(self.colorize(f"[{correlation_id}]", Colors.DIM))
        
        # Check for layer in record
        layer = getattr(record, "layer", None)
        if layer:
            layer_color = LAYER_COLORS.get(layer, "")
            parts.append(self.colorize(f"[{layer}]", layer_color))
        
        # Component
        component = getattr(record, "component", None)
        if component:
            parts.append(self.colorize(f"[{component}]", Colors.CYAN))
        
        if self.include_logger_name:
            parts.append(self.colorize(f"[{record.name}]", Colors.DIM))
        
        # Bold message
        message = record.getMessage()
        parts.append(self.colorize(message, Colors.BOLD))
        
        # Extra metadata
        extras = []
        skip_attrs = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "message", "asctime", "layer", "component",
        }
        for key, value in record.__dict__.items():
            if key not in skip_attrs and not key.startswith("_"):
                extras.append(
                    f"{self.colorize(key + '=', Colors.DIM)}{value}"
                )
        
        if extras:
            parts.append(" ".join(extras))
        
        return " ".join(parts)
