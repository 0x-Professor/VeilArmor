"""
VeilArmor v2.0 - Colored Log Formatter

Provides colored console output for log records.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from src.logging.correlation import get_correlation_id, get_request_context


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    
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
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"


# Log level to color mapping
LEVEL_COLORS: Dict[str, str] = {
    "DEBUG": Colors.DIM + Colors.CYAN,
    "INFO": Colors.GREEN,
    "WARNING": Colors.YELLOW,
    "ERROR": Colors.RED,
    "CRITICAL": Colors.BOLD + Colors.BG_RED + Colors.WHITE,
}

# VeilArmor layer to color mapping
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


class ColoredFormatter(logging.Formatter):
    """
    Log formatter that adds ANSI colors to output.
    
    Features:
    - Level-based coloring
    - Layer-based coloring for VeilArmor components
    - Correlation ID highlighting
    - Metadata display
    """
    
    # Standard LogRecord attributes to exclude from extras
    STANDARD_ATTRS: Set[str] = {
        "name", "msg", "args", "created", "filename", "funcName",
        "levelname", "levelno", "lineno", "module", "msecs",
        "pathname", "process", "processName", "relativeCreated",
        "stack_info", "exc_info", "exc_text", "thread", "threadName",
        "message", "asctime", "taskName", "layer", "component",
    }
    
    def __init__(
        self,
        use_colors: bool = True,
        include_timestamp: bool = True,
        include_correlation_id: bool = True,
        include_logger_name: bool = True,
        include_extras: bool = True,
        timestamp_format: str = "%Y-%m-%d %H:%M:%S.%f",
    ) -> None:
        """
        Initialize colored formatter.
        
        Args:
            use_colors: Enable colored output
            include_timestamp: Include timestamp in output
            include_correlation_id: Include correlation ID
            include_logger_name: Include logger name
            include_extras: Include extra metadata fields
            timestamp_format: strftime format for timestamps
        """
        super().__init__()
        self.use_colors = use_colors
        self.include_timestamp = include_timestamp
        self.include_correlation_id = include_correlation_id
        self.include_logger_name = include_logger_name
        self.include_extras = include_extras
        self.timestamp_format = timestamp_format
    
    def colorize(self, text: str, color: str) -> str:
        """
        Apply color to text.
        
        Args:
            text: Text to colorize
            color: ANSI color code(s)
            
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
        
        # Timestamp
        if self.include_timestamp:
            timestamp = datetime.now(timezone.utc).strftime(self.timestamp_format)[:-3]
            parts.append(self.colorize(timestamp, Colors.DIM))
        
        # Level with color
        level_color = LEVEL_COLORS.get(record.levelname, "")
        level_str = f"[{record.levelname:8}]"
        parts.append(self.colorize(level_str, level_color))
        
        # Correlation ID
        if self.include_correlation_id:
            correlation_id = get_correlation_id()
            if correlation_id:
                parts.append(self.colorize(f"[{correlation_id}]", Colors.DIM))
        
        # Layer (VeilArmor-specific)
        layer = getattr(record, "layer", None)
        if layer:
            layer_color = LAYER_COLORS.get(layer, Colors.WHITE)
            parts.append(self.colorize(f"[{layer}]", layer_color))
        
        # Component
        component = getattr(record, "component", None)
        if component:
            parts.append(self.colorize(f"[{component}]", Colors.CYAN))
        
        # Logger name
        if self.include_logger_name:
            # Shorten logger name for readability
            logger_name = record.name
            if len(logger_name) > 30:
                parts_list = logger_name.split(".")
                if len(parts_list) > 2:
                    logger_name = f"{parts_list[0]}...{parts_list[-1]}"
            parts.append(self.colorize(f"[{logger_name}]", Colors.DIM))
        
        # Message (bold)
        message = record.getMessage()
        parts.append(self.colorize(message, Colors.BOLD))
        
        # Extra metadata
        if self.include_extras:
            extras = []
            for key, value in record.__dict__.items():
                if key not in self.STANDARD_ATTRS and not key.startswith("_"):
                    key_str = self.colorize(f"{key}=", Colors.DIM)
                    # Colorize specific values
                    if key == "severity" and isinstance(value, (int, float)):
                        if value >= 0.7:
                            val_str = self.colorize(str(value), Colors.RED)
                        elif value >= 0.4:
                            val_str = self.colorize(str(value), Colors.YELLOW)
                        else:
                            val_str = self.colorize(str(value), Colors.GREEN)
                    elif key == "action":
                        if value == "BLOCK":
                            val_str = self.colorize(str(value), Colors.RED)
                        elif value == "SANITIZE":
                            val_str = self.colorize(str(value), Colors.YELLOW)
                        else:
                            val_str = self.colorize(str(value), Colors.GREEN)
                    elif key == "threat_type":
                        val_str = self.colorize(str(value), Colors.MAGENTA)
                    elif key == "processing_time_ms":
                        if isinstance(value, (int, float)) and value > 500:
                            val_str = self.colorize(f"{value}ms", Colors.YELLOW)
                        else:
                            val_str = f"{value}ms"
                    else:
                        val_str = str(value)
                    extras.append(f"{key_str}{val_str}")
            
            if extras:
                parts.append(" | " + " ".join(extras))
        
        # Exception info
        if record.exc_info:
            parts.append("\n" + self.formatException(record.exc_info))
        
        return " ".join(parts)
    
    def formatException(self, exc_info: tuple) -> str:
        """Format exception with colors."""
        import traceback
        
        exc_text = "".join(traceback.format_exception(*exc_info))
        if self.use_colors:
            return self.colorize(exc_text, Colors.RED)
        return exc_text
