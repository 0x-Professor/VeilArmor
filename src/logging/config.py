"""
VeilArmor - Logging Configuration

Configures structured logging with multiple handlers, colored console output,
JSON file logging, and integration with correlation IDs.
"""

import logging
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import structlog
from structlog.types import Processor

from src.logging.correlation import get_correlation_id, get_request_context


class LogLevel(str, Enum):
    """Log level enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(str, Enum):
    """Log output format."""
    JSON = "json"
    CONSOLE = "console"
    TEXT = "text"


@dataclass
class LogConfig:
    """
    Logging configuration.
    
    Attributes:
        level: Minimum log level
        format: Output format (json, console, text)
        log_file: Path to log file (optional)
        json_log_file: Path to JSON log file (optional)
        enable_colors: Enable colored console output
        include_timestamp: Include timestamp in logs
        include_caller: Include caller info (file, line, function)
        log_dir: Directory for log files
        max_file_size_mb: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        component_levels: Per-component log levels
    """
    
    level: LogLevel = LogLevel.INFO
    format: LogFormat = LogFormat.CONSOLE
    log_file: Optional[str] = None
    json_log_file: Optional[str] = None
    enable_colors: bool = True
    include_timestamp: bool = True
    include_caller: bool = False
    log_dir: str = "logs"
    max_file_size_mb: int = 100
    backup_count: int = 5
    component_levels: Dict[str, LogLevel] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogConfig":
        """Create config from dictionary."""
        return cls(
            level=LogLevel(data.get("level", "INFO")),
            format=LogFormat(data.get("format", "console")),
            log_file=data.get("log_file"),
            json_log_file=data.get("json_log_file"),
            enable_colors=data.get("enable_colors", True),
            include_timestamp=data.get("include_timestamp", True),
            include_caller=data.get("include_caller", False),
            log_dir=data.get("log_dir", "logs"),
            max_file_size_mb=data.get("max_file_size_mb", 100),
            backup_count=data.get("backup_count", 5),
            component_levels={
                k: LogLevel(v) for k, v in data.get("component_levels", {}).items()
            }
        )


# ANSI color codes for console output
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
LEVEL_COLORS = {
    "DEBUG": Colors.DIM + Colors.CYAN,
    "INFO": Colors.GREEN,
    "WARNING": Colors.YELLOW,
    "ERROR": Colors.RED,
    "CRITICAL": Colors.BOLD + Colors.BG_RED + Colors.WHITE,
}

# Layer to color mapping
LAYER_COLORS = {
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


def add_correlation_id(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add correlation ID to log event."""
    if "correlation_id" not in event_dict:
        correlation_id = get_correlation_id()
        if correlation_id:
            event_dict["correlation_id"] = correlation_id
    return event_dict


def add_request_context(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add full request context to log event."""
    context = get_request_context()
    if context:
        if "user_id" not in event_dict and context.user_id:
            event_dict["user_id"] = context.user_id
        if "session_id" not in event_dict and context.session_id:
            event_dict["session_id"] = context.session_id
        if "conversation_id" not in event_dict and context.conversation_id:
            event_dict["conversation_id"] = context.conversation_id
    return event_dict


def colorize_log_level(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add color to log level for console output."""
    level = event_dict.get("level", "INFO").upper()
    color = LEVEL_COLORS.get(level, "")
    if color:
        event_dict["level"] = f"{color}{level}{Colors.RESET}"
    return event_dict


def colorize_layer(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add color to layer name for console output."""
    layer = event_dict.get("layer")
    if layer:
        color = LAYER_COLORS.get(layer, "")
        if color:
            event_dict["layer"] = f"{color}{layer}{Colors.RESET}"
    return event_dict


def format_timestamp(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Format timestamp with color."""
    timestamp = event_dict.get("timestamp")
    if timestamp:
        event_dict["timestamp"] = f"{Colors.DIM}{timestamp}{Colors.RESET}"
    return event_dict


class ColoredConsoleRenderer:
    """Custom console renderer with colors."""
    
    def __init__(self, colors: bool = True) -> None:
        self.colors = colors
    
    def __call__(
        self, logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
    ) -> str:
        """Render log event to colored string."""
        # Extract standard fields
        timestamp = event_dict.pop("timestamp", "")
        level = event_dict.pop("level", "INFO")
        event = event_dict.pop("event", "")
        logger_name = event_dict.pop("logger", "")
        correlation_id = event_dict.pop("correlation_id", "")
        layer = event_dict.pop("layer", "")
        component = event_dict.pop("component", "")
        
        # Build output parts
        parts = []
        
        if timestamp:
            if self.colors:
                parts.append(f"{Colors.DIM}{timestamp}{Colors.RESET}")
            else:
                parts.append(timestamp)
        
        # Level with color
        if self.colors:
            level_upper = level.upper() if not level.startswith("\033") else level
            if not level.startswith("\033"):
                color = LEVEL_COLORS.get(level_upper, "")
                parts.append(f"[{color}{level_upper:8}{Colors.RESET}]")
            else:
                parts.append(f"[{level:8}]")
        else:
            parts.append(f"[{level:8}]")
        
        # Correlation ID
        if correlation_id:
            if self.colors:
                parts.append(f"{Colors.DIM}[{correlation_id}]{Colors.RESET}")
            else:
                parts.append(f"[{correlation_id}]")
        
        # Layer with color
        if layer:
            if self.colors:
                layer_display = layer if layer.startswith("\033") else layer
                if not layer.startswith("\033"):
                    color = LAYER_COLORS.get(layer, "")
                    parts.append(f"{color}{layer}{Colors.RESET}")
                else:
                    parts.append(layer)
            else:
                parts.append(layer)
        
        # Component
        if component:
            if self.colors:
                parts.append(f"{Colors.CYAN}{component}{Colors.RESET}")
            else:
                parts.append(component)
        
        # Event message
        if self.colors:
            parts.append(f"{Colors.BOLD}{event}{Colors.RESET}")
        else:
            parts.append(event)
        
        # Remaining fields as key=value
        if event_dict:
            extras = []
            for key, value in event_dict.items():
                if key.startswith("_"):
                    continue
                if self.colors:
                    extras.append(f"{Colors.DIM}{key}={Colors.RESET}{value}")
                else:
                    extras.append(f"{key}={value}")
            if extras:
                parts.append(" ".join(extras))
        
        return " ".join(parts)


def configure_logging(
    config: Optional[Union[LogConfig, Dict[str, Any]]] = None,
    level: Optional[str] = None,
    format: Optional[str] = None,
    colors: bool = True,
) -> None:
    """
    Configure the logging system.
    
    Args:
        config: LogConfig object or dictionary with config values
        level: Override log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Override log format (json, console, text)
        colors: Enable/disable colored output
    """
    # Handle config
    if config is None:
        config = LogConfig()
    elif isinstance(config, dict):
        config = LogConfig.from_dict(config)
    
    # Apply overrides
    if level:
        config.level = LogLevel(level.upper())
    if format:
        config.format = LogFormat(format.lower())
    config.enable_colors = colors
    
    # Create log directory if needed
    if config.log_file or config.json_log_file:
        log_dir = Path(config.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
    
    # Build processor chain
    processors: List[Processor] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="ISO", utc=True),
        add_correlation_id,
        add_request_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]
    
    # Add format-specific processors
    if config.format == LogFormat.JSON:
        processors.append(structlog.processors.JSONRenderer())
    elif config.format == LogFormat.CONSOLE and config.enable_colors:
        processors.append(ColoredConsoleRenderer(colors=True))
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=False))
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, config.level.value),
    )
    
    # Configure file handlers if specified
    root_logger = logging.getLogger()
    
    if config.log_file:
        file_path = Path(config.log_dir) / config.log_file
        file_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=config.max_file_size_mb * 1024 * 1024,
            backupCount=config.backup_count,
        )
        file_handler.setLevel(getattr(logging, config.level.value))
        root_logger.addHandler(file_handler)
    
    if config.json_log_file:
        json_path = Path(config.log_dir) / config.json_log_file
        json_handler = logging.handlers.RotatingFileHandler(
            json_path,
            maxBytes=config.max_file_size_mb * 1024 * 1024,
            backupCount=config.backup_count,
        )
        json_handler.setLevel(getattr(logging, config.level.value))
        # JSON handler uses a JSON formatter
        from pythonjsonlogger import jsonlogger
        json_formatter = jsonlogger.JsonFormatter(
            "%(timestamp)s %(level)s %(name)s %(message)s"
        )
        json_handler.setFormatter(json_formatter)
        root_logger.addHandler(json_handler)
    
    # Set component-specific levels
    for component, component_level in config.component_levels.items():
        logging.getLogger(component).setLevel(
            getattr(logging, component_level.value)
        )


# Import handlers for RotatingFileHandler
import logging.handlers


def get_logger(name: str, layer: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    """
    Get a logger instance with optional layer context.
    
    Args:
        name: Logger name (usually __name__)
        layer: VeilArmor layer name for structured logging
        
    Returns:
        Configured structlog logger
    """
    logger = structlog.get_logger(name)
    if layer:
        logger = logger.bind(layer=layer)
    return logger


# Default configuration on import
def _default_configure() -> None:
    """Apply default logging configuration."""
    # Check environment for config
    log_level = os.environ.get("VEILARMOR_LOG_LEVEL", "INFO")
    log_format = os.environ.get("VEILARMOR_LOG_FORMAT", "console")
    colors = os.environ.get("VEILARMOR_LOG_COLORS", "true").lower() == "true"
    
    configure_logging(
        level=log_level,
        format=log_format,
        colors=colors,
    )


# Auto-configure with defaults
_default_configure()
