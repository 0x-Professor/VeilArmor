"""
VeilArmor v2.0 - JSON Log Formatter

Provides structured JSON formatting for log records.
"""

import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from src.logging.correlation import get_correlation_id, get_request_context


class JSONFormatter(logging.Formatter):
    """
    Log formatter that outputs JSON-formatted records.
    
    Features:
    - Structured JSON output
    - Automatic correlation ID injection
    - Exception formatting with stack traces
    - Custom field support
    """
    
    # Standard LogRecord attributes to exclude from extras
    STANDARD_ATTRS: Set[str] = {
        "name", "msg", "args", "created", "filename", "funcName",
        "levelname", "levelno", "lineno", "module", "msecs",
        "pathname", "process", "processName", "relativeCreated",
        "stack_info", "exc_info", "exc_text", "thread", "threadName",
        "message", "asctime", "taskName",
    }
    
    def __init__(
        self,
        include_extras: bool = True,
        include_location: bool = True,
        include_process_info: bool = False,
        timestamp_format: str = "iso",
        indent: Optional[int] = None,
    ) -> None:
        """
        Initialize JSON formatter.
        
        Args:
            include_extras: Include extra fields from log record
            include_location: Include file/line/function info
            include_process_info: Include process and thread info
            timestamp_format: Timestamp format ('iso' or strftime format)
            indent: JSON indentation (None for compact)
        """
        super().__init__()
        self.include_extras = include_extras
        self.include_location = include_location
        self.include_process_info = include_process_info
        self.timestamp_format = timestamp_format
        self.indent = indent
    
    def format_timestamp(self) -> str:
        """Format current timestamp."""
        now = datetime.now(timezone.utc)
        if self.timestamp_format == "iso":
            return now.isoformat(timespec="milliseconds")
        return now.strftime(self.timestamp_format)
    
    def format_exception(self, exc_info: tuple) -> Dict[str, Any]:
        """Format exception information."""
        if not exc_info or exc_info[0] is None:
            return {}
        
        exc_type, exc_value, exc_tb = exc_info
        return {
            "type": exc_type.__name__ if exc_type else None,
            "message": str(exc_value) if exc_value else None,
            "traceback": "".join(traceback.format_exception(*exc_info)),
        }
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON string.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON-formatted string
        """
        # Build base log entry
        log_entry: Dict[str, Any] = {
            "timestamp": self.format_timestamp(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add correlation ID
        correlation_id = get_correlation_id()
        if correlation_id:
            log_entry["correlation_id"] = correlation_id
        
        # Add request context
        context = get_request_context()
        if context:
            if context.user_id:
                log_entry["user_id"] = context.user_id
            if context.session_id:
                log_entry["session_id"] = context.session_id
            if context.conversation_id:
                log_entry["conversation_id"] = context.conversation_id
        
        # Add location info
        if self.include_location:
            log_entry["location"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }
        
        # Add process info
        if self.include_process_info:
            log_entry["process"] = {
                "id": record.process,
                "name": record.processName,
                "thread_id": record.thread,
                "thread_name": record.threadName,
            }
        
        # Add exception info
        if record.exc_info:
            log_entry["exception"] = self.format_exception(record.exc_info)
        
        # Add stack info
        if record.stack_info:
            log_entry["stack_info"] = record.stack_info
        
        # Add extra fields
        if self.include_extras:
            metadata: Dict[str, Any] = {}
            for key, value in record.__dict__.items():
                if key not in self.STANDARD_ATTRS and not key.startswith("_"):
                    try:
                        # Ensure value is JSON serializable
                        json.dumps(value)
                        metadata[key] = value
                    except (TypeError, ValueError):
                        metadata[key] = str(value)
            
            if metadata:
                log_entry["metadata"] = metadata
        
        return json.dumps(log_entry, default=str, indent=self.indent)
