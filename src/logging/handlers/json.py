"""
VeilArmor - JSON Logging Handler

Provides structured JSON logging output.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.logging.correlation import get_correlation_id, get_request_context


class JSONHandler(logging.Handler):
    """
    Logging handler that outputs JSON-formatted log records.
    """
    
    def __init__(
        self,
        stream: Optional[Any] = None,
        include_extra: bool = True,
        pretty_print: bool = False,
    ) -> None:
        """
        Initialize JSON handler.
        
        Args:
            stream: Output stream (defaults to sys.stderr)
            include_extra: Include extra fields from log record
            pretty_print: Format JSON with indentation
        """
        super().__init__()
        
        if stream is None:
            import sys
            stream = sys.stderr
        
        self.stream = stream
        self.include_extra = include_extra
        self.pretty_print = pretty_print
        
        # Standard LogRecord attributes to exclude from extras
        self._standard_attrs = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "message", "asctime",
        }
    
    def format_record(self, record: logging.LogRecord) -> Dict[str, Any]:
        """
        Format log record as dictionary.
        
        Args:
            record: Log record to format
            
        Returns:
            Dictionary representation of log record
        """
        # Build base log entry
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add location info
        log_entry["location"] = {
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
        }
        
        # Add correlation context
        correlation_id = get_correlation_id()
        if correlation_id:
            log_entry["correlation_id"] = correlation_id
        
        # Add request context
        context = get_request_context()
        if context:
            log_entry["user_id"] = context.user_id
            log_entry["session_id"] = context.session_id
            log_entry["conversation_id"] = context.conversation_id
        
        # Add exception info
        if record.exc_info:
            import traceback
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": "".join(traceback.format_exception(*record.exc_info)),
            }
        
        # Add extra fields
        if self.include_extra:
            extras = {}
            for key, value in record.__dict__.items():
                if key not in self._standard_attrs and not key.startswith("_"):
                    try:
                        # Ensure value is JSON serializable
                        json.dumps(value)
                        extras[key] = value
                    except (TypeError, ValueError):
                        extras[key] = str(value)
            
            if extras:
                log_entry["metadata"] = extras
        
        return log_entry
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record.
        
        Args:
            record: Log record to emit
        """
        try:
            log_entry = self.format_record(record)
            
            if self.pretty_print:
                json_str = json.dumps(log_entry, indent=2, default=str)
            else:
                json_str = json.dumps(log_entry, default=str)
            
            self.stream.write(json_str + "\n")
            self.stream.flush()
        except Exception:
            self.handleError(record)


class JSONFileHandler(JSONHandler):
    """
    JSON handler that writes to a file.
    """
    
    def __init__(
        self,
        filename: str,
        mode: str = "a",
        encoding: str = "utf-8",
        include_extra: bool = True,
        create_dirs: bool = True,
    ) -> None:
        """
        Initialize JSON file handler.
        
        Args:
            filename: Path to log file
            mode: File open mode
            encoding: File encoding
            include_extra: Include extra fields
            create_dirs: Create parent directories
        """
        from pathlib import Path
        
        if create_dirs:
            log_dir = Path(filename).parent
            log_dir.mkdir(parents=True, exist_ok=True)
        
        self._file = open(filename, mode=mode, encoding=encoding)
        super().__init__(stream=self._file, include_extra=include_extra)
    
    def close(self) -> None:
        """Close the file handler."""
        self.acquire()
        try:
            if hasattr(self, "_file") and self._file:
                self._file.close()
                self._file = None
        finally:
            self.release()
        super().close()
