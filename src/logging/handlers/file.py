"""
VeilArmor - File Logging Handler

Provides file-based logging with rotation support.
"""

import logging
import os
from logging.handlers import RotatingFileHandler as BaseRotatingFileHandler
from pathlib import Path
from typing import Optional


class FileHandler(logging.FileHandler):
    """
    Enhanced file handler with automatic directory creation.
    """
    
    def __init__(
        self,
        filename: str,
        mode: str = "a",
        encoding: Optional[str] = "utf-8",
        delay: bool = False,
        create_dirs: bool = True,
    ) -> None:
        """
        Initialize file handler.
        
        Args:
            filename: Path to log file
            mode: File open mode
            encoding: File encoding
            delay: Delay file opening until first write
            create_dirs: Create parent directories if they don't exist
        """
        if create_dirs:
            log_dir = Path(filename).parent
            log_dir.mkdir(parents=True, exist_ok=True)
        
        super().__init__(filename, mode=mode, encoding=encoding, delay=delay)


class RotatingFileHandler(BaseRotatingFileHandler):
    """
    Enhanced rotating file handler with automatic directory creation.
    """
    
    def __init__(
        self,
        filename: str,
        mode: str = "a",
        max_bytes: int = 100 * 1024 * 1024,  # 100 MB default
        backup_count: int = 5,
        encoding: Optional[str] = "utf-8",
        delay: bool = False,
        create_dirs: bool = True,
    ) -> None:
        """
        Initialize rotating file handler.
        
        Args:
            filename: Path to log file
            mode: File open mode
            max_bytes: Maximum file size before rotation
            backup_count: Number of backup files to keep
            encoding: File encoding
            delay: Delay file opening until first write
            create_dirs: Create parent directories if they don't exist
        """
        if create_dirs:
            log_dir = Path(filename).parent
            log_dir.mkdir(parents=True, exist_ok=True)
        
        super().__init__(
            filename,
            mode=mode,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding=encoding,
            delay=delay,
        )
