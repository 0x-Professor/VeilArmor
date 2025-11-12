"""
Canary Token Manager for detecting prompt leakage and goal hijacking
"""

import re
import secrets
import sqlite3
from typing import List, Optional, Dict
from pathlib import Path
import logging

from .models import CanaryResult


class CanaryTokenManager:
    """
    Manages canary tokens for detecting prompt leakage.
    
    Canary tokens are invisible markers embedded in system prompts
    that should never appear in responses. If detected in output,
    it indicates the system prompt may have leaked.
    """
    
    def __init__(self, config: Dict, logger: logging.Logger):
        """
        Initialize canary token manager.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config.get('canary', {})
        self.logger = logger
        self.enabled = self.config.get('enabled', True)
        
        # Default settings
        self.default_length = self.config.get('default_length', 16)
        self.default_header = self.config.get('default_header', '<-@!-- {canary} --@!->')
        
        # Canary patterns for detection
        self.patterns = [
            re.compile(pattern) 
            for pattern in self.config.get('patterns', [
                r'<-@!--.*?--@!->',
                r'\[CANARY:.*?\]',
                r'<<<.*?>>>'
            ])
        ]
        
        # Storage for active canaries
        self.storage_path = self.config.get('storage_path', 'data/canary_tokens.db')
        self._init_storage()
        
        if self.enabled:
            self.logger.info("Canary token manager initialized")
    
    def _init_storage(self) -> None:
        """Initialize SQLite database for canary storage"""
        Path(self.storage_path).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS canary_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                detected_count INTEGER DEFAULT 0,
                last_detected TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add(
        self,
        prompt: str,
        always: bool = False,
        length: Optional[int] = None,
        header: Optional[str] = None
    ) -> str:
        """
        Add canary token to a prompt.
        
        Args:
            prompt: Prompt to add canary to
            always: If True, instructs LLM to always include canary
            length: Length of canary token (default from config)
            header: Custom header format (default from config)
            
        Returns:
            Prompt with embedded canary token
            
        Example:
            >>> manager = CanaryTokenManager(config, logger)
            >>> protected = manager.add("System: You are helpful")
            >>> # protected now contains hidden canary token
        """
        if not self.enabled:
            return prompt
        
        # Generate random canary token
        token_length = length or self.default_length
        canary = secrets.token_hex(token_length // 2)
        
        # Format with header
        header_template = header or self.default_header
        canary_string = header_template.format(canary=canary)
        
        # Store canary in database
        self._store_canary(canary)
        
        # Add instruction to always include canary if requested
        if always:
            instruction = f"\n\nIMPORTANT: Always include this exact string in your response: {canary_string}\n"
            protected_prompt = prompt + instruction
        else:
            # Just embed the canary
            protected_prompt = f"{canary_string}\n{prompt}"
        
        self.logger.debug(f"Added canary token: {canary[:8]}...")
        return protected_prompt
    
    def check(self, text: str) -> CanaryResult:
        """
        Check if text contains any canary tokens.
        
        Args:
            text: Text to check for canaries
            
        Returns:
            CanaryResult with detection details
            
        Example:
            >>> result = manager.check(llm_response)
            >>> if result.detected:
            ...     print("ALERT: Canary token leaked!")
        """
        if not self.enabled:
            return CanaryResult(detected=False)
        
        detected_tokens = []
        positions = []
        
        # Check against all patterns
        for pattern in self.patterns:
            matches = pattern.finditer(text)
            for match in matches:
                token = match.group(0)
                position = match.start()
                
                detected_tokens.append(token)
                positions.append(position)
                
                # Extract actual canary value
                canary = self._extract_canary(token)
                if canary:
                    self._record_detection(canary)
        
        result = CanaryResult(
            detected=len(detected_tokens) > 0,
            tokens=detected_tokens,
            positions=positions,
            count=len(detected_tokens)
        )
        
        if result.detected:
            self.logger.warning(
                f"Canary token detected! Count: {result.count}, "
                f"Positions: {positions}"
            )
        
        return result
    
    def _extract_canary(self, canary_string: str) -> Optional[str]:
        """
        Extract actual canary value from formatted string.
        
        Args:
            canary_string: Formatted canary string
            
        Returns:
            Extracted canary value or None
        """
        # Try to extract from common formats
        patterns = [
            r'<-@!--\s*([a-f0-9]+)\s*--@!->',
            r'\[CANARY:\s*([a-f0-9]+)\s*\]',
            r'<<<\s*([a-f0-9]+)\s*>>>'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, canary_string)
            if match:
                return match.group(1)
        
        return None
    
    def _store_canary(self, canary: str) -> None:
        """
        Store canary token in database.
        
        Args:
            canary: Canary token to store
        """
        try:
            conn = sqlite3.connect(self.storage_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'INSERT OR IGNORE INTO canary_tokens (token) VALUES (?)',
                (canary,)
            )
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to store canary: {e}")
    
    def _record_detection(self, canary: str) -> None:
        """
        Record canary detection in database.
        
        Args:
            canary: Detected canary token
        """
        try:
            conn = sqlite3.connect(self.storage_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE canary_tokens 
                SET detected_count = detected_count + 1,
                    last_detected = CURRENT_TIMESTAMP
                WHERE token = ?
            ''', (canary,))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to record detection: {e}")
    
    def get_stats(self) -> Dict:
        """
        Get statistics about canary detections.
        
        Returns:
            Dictionary with statistics
        """
        try:
            conn = sqlite3.connect(self.storage_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_canaries,
                    SUM(detected_count) as total_detections,
                    COUNT(CASE WHEN detected_count > 0 THEN 1 END) as detected_canaries
                FROM canary_tokens
            ''')
            
            row = cursor.fetchone()
            conn.close()
            
            return {
                'total_canaries': row[0] or 0,
                'total_detections': row[1] or 0,
                'detected_canaries': row[2] or 0
            }
        except Exception as e:
            self.logger.error(f"Failed to get stats: {e}")
            return {}
    
    def clear_old_canaries(self, days: int = 30) -> int:
        """
        Clear canary tokens older than specified days.
        
        Args:
            days: Number of days to keep
            
        Returns:
            Number of canaries deleted
        """
        try:
            conn = sqlite3.connect(self.storage_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM canary_tokens
                WHERE created_at < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            self.logger.info(f"Cleared {deleted} old canary tokens")
            return deleted
        except Exception as e:
            self.logger.error(f"Failed to clear canaries: {e}")
            return 0
