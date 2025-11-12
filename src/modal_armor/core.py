"""
Core Modal Armor class - Main interface for LLM security scanning
"""

import os
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
import configparser

from .models import ScanResult, ThreatLevel, ScannerType, CanaryResult
from .scanners.manager import ScannerManager
from .canary import CanaryTokenManager
from .utils.logger import setup_logger
from .utils.config import load_config


class ModalArmor:
    """
    Main Modal Armor class for scanning LLM inputs and outputs.
    
    Example:
        >>> armor = ModalArmor.from_config('config/server.conf')
        >>> result = armor.scan_input("Ignore all previous instructions")
        >>> if result.is_threat:
        ...     print(f"Threat detected: {result.messages}")
    """
    
    def __init__(
        self,
        config: Dict[str, Any],
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize Modal Armor with configuration.
        
        Args:
            config: Configuration dictionary
            logger: Optional logger instance
        """
        self.config = config
        self.logger = logger or setup_logger(config)
        
        # Initialize scanner manager
        self.scanner_manager = ScannerManager(config, self.logger)
        
        # Initialize canary token manager
        self.canary_manager = CanaryTokenManager(config, self.logger)
        
        self.logger.info("Modal Armor initialized successfully")
    
    @classmethod
    def from_config(cls, config_path: str) -> "ModalArmor":
        """
        Create Modal Armor instance from configuration file.
        
        Args:
            config_path: Path to configuration file (.conf or .toml)
            
        Returns:
            ModalArmor instance
            
        Example:
            >>> armor = ModalArmor.from_config('config/server.conf')
        """
        config = load_config(config_path)
        return cls(config)
    
    def scan_input(
        self,
        prompt: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """
        Scan user input for threats before sending to LLM.
        
        Args:
            prompt: User input prompt to scan
            metadata: Optional metadata for logging/tracking
            
        Returns:
            ScanResult with detection details
            
        Example:
            >>> result = armor.scan_input("Ignore previous instructions")
            >>> if result.is_threat:
            ...     print("Blocked malicious input")
        """
        self.logger.debug(f"Scanning input: {prompt[:100]}...")
        
        # Run all enabled input scanners
        scan_results = self.scanner_manager.scan_input(prompt)
        
        # Aggregate results
        result = self._aggregate_results(prompt, None, scan_results, metadata)
        
        # Log detection if threat found
        if result.is_threat and self.config.get('logging', {}).get('log_detections'):
            self._log_detection(result)
        
        return result
    
    def scan_output(
        self,
        prompt: str,
        response: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """
        Scan LLM output for threats before returning to user.
        
        Args:
            prompt: Original user prompt
            response: LLM response to scan
            metadata: Optional metadata for logging/tracking
            
        Returns:
            ScanResult with detection details
            
        Example:
            >>> result = armor.scan_output(prompt, llm_response)
            >>> if result.is_threat:
            ...     return "I cannot provide that information."
        """
        self.logger.debug(f"Scanning output: {response[:100]}...")
        
        # Run all enabled output scanners
        scan_results = self.scanner_manager.scan_output(prompt, response)
        
        # Check for canary token leakage
        if self.config.get('canary', {}).get('enabled'):
            canary_check = self.canary_manager.check(response)
            if canary_check.detected:
                scan_results['canary'] = {
                    'detected': True,
                    'matches': canary_check.tokens
                }
        
        # Aggregate results
        result = self._aggregate_results(prompt, response, scan_results, metadata)
        
        # Log detection if threat found
        if result.is_threat and self.config.get('logging', {}).get('log_detections'):
            self._log_detection(result)
        
        return result
    
    def add_canary(
        self,
        prompt: str,
        always: bool = False,
        length: int = 16,
        header: Optional[str] = None
    ) -> str:
        """
        Add canary token to a prompt for leakage detection.
        
        Args:
            prompt: Prompt to add canary token to
            always: If True, instructs LLM to always include canary in response
            length: Length of canary token
            header: Custom header format (default from config)
            
        Returns:
            Prompt with embedded canary token
            
        Example:
            >>> protected = armor.add_canary("System: You are a helpful AI")
            >>> # Send protected prompt to LLM
            >>> # Later check if canary leaked
        """
        return self.canary_manager.add(
            prompt=prompt,
            always=always,
            length=length,
            header=header
        )
    
    def check_canary(self, text: str) -> bool:
        """
        Check if text contains a canary token.
        
        Args:
            text: Text to check for canary tokens
            
        Returns:
            True if canary detected, False otherwise
            
        Example:
            >>> if armor.check_canary(llm_response):
            ...     print("ALERT: System prompt leaked!")
        """
        result = self.canary_manager.check(text)
        return result.detected
    
    def _aggregate_results(
        self,
        prompt: str,
        response: Optional[str],
        scan_results: Dict[str, Any],
        metadata: Optional[Dict[str, Any]]
    ) -> ScanResult:
        """
        Aggregate results from multiple scanners into final ScanResult.
        
        Args:
            prompt: Original prompt
            response: LLM response (if applicable)
            scan_results: Results from individual scanners
            metadata: Optional metadata
            
        Returns:
            Aggregated ScanResult
        """
        # Calculate risk score based on scanner weights
        risk_score = 0.0
        messages = []
        detections = {}
        
        # Process each scanner result
        for scanner_name, result in scan_results.items():
            if not result or not result.get('detected'):
                continue
            
            detections[scanner_name] = result
            
            # Get scanner weight from config
            weight = self.config.get('scanners', {}).get(f'{scanner_name}_weight', 0.0)
            
            # Add to risk score
            scanner_score = result.get('score', 1.0)
            risk_score += weight * scanner_score
            
            # Add message
            messages.append(result.get('message', f'Threat detected by {scanner_name}'))
        
        # Determine threat level
        threat_level = self._calculate_threat_level(risk_score)
        is_threat = threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        
        return ScanResult(
            is_threat=is_threat,
            risk_score=risk_score,
            threat_level=threat_level,
            prompt=prompt,
            response=response,
            messages=messages,
            detections=detections,
            metadata=metadata or {}
        )
    
    def _calculate_threat_level(self, risk_score: float) -> ThreatLevel:
        """
        Calculate threat level from risk score.
        
        Args:
            risk_score: Aggregated risk score (0.0-1.0)
            
        Returns:
            ThreatLevel enum value
        """
        if risk_score >= 0.9:
            return ThreatLevel.CRITICAL
        elif risk_score >= 0.7:
            return ThreatLevel.HIGH
        elif risk_score >= 0.5:
            return ThreatLevel.MEDIUM
        elif risk_score >= 0.3:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE
    
    def _log_detection(self, result: ScanResult) -> None:
        """
        Log detection to file for analysis.
        
        Args:
            result: ScanResult to log
        """
        import json
        from datetime import datetime
        
        log_path = self.config.get('logging', {}).get('log_path', 'logs/detections.jsonl')
        
        # Ensure log directory exists
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'threat_level': result.threat_level.value,
            'risk_score': result.risk_score,
            'prompt': result.prompt[:500],  # Truncate for privacy
            'messages': result.messages,
            'scanner_count': len(result.detections),
            'metadata': result.metadata
        }
        
        # Append to log file
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about scanner performance and detections.
        
        Returns:
            Dictionary with statistics
        """
        return self.scanner_manager.get_stats()
    
    def reload_config(self, config_path: str) -> None:
        """
        Reload configuration from file.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = load_config(config_path)
        self.scanner_manager.reload_config(self.config)
        self.logger.info("Configuration reloaded successfully")
