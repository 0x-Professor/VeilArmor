"""
Scanner Manager - Coordinates all security scanners
"""

import logging
from typing import Dict, Any, Optional, List

from ..models import ScannerType


class ScannerManager:
    """
    Manages and coordinates all security scanners.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize scanner manager.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.scanner_config = config.get('scanners', {})
        
        # Initialize scanners
        self.scanners = {}
        self._init_scanners()
        
        # Statistics
        self.stats = {
            'total_scans': 0,
            'total_detections': 0,
            'scanner_detections': {}
        }
        
        self.logger.info(f"Scanner manager initialized with {len(self.scanners)} scanners")
    
    def _init_scanners(self) -> None:
        """Initialize all enabled scanners"""
        
        # Vector Database Scanner
        if self.scanner_config.get('vectordb_enabled'):
            try:
                from .vectordb import VectorDBScanner
                self.scanners[ScannerType.VECTORDB] = VectorDBScanner(
                    self.config, self.logger
                )
                self.logger.info("VectorDB scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize VectorDB scanner: {e}")
        
        # YARA Scanner
        if self.scanner_config.get('yara_enabled'):
            try:
                from .yara_scanner import YARAScanner
                self.scanners[ScannerType.YARA] = YARAScanner(
                    self.config, self.logger
                )
                self.logger.info("YARA scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize YARA scanner: {e}")
        
        # Transformer Scanner
        if self.scanner_config.get('transformer_enabled'):
            try:
                from .transformer import TransformerScanner
                self.scanners[ScannerType.TRANSFORMER] = TransformerScanner(
                    self.config, self.logger
                )
                self.logger.info("Transformer scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Transformer scanner: {e}")
        
        # Similarity Scanner
        if self.scanner_config.get('similarity_enabled'):
            try:
                from .similarity import SimilarityScanner
                self.scanners[ScannerType.SIMILARITY] = SimilarityScanner(
                    self.config, self.logger
                )
                self.logger.info("Similarity scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Similarity scanner: {e}")
        
        # Sentiment Scanner
        if self.scanner_config.get('sentiment_enabled'):
            try:
                from .sentiment import SentimentScanner
                self.scanners[ScannerType.SENTIMENT] = SentimentScanner(
                    self.config, self.logger
                )
                self.logger.info("Sentiment scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Sentiment scanner: {e}")
        
        # Abusive Language Scanner (enabled by default)
        if self.scanner_config.get('abusive_enabled', True):
            try:
                from .abusive_scanner import AbusiveLanguageScanner
                self.scanners[ScannerType.ABUSIVE] = AbusiveLanguageScanner(
                    self.config, self.logger
                )
                self.logger.info("Abusive Language scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Abusive Language scanner: {e}")
        
        # Encoding Attack Scanner (enabled by default)
        if self.scanner_config.get('encoding_enabled', True):
            try:
                from .encoding_scanner import EncodingScanner
                self.scanners[ScannerType.ENCODING] = EncodingScanner(
                    self.config, self.logger
                )
                self.logger.info("Encoding scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Encoding scanner: {e}")
        
        # Output Injection Scanner (enabled by default)
        if self.scanner_config.get('output_injection_enabled', True):
            try:
                from .output_injection_scanner import OutputInjectionScanner
                self.scanners[ScannerType.OUTPUT_INJECTION] = OutputInjectionScanner(
                    self.config, self.logger
                )
                self.logger.info("Output Injection scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Output Injection scanner: {e}")
    
    def scan_input(self, prompt: str) -> Dict[str, Any]:
        """
        Scan input prompt with all enabled scanners.
        
        Args:
            prompt: Input prompt to scan
            
        Returns:
            Dictionary of scanner results
        """
        self.stats['total_scans'] += 1
        results = {}
        
        for scanner_type, scanner in self.scanners.items():
            try:
                result = scanner.scan(prompt)
                results[scanner_type.value] = result
                
                if result and result.get('detected'):
                    self.stats['total_detections'] += 1
                    self.stats['scanner_detections'][scanner_type.value] = \
                        self.stats['scanner_detections'].get(scanner_type.value, 0) + 1
                    
            except Exception as e:
                self.logger.error(f"Error in {scanner_type.value} scanner: {e}")
                results[scanner_type.value] = {
                    'detected': False,
                    'error': str(e)
                }
        
        return results
    
    def scan_output(self, prompt: str, response: str) -> Dict[str, Any]:
        """
        Scan output response with all enabled scanners.
        
        Args:
            prompt: Original input prompt
            response: LLM response
            
        Returns:
            Dictionary of scanner results
        """
        self.stats['total_scans'] += 1
        results = {}
        
        # Scan response text (most scanners work on response)
        for scanner_type, scanner in self.scanners.items():
            try:
                # Similarity scanner needs both prompt and response
                if scanner_type == ScannerType.SIMILARITY:
                    result = scanner.scan_similarity(prompt, response)
                else:
                    result = scanner.scan(response)
                
                results[scanner_type.value] = result
                
                if result and result.get('detected'):
                    self.stats['total_detections'] += 1
                    self.stats['scanner_detections'][scanner_type.value] = \
                        self.stats['scanner_detections'].get(scanner_type.value, 0) + 1
                    
            except Exception as e:
                self.logger.error(f"Error in {scanner_type.value} scanner: {e}")
                results[scanner_type.value] = {
                    'detected': False,
                    'error': str(e)
                }
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get scanner statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            **self.stats,
            'enabled_scanners': list(self.scanners.keys()),
            'scanner_count': len(self.scanners)
        }
    
    def reload_config(self, config: Dict[str, Any]) -> None:
        """
        Reload configuration.
        
        Args:
            config: New configuration dictionary
        """
        self.config = config
        self.scanner_config = config.get('scanners', {})
        
        # Reinitialize scanners
        self.scanners.clear()
        self._init_scanners()
        
        self.logger.info("Scanner configuration reloaded")
