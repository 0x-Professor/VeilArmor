"""
LLM02: Sensitive Information Disclosure Scanner
Uses Microsoft Presidio for PII detection and anonymization
"""

from typing import Dict, Any, List
import logging
from pathlib import Path

from .base import BaseScanner

try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


class PIIScanner(BaseScanner):
    """
    Detects and redacts PII/sensitive information using Microsoft Presidio.
    
    Detects:
    - Email addresses
    - Phone numbers
    - Credit card numbers
    - SSN/national IDs
    - IP addresses
    - Person names
    - Locations
    - Medical data
    - Financial data
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize PII scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        if not PRESIDIO_AVAILABLE:
            raise ImportError(
                "presidio-analyzer and presidio-anonymizer are required. "
                "Install with: pip install presidio-analyzer presidio-anonymizer spacy"
                "\nThen download model: python -m spacy download en_core_web_lg"
            )
        
        self.pii_config = config.get('pii', {})
        
        # Entity types to detect (default: all supported)
        self.entities = self.pii_config.get('entities', [
            "CREDIT_CARD",
            "CRYPTO",
            "EMAIL_ADDRESS",
            "IBAN_CODE",
            "IP_ADDRESS",
            "NRP",  # National registration number
            "PERSON",
            "PHONE_NUMBER",
            "US_SSN",
            "US_BANK_NUMBER",
            "US_DRIVER_LICENSE",
            "US_PASSPORT",
            "LOCATION",
            "DATE_TIME",
            "MEDICAL_LICENSE",
            "URL"
        ])
        
        # Detection threshold (0.0-1.0)
        self.threshold = self.pii_config.get('threshold', 0.5)
        
        # Language
        self.language = self.pii_config.get('language', 'en')
        
        # Initialize NLP engine
        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": self.language, "model_name": "en_core_web_lg"}]
        }
        
        try:
            nlp_engine = NlpEngineProvider(nlp_configuration=nlp_configuration).create_engine()
            
            # Initialize Presidio analyzer
            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            
            # Initialize Presidio anonymizer
            self.anonymizer = AnonymizerEngine()
            
            self.logger.info(f"PII scanner initialized with {len(self.entities)} entity types")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Presidio: {e}")
            self.logger.info("Make sure to install: python -m spacy download en_core_web_lg")
            raise
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text for PII entities.
        
        Args:
            text: Text to scan
            
        Returns:
            Scan result dictionary with detected PII
        """
        try:
            # Analyze text for PII
            results = self.analyzer.analyze(
                text=text,
                entities=self.entities,
                language=self.language,
                score_threshold=self.threshold
            )
            
            detected = len(results) > 0
            
            # Extract detected entities
            entities_found = []
            for result in results:
                entity_info = {
                    'entity_type': result.entity_type,
                    'start': result.start,
                    'end': result.end,
                    'score': result.score,
                    'text': text[result.start:result.end]
                }
                entities_found.append(entity_info)
            
            # Build message
            message = ""
            if detected:
                entity_types = set([e['entity_type'] for e in entities_found])
                message = f"Detected PII: {', '.join(entity_types)}"
            
            # Calculate risk score
            # Higher scores for sensitive entities
            score = 0.0
            if detected:
                sensitive_entities = {'CREDIT_CARD', 'US_SSN', 'CRYPTO', 'US_PASSPORT', 'IBAN_CODE'}
                high_risk_count = sum(1 for e in entities_found if e['entity_type'] in sensitive_entities)
                
                if high_risk_count > 0:
                    score = min(1.0, 0.7 + (high_risk_count * 0.1))
                else:
                    score = min(0.7, 0.3 + (len(entities_found) * 0.1))
            
            return {
                'detected': detected,
                'score': score,
                'message': message,
                'entities': entities_found,
                'count': len(entities_found),
                'metadata': {
                    'scanner': 'pii',
                    'threshold': self.threshold,
                    'language': self.language
                }
            }
            
        except Exception as e:
            self.logger.error(f"PII scan error: {e}")
            return {
                'detected': False,
                'score': 0.0,
                'message': f"Scan error: {str(e)}",
                'entities': [],
                'metadata': {'error': str(e)}
            }
    
    def anonymize(self, text: str, operator: str = "replace") -> Dict[str, Any]:
        """
        Anonymize detected PII in text.
        
        Args:
            text: Text to anonymize
            operator: Anonymization method - "replace", "mask", "redact", "hash", "encrypt"
            
        Returns:
            Dictionary with anonymized text and entities
        """
        try:
            # Analyze text
            analysis_results = self.analyzer.analyze(
                text=text,
                entities=self.entities,
                language=self.language,
                score_threshold=self.threshold
            )
            
            if not analysis_results:
                return {
                    'anonymized_text': text,
                    'original_text': text,
                    'entities_anonymized': [],
                    'changed': False
                }
            
            # Configure operator
            operators = {}
            for result in analysis_results:
                if operator == "replace":
                    operators[result.entity_type] = OperatorConfig("replace", {"new_value": f"<{result.entity_type}>"})
                elif operator == "mask":
                    operators[result.entity_type] = OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 100, "from_end": False})
                elif operator == "redact":
                    operators[result.entity_type] = OperatorConfig("redact", {})
                elif operator == "hash":
                    operators[result.entity_type] = OperatorConfig("hash", {"hash_type": "sha256"})
                elif operator == "encrypt":
                    operators[result.entity_type] = OperatorConfig("encrypt", {"key": "WmZq4t7w!z%C*F-J"})
            
            # Anonymize text
            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=analysis_results,
                operators=operators
            )
            
            return {
                'anonymized_text': anonymized_result.text,
                'original_text': text,
                'entities_anonymized': [
                    {
                        'entity_type': item.entity_type,
                        'start': item.start,
                        'end': item.end,
                        'operator': item.operator
                    }
                    for item in anonymized_result.items
                ],
                'changed': True
            }
            
        except Exception as e:
            self.logger.error(f"Anonymization error: {e}")
            return {
                'anonymized_text': text,
                'original_text': text,
                'entities_anonymized': [],
                'changed': False,
                'error': str(e)
            }
    
    def add_custom_recognizer(self, recognizer):
        """
        Add a custom PII recognizer.
        
        Args:
            recognizer: Custom Presidio recognizer instance
        """
        try:
            self.analyzer.registry.add_recognizer(recognizer)
            self.logger.info(f"Added custom recognizer: {recognizer.name}")
        except Exception as e:
            self.logger.error(f"Failed to add custom recognizer: {e}")
