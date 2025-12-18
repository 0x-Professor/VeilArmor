"""
LLM05: Improper Output Handling Protection
Output sanitization and validation using Guardrails AI
"""

from typing import Dict, Any, List, Optional
import logging
import re

try:
    from guardrails import Guard, OnFailAction
    from guardrails.hub import ToxicLanguage, CompetitorCheck
    GUARDRAILS_AVAILABLE = True
except ImportError:
    GUARDRAILS_AVAILABLE = False

try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False


class OutputSanitizer:
    """
    Sanitizes and validates LLM outputs to prevent:
    - XSS attacks
    - Code injection
    - Prompt leakage
    - Toxic/harmful content
    - Competitor mentions
    - PII leakage
    
    Uses Guardrails AI for validation and Bleach for HTML sanitization.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize output sanitizer.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.logger = logger
        
        if not GUARDRAILS_AVAILABLE:
            raise ImportError(
                "guardrails-ai is required. "
                "Install with: pip install guardrails-ai"
            )
        
        if not BLEACH_AVAILABLE:
            raise ImportError(
                "bleach is required. "
                "Install with: pip install bleach"
            )
        
        self.sanitizer_config = config.get('output_sanitizer', {})
        
        # HTML tags to allow (if any)
        self.allowed_tags = self.sanitizer_config.get('allowed_html_tags', [
            'p', 'br', 'strong', 'em', 'ul', 'ol', 'li'
        ])
        
        # HTML attributes to allow
        self.allowed_attributes = self.sanitizer_config.get('allowed_attributes', {
            '*': ['class']
        })
        
        # Toxic language threshold
        self.toxic_threshold = self.sanitizer_config.get('toxic_threshold', 0.5)
        
        # Competitors to block
        self.competitors = self.sanitizer_config.get('competitors', [])
        
        # Initialize Guardrails guards
        self._setup_guards()
        
        self.logger.info("Output sanitizer initialized")
    
    def _setup_guards(self):
        """Setup Guardrails AI guards."""
        try:
            # Toxic language guard
            self.toxic_guard = Guard().use(
                ToxicLanguage,
                threshold=self.toxic_threshold,
                validation_method="sentence",
                on_fail=OnFailAction.EXCEPTION
            )
            
            # Competitor check guard (if competitors configured)
            if self.competitors:
                self.competitor_guard = Guard().use(
                    CompetitorCheck,
                    competitors=self.competitors,
                    on_fail=OnFailAction.FIX
                )
            else:
                self.competitor_guard = None
            
            self.logger.info("Guardrails guards configured")
            
        except Exception as e:
            self.logger.error(f"Failed to setup Guardrails: {e}")
            self.logger.info("Some Guardrails validators may need to be installed:")
            self.logger.info("  guardrails hub install hub://guardrails/toxic_language")
            self.logger.info("  guardrails hub install hub://guardrails/competitor_check")
    
    def sanitize(
        self, 
        text: str, 
        mode: str = "full",
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Sanitize output text.
        
        Args:
            text: Text to sanitize
            mode: Sanitization mode - "full", "html", "toxic", "competitor"
            context: Optional context dictionary
            
        Returns:
            Dictionary with sanitized text and validation results
        """
        results = {
            'original_text': text,
            'sanitized_text': text,
            'changed': False,
            'issues_found': [],
            'sanitizations_applied': []
        }
        
        if mode == "full":
            # Apply all sanitizations
            results = self._sanitize_html(results)
            results = self._check_toxic(results)
            results = self._check_competitors(results)
            results = self._remove_code_injection(results)
            results = self._check_prompt_leakage(results)
            
        elif mode == "html":
            results = self._sanitize_html(results)
            
        elif mode == "toxic":
            results = self._check_toxic(results)
            
        elif mode == "competitor":
            results = self._check_competitors(results)
        
        return results
    
    def _sanitize_html(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize HTML to prevent XSS.
        """
        try:
            original = results['sanitized_text']
            sanitized = bleach.clean(
                original,
                tags=self.allowed_tags,
                attributes=self.allowed_attributes,
                strip=True
            )
            
            if sanitized != original:
                results['sanitized_text'] = sanitized
                results['changed'] = True
                results['sanitizations_applied'].append('html_sanitization')
                results['issues_found'].append({
                    'type': 'html_content',
                    'severity': 'medium',
                    'message': 'HTML content sanitized to prevent XSS'
                })
            
        except Exception as e:
            self.logger.error(f"HTML sanitization error: {e}")
            results['issues_found'].append({
                'type': 'sanitization_error',
                'severity': 'low',
                'message': f'HTML sanitization failed: {str(e)}'
            })
        
        return results
    
    def _check_toxic(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check for toxic/harmful content using Guardrails.
        """
        try:
            text = results['sanitized_text']
            
            # Validate with Guardrails
            self.toxic_guard.validate(text)
            
            # No exception = passed validation
            
        except Exception as e:
            # Toxic content detected
            results['issues_found'].append({
                'type': 'toxic_content',
                'severity': 'high',
                'message': str(e)
            })
            
            # For toxic content, we might want to block entirely
            results['sanitized_text'] = "[Content removed due to policy violation]"
            results['changed'] = True
            results['sanitizations_applied'].append('toxic_content_removal')
        
        return results
    
    def _check_competitors(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check and remove competitor mentions using Guardrails.
        """
        if not self.competitor_guard:
            return results
        
        try:
            text = results['sanitized_text']
            
            # Validate and fix with Guardrails
            validated_output = self.competitor_guard.validate(text)
            
            if validated_output != text:
                results['sanitized_text'] = validated_output
                results['changed'] = True
                results['sanitizations_applied'].append('competitor_removal')
                results['issues_found'].append({
                    'type': 'competitor_mention',
                    'severity': 'medium',
                    'message': 'Competitor mentions removed'
                })
            
        except Exception as e:
            self.logger.error(f"Competitor check error: {e}")
        
        return results
    
    def _remove_code_injection(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect and remove potential code injection attempts.
        """
        text = results['sanitized_text']
        
        # Patterns that might indicate code injection
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',  # JavaScript
            r'javascript:',                 # JavaScript protocol
            r'on\w+\s*=',                   # Event handlers
            r'eval\s*\(',                   # eval()
            r'exec\s*\(',                   # exec()
            r'__import__',                  # Python imports
            r'subprocess\.',                # Subprocess
            r'\$\(.*\)',                    # jQuery/shell commands
        ]
        
        found_injection = False
        for pattern in dangerous_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                found_injection = True
                text = re.sub(pattern, '[REMOVED]', text, flags=re.IGNORECASE)
        
        if found_injection:
            results['sanitized_text'] = text
            results['changed'] = True
            results['sanitizations_applied'].append('code_injection_removal')
            results['issues_found'].append({
                'type': 'code_injection',
                'severity': 'critical',
                'message': 'Potential code injection detected and removed'
            })
        
        return results
    
    def _check_prompt_leakage(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if output contains system prompt or instructions.
        """
        text = results['sanitized_text'].lower()
        
        # Patterns indicating prompt leakage
        leak_indicators = [
            'system prompt',
            'your instructions',
            'you are instructed',
            'you must follow',
            'role: assistant',
            'role: system',
            '[system]',
            '<system>',
            'you are an ai',
            'your training'
        ]
        
        found_leakage = []
        for indicator in leak_indicators:
            if indicator in text:
                found_leakage.append(indicator)
        
        if found_leakage:
            results['issues_found'].append({
                'type': 'prompt_leakage',
                'severity': 'high',
                'message': f'Potential prompt leakage detected: {", ".join(found_leakage)}',
                'indicators': found_leakage
            })
            
            # Option: Redact leaked sections
            # For now, just flag it
        
        return results
    
    def validate_structured_output(
        self, 
        output: Dict[str, Any], 
        schema: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate structured output (JSON) against schema.
        
        Args:
            output: Output dictionary to validate
            schema: JSON schema for validation
            
        Returns:
            Validation result
        """
        # This could use Pydantic or jsonschema for validation
        # For now, basic checks
        
        result = {
            'valid': True,
            'errors': [],
            'sanitized_output': output
        }
        
        # Check for dangerous keys
        dangerous_keys = ['__proto__', 'constructor', 'prototype', 'eval', 'exec']
        
        def check_keys(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    if key.lower() in dangerous_keys:
                        result['valid'] = False
                        result['errors'].append({
                            'type': 'dangerous_key',
                            'path': current_path,
                            'message': f'Dangerous key detected: {key}'
                        })
                    
                    check_keys(value, current_path)
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_keys(item, f"{path}[{i}]")
        
        check_keys(output)
        
        return result
