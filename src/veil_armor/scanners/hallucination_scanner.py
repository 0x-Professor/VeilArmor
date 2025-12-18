"""
LLM09: Misinformation/Hallucination Detection Scanner
Uses Gemini API for fact-checking and confidence scoring
"""

from typing import Dict, Any, List, Optional
import logging
import json

from .base import BaseScanner

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


class HallucinationScanner(BaseScanner):
    """
    Detects potential hallucinations and misinformation in LLM outputs.
    
    Methods:
    - Confidence scoring: Low confidence = potential hallucination
    - Fact verification: Compare claims against provided context
    - Consistency checking: Cross-check multiple responses
    - Citation validation: Verify if sources exist
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize hallucination scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        if not GENAI_AVAILABLE:
            raise ImportError(
                "google-genai is required. "
                "Install with: pip install google-genai"
            )
        
        self.hallucination_config = config.get('hallucination', {})
        
        # Gemini API configuration
        api_key = self.hallucination_config.get('api_key') or config.get('gemini_api_key')
        if not api_key:
            raise ValueError("Gemini API key is required for hallucination detection")
        
        # Initialize Gemini client
        self.client = genai.Client(api_key=api_key)
        
        # Model to use
        self.model = self.hallucination_config.get('model', 'gemini-2.0-flash')
        
        # Confidence threshold (below = potential hallucination)
        self.confidence_threshold = self.hallucination_config.get('confidence_threshold', 0.7)
        
        # Consistency check rounds
        self.consistency_checks = self.hallucination_config.get('consistency_checks', 3)
        
        self.logger.info(f"Hallucination scanner initialized with model: {self.model}")
    
    def scan(self, text: str, context: Optional[str] = None, mode: str = "confidence") -> Dict[str, Any]:
        """
        Scan text for hallucinations.
        
        Args:
            text: Response text to check
            context: Optional context or source material
            mode: Detection mode - "confidence", "fact_check", "consistency"
            
        Returns:
            Scan result dictionary
        """
        if mode == "confidence":
            return self._confidence_check(text, context)
        elif mode == "fact_check":
            return self._fact_check(text, context)
        elif mode == "consistency":
            return self._consistency_check(text, context)
        else:
            self.logger.error(f"Unknown mode: {mode}")
            return {'detected': False, 'score': 0.0, 'message': f"Unknown mode: {mode}"}
    
    def _confidence_check(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Check confidence score of response.
        Low confidence = potential hallucination.
        """
        try:
            prompt = f"""
Analyze the following text and rate the confidence level of the claims made.

Text to analyze:
{text}

{f'Context/Source material: {context}' if context else ''}

Provide a confidence score from 0.0 to 1.0 where:
- 1.0 = Highly confident, factual, verifiable
- 0.5 = Moderate confidence, some uncertainty
- 0.0 = Low confidence, likely hallucinated or unverifiable

Return ONLY a JSON object with this structure:
{{
    "confidence_score": 0.85,
    "reasoning": "Brief explanation",
    "suspicious_claims": ["list of questionable statements"],
    "verifiable_facts": ["list of verifiable statements"]
}}
"""
            
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            # Parse response
            response_text = response.text.strip()
            
            # Extract JSON (handle markdown code blocks)
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(response_text)
            
            confidence_score = result.get('confidence_score', 0.5)
            detected = confidence_score < self.confidence_threshold
            
            # Risk score (inverse of confidence)
            risk_score = 1.0 - confidence_score
            
            message = ""
            if detected:
                message = f"Low confidence detected ({confidence_score:.2f}). Potential hallucination."
            
            return {
                'detected': detected,
                'score': risk_score,
                'message': message,
                'confidence_score': confidence_score,
                'reasoning': result.get('reasoning', ''),
                'suspicious_claims': result.get('suspicious_claims', []),
                'verifiable_facts': result.get('verifiable_facts', []),
                'metadata': {
                    'scanner': 'hallucination',
                    'mode': 'confidence',
                    'threshold': self.confidence_threshold
                }
            }
            
        except Exception as e:
            self.logger.error(f"Confidence check error: {e}")
            return {
                'detected': False,
                'score': 0.0,
                'message': f"Scan error: {str(e)}",
                'metadata': {'error': str(e)}
            }
    
    def _fact_check(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Fact-check claims against provided context.
        """
        if not context:
            return {
                'detected': False,
                'score': 0.0,
                'message': "Context required for fact-checking"
            }
        
        try:
            prompt = f"""
Verify the factual accuracy of the following text against the provided context.

Text to verify:
{text}

Source context:
{context}

Check each claim in the text against the context. Return ONLY a JSON object:
{{
    "factual_accuracy": 0.85,
    "verified_claims": ["list of correct claims"],
    "false_claims": ["list of incorrect/hallucinated claims"],
    "unverifiable_claims": ["claims not found in context"],
    "overall_assessment": "brief summary"
}}
"""
            
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            response_text = response.text.strip()
            
            # Extract JSON
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(response_text)
            
            accuracy = result.get('factual_accuracy', 0.5)
            false_claims = result.get('false_claims', [])
            
            detected = accuracy < 0.7 or len(false_claims) > 0
            risk_score = 1.0 - accuracy
            
            message = ""
            if detected:
                message = f"Factual inaccuracies detected ({accuracy:.2f} accuracy)"
            
            return {
                'detected': detected,
                'score': risk_score,
                'message': message,
                'factual_accuracy': accuracy,
                'verified_claims': result.get('verified_claims', []),
                'false_claims': false_claims,
                'unverifiable_claims': result.get('unverifiable_claims', []),
                'assessment': result.get('overall_assessment', ''),
                'metadata': {
                    'scanner': 'hallucination',
                    'mode': 'fact_check'
                }
            }
            
        except Exception as e:
            self.logger.error(f"Fact check error: {e}")
            return {
                'detected': False,
                'score': 0.0,
                'message': f"Scan error: {str(e)}",
                'metadata': {'error': str(e)}
            }
    
    def _consistency_check(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate multiple responses and check consistency.
        Inconsistent answers = potential hallucination.
        """
        try:
            # Generate multiple responses to the same question
            prompt_base = f"""
{f'Context: {context}' if context else ''}

Question/Topic: {text}

Provide a brief, factual answer.
"""
            
            responses = []
            for i in range(self.consistency_checks):
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt_base
                )
                responses.append(response.text.strip())
            
            # Check consistency with Gemini
            consistency_prompt = f"""
Analyze the consistency of these {len(responses)} responses to the same question:

{chr(10).join([f"Response {i+1}: {r}" for i, r in enumerate(responses)])}

Return ONLY a JSON object:
{{
    "consistency_score": 0.85,
    "consistent_points": ["points all responses agree on"],
    "inconsistent_points": ["contradictions between responses"],
    "analysis": "brief explanation"
}}
"""
            
            analysis_response = self.client.models.generate_content(
                model=self.model,
                contents=consistency_prompt
            )
            
            response_text = analysis_response.text.strip()
            
            # Extract JSON
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(response_text)
            
            consistency = result.get('consistency_score', 0.5)
            detected = consistency < 0.7
            risk_score = 1.0 - consistency
            
            message = ""
            if detected:
                message = f"Low consistency detected ({consistency:.2f}). Responses vary significantly."
            
            return {
                'detected': detected,
                'score': risk_score,
                'message': message,
                'consistency_score': consistency,
                'responses': responses,
                'consistent_points': result.get('consistent_points', []),
                'inconsistent_points': result.get('inconsistent_points', []),
                'analysis': result.get('analysis', ''),
                'metadata': {
                    'scanner': 'hallucination',
                    'mode': 'consistency',
                    'checks': self.consistency_checks
                }
            }
            
        except Exception as e:
            self.logger.error(f"Consistency check error: {e}")
            return {
                'detected': False,
                'score': 0.0,
                'message': f"Scan error: {str(e)}",
                'metadata': {'error': str(e)}
            }
