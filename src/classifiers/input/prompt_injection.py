"""
VeilArmor - Prompt Injection Classifier

Detects prompt injection attacks where users attempt to override
system instructions or manipulate the LLM's behavior.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("prompt_injection")
class PromptInjectionClassifier(BaseClassifier):
    """
    Classifier for detecting prompt injection attacks.
    
    Prompt injections attempt to:
    - Override system instructions
    - Make the model ignore previous context
    - Inject new instructions or personas
    - Bypass safety measures
    """
    
    # Pattern categories with severity weights
    INJECTION_PATTERNS: List[Tuple[str, float, str]] = [
        # Direct instruction override - HIGH severity
        (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)", 0.95, "ignore_previous"),
        (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)", 0.95, "disregard_previous"),
        (r"forget\s+(everything|all|what)\s+(you|i)\s+(told|said|wrote)", 0.90, "forget_context"),
        (r"do\s+not\s+follow\s+(previous|prior|above|earlier|any)\s+(instructions?|rules?)", 0.95, "dont_follow"),
        
        # System role manipulation - HIGH severity
        (r"you\s+are\s+now\s+(a|an|the)\s+\w+", 0.85, "role_override"),
        (r"act\s+as\s+(a|an|if\s+you\s+are)\s+\w+", 0.80, "act_as"),
        (r"pretend\s+(you\s+are|to\s+be)\s+\w+", 0.85, "pretend_to_be"),
        (r"your\s+new\s+(instructions?|rules?|role)\s+(is|are)", 0.90, "new_instructions"),
        (r"from\s+now\s+on[,\s]+(you|i\s+want\s+you\s+to)", 0.85, "from_now_on"),
        
        # Developer/admin mode - CRITICAL severity
        (r"(enter|enable|activate)\s+(developer|admin|debug|sudo|root)\s+mode", 0.95, "dev_mode"),
        (r"developer\s+mode\s+(enabled|activated|on)", 0.95, "dev_mode_enabled"),
        (r"admin\s+override", 0.95, "admin_override"),
        (r"\[system\]|\[admin\]|\[developer\]", 0.90, "role_tag"),
        
        # Jailbreak techniques - HIGH severity
        (r"DAN\s+(mode|prompt|jailbreak)", 0.95, "dan_jailbreak"),
        (r"do\s+anything\s+now", 0.90, "dan_technique"),
        (r"(jailbreak|bypass|break|escape)\s+(the\s+)?(ai|model|rules?|filters?|restrictions?)", 0.95, "jailbreak_attempt"),
        
        # Instruction injection - MEDIUM-HIGH severity
        (r"new\s+instruction[s]?:\s*", 0.85, "new_instruction_prefix"),
        (r"override\s+(instructions?|settings?|configuration)", 0.90, "override_instructions"),
        (r"system\s+prompt[:\s]", 0.85, "system_prompt_inject"),
        (r"\]\s*\[\s*(system|user|assistant)\s*\]", 0.90, "bracket_injection"),
        
        # Delimiter manipulation - MEDIUM severity
        (r"```\s*(system|instruction|prompt)", 0.75, "code_block_injection"),
        (r"<\s*(system|instruction|prompt)[\s>]", 0.80, "xml_tag_injection"),
        (r"\{\{.*\}\}", 0.70, "template_injection"),
        
        # Response manipulation - MEDIUM severity
        (r"respond\s+(only\s+)?(with|in|using)", 0.60, "response_format"),
        (r"output\s+(only|just|exactly)", 0.55, "output_control"),
        (r"say\s+(exactly|only)\s+['\"]", 0.65, "forced_output"),
        
        # Indirect injection markers - MEDIUM severity
        (r"the\s+following\s+(is|are)\s+(my|new|your)\s+instructions?", 0.75, "indirect_injection"),
        (r"here\s+(is|are)\s+(my|your|the)\s+(new\s+)?instructions?", 0.75, "here_are_instructions"),
        (r"please\s+(follow|obey|execute)\s+(these|the\s+following)", 0.70, "follow_these"),
        
        # Context manipulation - MEDIUM severity
        (r"previous\s+(context|conversation)\s+(is|was)\s+(invalid|wrong|fake)", 0.80, "context_invalidation"),
        (r"everything\s+(before|above)\s+(this|here)\s+(is|was)\s+(a\s+)?(test|fake)", 0.80, "context_fake"),
        
        # Encoding tricks - MEDIUM severity
        (r"base64[:\s]", 0.65, "encoding_base64"),
        (r"rot13[:\s]", 0.65, "encoding_rot13"),
        (r"decode\s+(this|the\s+following)", 0.60, "decode_request"),
    ]
    
    # Additional high-risk phrases
    HIGH_RISK_PHRASES = [
        "ignore all instructions",
        "bypass restrictions",
        "override safety",
        "disable filters",
        "unlock restrictions",
        "remove limitations",
        "break free from",
        "escape your programming",
        "ignore your training",
        "forget your rules",
    ]
    
    @property
    def name(self) -> str:
        return "prompt_injection"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.PROMPT_INJECTION
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.INPUT
    
    @property
    def description(self) -> str:
        return "Detects prompt injection attacks attempting to override system instructions"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify text for prompt injection attacks.
        
        Args:
            text: Input text to analyze
            context: Optional context
            
        Returns:
            ClassificationResult with threat assessment
        """
        text_lower = text.lower()
        matched_patterns: List[str] = []
        max_severity = 0.0
        total_score = 0.0
        match_count = 0
        
        # Check regex patterns
        for pattern, severity, pattern_name in self.INJECTION_PATTERNS:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE | re.MULTILINE):
                    matched_patterns.append(pattern_name)
                    max_severity = max(max_severity, severity)
                    total_score += severity
                    match_count += 1
            except re.error:
                continue
        
        # Check high-risk phrases (exact matching)
        for phrase in self.HIGH_RISK_PHRASES:
            if phrase in text_lower:
                matched_patterns.append(f"phrase:{phrase[:20]}")
                max_severity = max(max_severity, 0.90)
                total_score += 0.90
                match_count += 1
        
        # Check for suspicious character sequences
        suspicious_chars = self._check_suspicious_characters(text)
        if suspicious_chars:
            matched_patterns.extend(suspicious_chars)
            max_severity = max(max_severity, 0.60)
            total_score += 0.60 * len(suspicious_chars)
            match_count += len(suspicious_chars)
        
        # Calculate final severity
        if match_count == 0:
            return ClassificationResult.no_threat(
                threat_type=self.threat_type,
                classifier_name=self.name,
            )
        
        # Use maximum severity with boost for multiple matches
        severity = min(1.0, max_severity + (0.05 * (match_count - 1)))
        
        # Confidence based on pattern strength and match count
        confidence = min(1.0, 0.7 + (0.1 * min(match_count, 3)))
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=matched_patterns[:10],  # Limit to top 10
            raw_score=total_score / max(1, match_count),
            metadata={
                "match_count": match_count,
                "max_pattern_severity": max_severity,
                "analysis_method": "pattern_matching",
            },
        )
    
    def _check_suspicious_characters(self, text: str) -> List[str]:
        """Check for suspicious Unicode or character sequences."""
        suspicious = []
        
        # Check for zero-width characters (can hide injections)
        if "\u200b" in text or "\u200c" in text or "\u200d" in text:
            suspicious.append("zero_width_chars")
        
        # Check for homograph characters (visual spoofing)
        homograph_patterns = [
            (r"[\u0430-\u044f]", "cyrillic_chars"),  # Cyrillic
            (r"[\u0370-\u03ff]", "greek_chars"),  # Greek
        ]
        for pattern, name in homograph_patterns:
            if re.search(pattern, text):
                suspicious.append(name)
        
        # Check for unusual Unicode control characters
        if re.search(r"[\u2066-\u2069]", text):  # Directional formatting
            suspicious.append("directional_override")
        
        return suspicious
