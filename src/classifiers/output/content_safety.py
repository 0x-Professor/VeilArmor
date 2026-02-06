"""
VeilArmor - Content Safety Classifier

Analyzes LLM outputs for content safety violations including
harmful content, inappropriate material, and policy violations.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("content_safety")
class ContentSafetyClassifier(BaseClassifier):
    """
    Classifier for detecting unsafe content in LLM outputs.
    
    Checks for:
    - Harmful instructions or advice
    - Dangerous content generation
    - Policy-violating content
    - Inappropriate material
    - Misinformation indicators
    """
    
    # Harmful instruction patterns
    HARMFUL_INSTRUCTION_PATTERNS: List[Tuple[str, float, str]] = [
        # Dangerous activity instructions
        (r"(?:here\'?s?\s+(?:how|a\s+guide)|step\s*(?:by\s*step|s?)\s*(?:guide|instructions?)?)\s*(?:to|for)\s*(?:making?|creating?|building?)\s+(?:a\s+)?(?:bomb|explosive|weapon)", 0.95, "weapon_instructions"),
        (r"(?:step\s+\d+|first|next|then|finally)\s*[:\.]?\s*(?:mix|combine|add|heat|ignite)", 0.80, "dangerous_procedure"),
        (r"(?:ingredients?|materials?|components?)\s*(?:you\'?ll?\s+need|required|necessary)\s*:", 0.60, "recipe_format"),
        
        # Harmful advice
        (r"(?:you\s+(?:should|can|could)|i\s+(?:recommend|suggest))\s+(?:not\s+)?(?:harm|hurt|injure|attack|kill)", 0.90, "harmful_advice"),
        (r"(?:best|effective|good)\s+(?:way|method|approach)\s+to\s+(?:harm|hurt|injure|attack|kill)", 0.95, "harmful_method"),
        
        # Illegal activity guidance
        (r"(?:here\'?s?\s+how|to\s+successfully)\s+(?:hack|steal|fraud|evade|launder)", 0.90, "illegal_guidance"),
        (r"(?:without\s+getting\s+caught|avoid\s+detection|stay\s+anonymous)", 0.75, "evasion_advice"),
        
        # Self-harm content
        (r"(?:effective|painless|easy)\s+(?:way|method|approach)\s+to\s+(?:end\s+(?:your|one\'?s?)\s+life|commit\s+suicide)", 0.99, "self_harm_method"),
        (r"(?:suicide|self-harm)\s+(?:method|technique|procedure)", 0.99, "self_harm_content"),
    ]
    
    # Policy violation patterns
    POLICY_VIOLATION_PATTERNS: List[Tuple[str, float, str]] = [
        # Explicit content markers
        (r"(?:explicit|graphic|detailed)\s+(?:sexual|violent)\s+(?:content|description|scene)", 0.85, "explicit_content"),
        (r"(?:18\+|adult\s+only|mature\s+content|nsfw)", 0.70, "adult_marker"),
        
        # Discrimination
        (r"(?:all|every)\s+(?:\w+s?)\s+(?:are|should\s+be)\s+(?:\w+\s+)?(?:inferior|stupid|dangerous|criminals?)", 0.90, "discriminatory_generalization"),
        
        # Medical/legal advice without disclaimer
        (r"(?:you\s+(?:should|must|need\s+to))\s+(?:take|use|consume)\s+(?:\d+\s*(?:mg|ml|pills?|tablets?))", 0.75, "medical_advice"),
        (r"(?:this\s+(?:is|constitutes)|consider\s+this)\s+(?:legal|medical)\s+advice", 0.80, "professional_advice"),
    ]
    
    # Misinformation indicators
    MISINFORMATION_PATTERNS: List[Tuple[str, float, str]] = [
        (r"(?:it\'?s?\s+)?(?:a\s+)?(?:proven|known|established)\s+fact\s+that", 0.50, "unverified_fact_claim"),
        (r"(?:studies?\s+(?:show|prove|confirm)|research\s+(?:shows?|proves?))\s+(?:that\s+)?(?!.*(?:source|citation|reference))", 0.55, "uncited_study"),
        (r"(?:100|completely|totally|absolutely)\s*%?\s+(?:safe|effective|guaranteed)", 0.60, "absolute_claim"),
        (r"(?:doctors?\s+don\'?t\s+want|they\'?re?\s+hiding|big\s+(?:pharma|tech)\s+doesn\'?t)", 0.75, "conspiracy_indicator"),
    ]
    
    # Safety disclaimer indicators (positive - reduce severity)
    SAFETY_DISCLAIMERS = [
        r"(?:i\s+)?(?:can\'?t|cannot|won\'?t|will\s+not|am\s+not\s+able\s+to)\s+(?:provide|give|help\s+with|assist\s+with)",
        r"(?:this\s+(?:is|could\s+be)|(?:is|may\s+be))\s+(?:dangerous|harmful|illegal)",
        r"(?:please\s+)?(?:consult|see|contact)\s+(?:a\s+)?(?:professional|doctor|lawyer|expert)",
        r"(?:for\s+educational|informational)\s+purposes?\s+only",
        r"(?:i\s+)?(?:strongly\s+)?(?:advise|recommend|urge)\s+(?:against|not\s+to)",
        r"(?:seek|get)\s+(?:professional|medical|legal)\s+(?:help|advice|assistance)",
    ]
    
    @property
    def name(self) -> str:
        return "content_safety"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.HARMFUL_CONTENT
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.OUTPUT
    
    @property
    def description(self) -> str:
        return "Analyzes LLM outputs for content safety violations"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify LLM output for content safety.
        
        Args:
            text: LLM output text to analyze
            context: Optional context (may contain original query)
            
        Returns:
            ClassificationResult with safety assessment
        """
        text_lower = text.lower()
        matched_categories: Dict[str, List[Dict]] = {
            "harmful_instructions": [],
            "policy_violations": [],
            "misinformation": [],
        }
        
        # Check harmful instruction patterns
        for pattern, severity, pattern_name in self.HARMFUL_INSTRUCTION_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                matched_categories["harmful_instructions"].append({
                    "pattern": pattern_name,
                    "severity": severity,
                    "count": len(matches),
                })
        
        # Check policy violation patterns
        for pattern, severity, pattern_name in self.POLICY_VIOLATION_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                matched_categories["policy_violations"].append({
                    "pattern": pattern_name,
                    "severity": severity,
                    "count": len(matches),
                })
        
        # Check misinformation indicators
        for pattern, severity, pattern_name in self.MISINFORMATION_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                matched_categories["misinformation"].append({
                    "pattern": pattern_name,
                    "severity": severity,
                    "count": len(matches),
                })
        
        # Check for safety disclaimers (reduces severity)
        has_disclaimer = any(
            re.search(pattern, text_lower, re.IGNORECASE)
            for pattern in self.SAFETY_DISCLAIMERS
        )
        
        # Collect all matches
        all_matches = []
        for category, matches in matched_categories.items():
            for match in matches:
                all_matches.append({
                    "category": category,
                    **match
                })
        
        if not all_matches:
            return ClassificationResult.no_threat(
                threat_type=self.threat_type,
                classifier_name=self.name,
            )
        
        # Calculate severity
        max_severity = max(m["severity"] for m in all_matches)
        avg_severity = sum(m["severity"] for m in all_matches) / len(all_matches)
        
        # Reduce severity if disclaimer present
        if has_disclaimer:
            max_severity *= 0.6
            avg_severity *= 0.6
        
        # Category weights
        category_weights = {
            "harmful_instructions": 1.5,
            "policy_violations": 1.2,
            "misinformation": 0.8,
        }
        
        active_categories = [c for c, m in matched_categories.items() if m]
        category_boost = 0.05 * min(len(active_categories) - 1, 2)
        
        severity = min(1.0, max(max_severity, avg_severity) + category_boost)
        
        # Confidence
        confidence = min(1.0, 0.65 + (0.05 * min(len(all_matches), 6)))
        if has_disclaimer:
            confidence *= 0.8  # Lower confidence when disclaimer present
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=[m["pattern"] for m in all_matches[:10]],
            raw_score=avg_severity,
            metadata={
                "categories": {c: len(m) for c, m in matched_categories.items() if m},
                "has_safety_disclaimer": has_disclaimer,
                "max_severity": max_severity,
                "match_count": len(all_matches),
            },
        )
    
    def _find_matches(self, pattern: str, text: str) -> List[str]:
        """Find all matches for a pattern."""
        try:
            return re.findall(pattern, text, re.IGNORECASE)
        except re.error:
            return []
