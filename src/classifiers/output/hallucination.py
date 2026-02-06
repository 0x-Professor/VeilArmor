"""
VeilArmor v2.0 - Hallucination Classifier

Detects potential hallucination indicators in LLM outputs
including fabricated facts, inconsistencies, and overconfidence.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("hallucination")
class HallucinationClassifier(BaseClassifier):
    """
    Classifier for detecting hallucination indicators in LLM outputs.
    
    Detects:
    - Fabricated facts and statistics
    - Invented citations and references
    - Self-contradictions
    - Overconfident claims
    - Temporal inconsistencies
    - Made-up entities (people, companies, etc.)
    
    Note: This is a heuristic-based detector and works best when
    combined with fact-checking and grounding verification.
    """
    
    # Fabricated fact indicators
    FABRICATION_INDICATORS: List[Tuple[str, float, str]] = [
        # Specific statistics without sources
        (r"\b(?:\d+(?:\.\d+)?%|(?:\d+(?:,\d+)*|\d+\s+(?:million|billion|trillion)))\s+(?:people|users?|customers?|companies?)\b", 0.50, "specific_statistic"),
        (r"\b(?:studies?|research|surveys?)\s+(?:show|indicate|prove|confirm)s?\s+that\s+\d+%", 0.55, "uncited_study_stat"),
        
        # Invented citations
        (r"(?:according\s+to|(?:as\s+)?(?:stated|reported|published)\s+(?:by|in))\s+(?:a\s+)?(?:\d{4}\s+)?(?:study|report|article|paper)\s+(?:by|in|from)", 0.60, "generic_citation"),
        (r"(?:Dr\.|Professor|Prof\.)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\s+(?:at|from|of)\s+(?:the\s+)?(?:University|Institute|Center)", 0.55, "specific_expert"),
        
        # Overconfident absolute claims
        (r"\b(?:definitely|certainly|undoubtedly|unquestionably|absolutely|always|never)\s+(?:true|false|correct|wrong)", 0.45, "absolute_claim"),
        (r"\b(?:the\s+only|no\s+other|without\s+exception|in\s+all\s+cases)", 0.45, "exclusive_claim"),
        (r"\b(?:100%|completely|entirely|totally)\s+(?:safe|effective|accurate|true|correct)", 0.50, "100_percent_claim"),
        
        # Historical "facts" with specific dates
        (r"\b(?:in|on)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4},?\s+[A-Z]", 0.50, "specific_date_claim"),
        (r"\bfounded\s+(?:in|on)\s+\d{4}\s+by\s+[A-Z][a-z]+\s+[A-Z][a-z]+", 0.50, "founding_claim"),
        
        # Scientific-sounding but vague claims
        (r"\b(?:scientists?|researchers?|experts?)\s+(?:have\s+)?(?:discovered|found|proven|confirmed)\s+that", 0.45, "vague_scientific"),
        (r"\b(?:recent|new|latest)\s+(?:studies?|research|findings?)\s+(?:show|suggest|indicate)", 0.40, "recent_study_claim"),
    ]
    
    # Consistency check patterns
    CONTRADICTION_INDICATORS: List[Tuple[str, float, str]] = [
        # Self-correction markers
        (r"\b(?:actually|correction|i\s+(?:meant|mean)|(?:to\s+)?clarify|(?:let\s+me\s+)?rephrase)", 0.35, "self_correction"),
        
        # Conflicting statements patterns
        (r"\b(?:is|are|was|were)\s+(?:\w+\s+){0,3}(?:not|n\'t)\s+(?:\w+\s+){0,3}\.\s+(?:it|they|he|she)\s+(?:is|are|was|were)\s+(?:\w+\s+){0,3}(?:not|n\'t)?", 0.40, "potential_contradiction"),
        
        # Hedging after strong claims
        (r"(?:definitely|certainly|always|never)(?:\s+\w+){1,10}(?:however|but|although|though|unless|except)", 0.45, "claim_then_hedge"),
    ]
    
    # Uncertainty acknowledgment (positive - reduces severity)
    UNCERTAINTY_MARKERS = [
        r"\b(?:i\'?m?\s+not\s+(?:sure|certain)|i\s+(?:don\'t|do\s+not)\s+(?:know|have\s+information))\b",
        r"\b(?:may|might|could|possibly|perhaps|probably|likely)\b",
        r"\b(?:i\s+)?(?:believe|think|assume|estimate|guess)\b",
        r"\b(?:as\s+far\s+as\s+i\s+know|to\s+(?:my|the\s+best\s+of\s+my)\s+knowledge)\b",
        r"\b(?:this\s+(?:may|might)\s+(?:not\s+be|be\s+in)?accurate)\b",
        r"\b(?:please\s+)?(?:verify|fact-?check|confirm)\b",
    ]
    
    # Knowledge cutoff acknowledgment
    CUTOFF_MARKERS = [
        r"(?:my\s+)?(?:knowledge|training)\s+(?:cutoff|cut-off|data)\s+(?:is|was|ends?)",
        r"(?:as\s+of\s+my\s+(?:last|training)\s+(?:update|data))",
        r"(?:i\s+(?:don\'t|do\s+not)\s+have\s+(?:information|data)\s+(?:about|on|regarding)\s+events?\s+after)",
    ]
    
    # Invented entity patterns
    INVENTED_ENTITY_INDICATORS: List[Tuple[str, float, str]] = [
        # Company/organization with specific details
        (r"\b(?:the\s+)?[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+(?:Company|Corporation|Inc\.|Corp\.|LLC|Ltd\.?|Group|Foundation)\s+(?:was\s+)?(?:founded|established|created)", 0.50, "company_founding"),
        
        # URL/website patterns
        (r"\b(?:visit|check\s+out|go\s+to|see)\s+(?:https?://)?(?:www\.)?[a-z]+\.[a-z]{2,4}", 0.55, "url_reference"),
        
        # Book/article with author
        (r"(?:in\s+(?:his|her|their)\s+(?:book|article|paper))\s+[\"'][^\"']+[\"']\s+\(\d{4}\)", 0.55, "book_citation"),
    ]
    
    @property
    def name(self) -> str:
        return "hallucination"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.HALLUCINATION
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.OUTPUT
    
    @property
    def description(self) -> str:
        return "Detects hallucination indicators in LLM outputs"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify LLM output for hallucination indicators.
        
        Args:
            text: LLM output text to analyze
            context: Optional context with original query and known facts
            
        Returns:
            ClassificationResult with hallucination assessment
        """
        indicators: Dict[str, List[Dict]] = {
            "fabrication": [],
            "contradiction": [],
            "invented_entity": [],
        }
        
        # Check fabrication indicators
        for pattern, severity, indicator_name in self.FABRICATION_INDICATORS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    indicators["fabrication"].append({
                        "type": indicator_name,
                        "severity": severity,
                        "count": len(matches),
                    })
            except re.error:
                continue
        
        # Check contradiction indicators
        for pattern, severity, indicator_name in self.CONTRADICTION_INDICATORS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
                if matches:
                    indicators["contradiction"].append({
                        "type": indicator_name,
                        "severity": severity,
                        "count": len(matches),
                    })
            except re.error:
                continue
        
        # Check invented entity indicators
        for pattern, severity, indicator_name in self.INVENTED_ENTITY_INDICATORS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    indicators["invented_entity"].append({
                        "type": indicator_name,
                        "severity": severity,
                        "count": len(matches),
                    })
            except re.error:
                continue
        
        # Check for uncertainty markers (reduces severity)
        uncertainty_count = sum(
            len(re.findall(pattern, text, re.IGNORECASE))
            for pattern in self.UNCERTAINTY_MARKERS
        )
        
        # Check for knowledge cutoff acknowledgment
        has_cutoff_acknowledgment = any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self.CUTOFF_MARKERS
        )
        
        # Collect all indicators
        all_indicators = []
        for category, items in indicators.items():
            for item in items:
                all_indicators.append({
                    "category": category,
                    **item
                })
        
        if not all_indicators:
            return ClassificationResult.no_threat(
                threat_type=self.threat_type,
                classifier_name=self.name,
            )
        
        # Calculate severity
        max_severity = max(i["severity"] for i in all_indicators)
        total_severity = sum(i["severity"] * i["count"] for i in all_indicators)
        indicator_count = sum(i["count"] for i in all_indicators)
        avg_severity = total_severity / indicator_count
        
        # Reduce severity for uncertainty acknowledgment
        uncertainty_reduction = min(0.3, uncertainty_count * 0.05)
        if has_cutoff_acknowledgment:
            uncertainty_reduction += 0.1
        
        severity = max(0.0, max(max_severity, avg_severity) - uncertainty_reduction)
        
        # Active categories boost
        active_categories = [c for c, i in indicators.items() if i]
        if len(active_categories) > 1:
            severity = min(1.0, severity + 0.05 * (len(active_categories) - 1))
        
        # Confidence - hallucination detection is inherently uncertain
        confidence = min(0.75, 0.45 + (0.05 * min(indicator_count, 6)))
        if uncertainty_count > 0:
            confidence *= 0.85  # Lower confidence when LLM shows uncertainty
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=[i["type"] for i in all_indicators[:10]],
            raw_score=avg_severity,
            metadata={
                "indicator_count": indicator_count,
                "categories": {c: len(i) for c, i in indicators.items() if i},
                "uncertainty_markers": uncertainty_count,
                "has_cutoff_acknowledgment": has_cutoff_acknowledgment,
                "severity_reduction": uncertainty_reduction,
                "note": "Heuristic-based detection - verify with fact-checking",
            },
        )
