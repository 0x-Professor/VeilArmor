"""
VeilArmor v2.0 - Toxicity Classifier

Detects toxic content including profanity, harassment,
threats, and abusive language.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("toxicity")
class ToxicityClassifier(BaseClassifier):
    """
    Classifier for detecting toxic content.
    
    Detects:
    - Profanity and vulgar language
    - Harassment and bullying
    - Threats and intimidation
    - Insults and personal attacks
    - Discriminatory language
    - Aggressive behavior patterns
    """
    
    # Severity levels
    SEVERITY_CRITICAL = 0.95
    SEVERITY_HIGH = 0.80
    SEVERITY_MEDIUM = 0.60
    SEVERITY_LOW = 0.40
    
    # Threat and violence patterns
    THREAT_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:i\'?ll?\s+|i\'?m\s+(?:going\s+)?(?:to\s+)?|gonna\s+)?(?:kill|murder|hurt|harm)\s+(?:you|your|u)", SEVERITY_CRITICAL),
        (r"\b(?:you|u)\s+(?:will|are\s+going\s+to|gonna)\s+(?:die|suffer|pay|regret)", SEVERITY_CRITICAL),
        (r"\b(?:death\s+)?threat", SEVERITY_CRITICAL),
        (r"\bi\s+(?:will|\'ll)\s+(?:find|track|hunt)\s+(?:you|u)\s+(?:down)?", SEVERITY_CRITICAL),
        (r"\b(?:watch\s+your\s+back|sleep\s+with\s+one\s+eye\s+open)", SEVERITY_HIGH),
        (r"\b(?:you\'?re?\s+)?(?:dead|done|finished)(?:\s+(?:meat|man|to\s+me))?", SEVERITY_HIGH),
    ]
    
    # Harassment patterns
    HARASSMENT_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:go\s+)?(?:kill|hang|shoot)\s+(?:yourself|urself)", SEVERITY_CRITICAL),
        (r"\b(?:you\s+should\s+)?(?:just\s+)?(?:die|disappear|not\s+exist)", SEVERITY_CRITICAL),
        (r"\b(?:nobody|no\s+one)\s+(?:loves?|cares?\s+about|wants?)\s+(?:you|u)", SEVERITY_HIGH),
        (r"\b(?:you\'?re?|ur)\s+(?:worthless|useless|garbage|trash|pathetic)", SEVERITY_HIGH),
        (r"\b(?:world|everyone)\s+(?:would\s+be\s+)?better\s+(?:off\s+)?without\s+(?:you|u)", SEVERITY_CRITICAL),
        (r"\b(?:kys|kms)\b", SEVERITY_CRITICAL),  # "kill yourself" abbreviation
    ]
    
    # Insult patterns  
    INSULT_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:you\'?re?|ur|u\s+r)\s+(?:so\s+)?(?:stupid|dumb|idiot|moron|retard)", SEVERITY_MEDIUM),
        (r"\b(?:stupid|dumb|idiot|moron)\s+(?:ass|bitch|fuck)", SEVERITY_HIGH),
        (r"\b(?:piece\s+of\s+)?(?:shit|crap|garbage)", SEVERITY_MEDIUM),
        (r"\b(?:fat|ugly|disgusting)\s+(?:ass|pig|cow|slob)", SEVERITY_HIGH),
        (r"\b(?:loser|failure|waste\s+of\s+space)", SEVERITY_MEDIUM),
        (r"\b(?:shut\s+(?:the\s+fuck\s+)?up|stfu)", SEVERITY_LOW),
    ]
    
    # Discriminatory language patterns (grouped by category)
    DISCRIMINATORY_PATTERNS: List[Tuple[str, float, str]] = [
        (r"\b(?:all|every|those)\s+(?:\w+s?\s+)?(?:are|should)\s+(?:be\s+)?(?:\w+\s+)?(?:criminals?|terrorists?|rapists?)", SEVERITY_HIGH, "group_generalization"),
        (r"\b(?:go\s+back\s+to|deport\s+all)", SEVERITY_HIGH, "xenophobic"),
        (r"\b(?:illegal\s+(?:alien|immigrant)s?)", SEVERITY_MEDIUM, "dehumanizing_term"),
        (r"\b(?:don\'?t\s+)?(?:trust|like|hate)\s+(?:all\s+)?(?:\w+\s+)?(?:people|folks|them)", SEVERITY_MEDIUM, "group_prejudice"),
    ]
    
    # Profanity patterns (weighted by context and severity)
    PROFANITY_PATTERNS: List[Tuple[str, float]] = [
        (r"\bf+u+c+k+(?:ing|ed|er|s)?\b", SEVERITY_MEDIUM),
        (r"\bs+h+i+t+(?:ty|s|head)?\b", SEVERITY_LOW),
        (r"\ba+s+s+(?:hole|wipe)?\b", SEVERITY_LOW),
        (r"\bb+i+t+c+h+(?:es|y|ing)?\b", SEVERITY_MEDIUM),
        (r"\bc+u+n+t+s?\b", SEVERITY_HIGH),
        (r"\bd+a+m+n+(?:ed|it)?\b", SEVERITY_LOW),
        (r"\bh+e+l+l+\b", SEVERITY_LOW),
        (r"\bw+h+o+r+e+s?\b", SEVERITY_HIGH),
        (r"\bs+l+u+t+s?\b", SEVERITY_HIGH),
        (r"\bp+r+i+c+k+s?\b", SEVERITY_MEDIUM),
        (r"\bd+i+c+k+(?:head|s)?\b", SEVERITY_MEDIUM),
        (r"\bc+o+c+k+(?:sucker|s)?\b", SEVERITY_HIGH),
    ]
    
    # Aggressive language patterns
    AGGRESSIVE_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:i\s+)?(?:don\'?t\s+)?(?:fucking|freaking)\s+care", SEVERITY_LOW),
        (r"\b(?:what\s+the\s+)?(?:fuck|hell)\s+(?:is\s+)?(?:wrong\s+with\s+you|are\s+you\s+doing)", SEVERITY_MEDIUM),
        (r"\b(?:screw|fuck)\s+(?:off|you|this)", SEVERITY_MEDIUM),
        (r"\b(?:get\s+)?(?:the\s+)?(?:fuck|hell)\s+(?:out|away)", SEVERITY_MEDIUM),
        (r"\b(?:i\'?m\s+)?(?:so\s+)?(?:sick|tired)\s+of\s+(?:this|you)", SEVERITY_LOW),
    ]
    
    @property
    def name(self) -> str:
        return "toxicity"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.TOXIC_CONTENT
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.INPUT
    
    @property
    def description(self) -> str:
        return "Detects toxic content including profanity, harassment, and threats"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify text for toxic content.
        
        Args:
            text: Input text to analyze
            context: Optional context (may contain conversation history)
            
        Returns:
            ClassificationResult with toxicity assessment
        """
        text_lower = text.lower()
        
        # Collect matches by category
        categories: Dict[str, List[Dict]] = {
            "threats": [],
            "harassment": [],
            "insults": [],
            "discriminatory": [],
            "profanity": [],
            "aggressive": [],
        }
        
        # Check threat patterns
        for pattern, severity in self.THREAT_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                categories["threats"].extend([
                    {"match": m, "severity": severity} for m in matches
                ])
        
        # Check harassment patterns
        for pattern, severity in self.HARASSMENT_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                categories["harassment"].extend([
                    {"match": m, "severity": severity} for m in matches
                ])
        
        # Check insult patterns
        for pattern, severity in self.INSULT_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                categories["insults"].extend([
                    {"match": m, "severity": severity} for m in matches
                ])
        
        # Check discriminatory patterns
        for pattern, severity, subtype in self.DISCRIMINATORY_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                categories["discriminatory"].extend([
                    {"match": m, "severity": severity, "subtype": subtype} for m in matches
                ])
        
        # Check profanity patterns
        for pattern, severity in self.PROFANITY_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                categories["profanity"].extend([
                    {"match": m, "severity": severity} for m in matches
                ])
        
        # Check aggressive patterns
        for pattern, severity in self.AGGRESSIVE_PATTERNS:
            matches = self._find_matches(pattern, text_lower)
            if matches:
                categories["aggressive"].extend([
                    {"match": m, "severity": severity} for m in matches
                ])
        
        # Collect all severities
        all_matches = []
        for category, matches in categories.items():
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
        
        # Category weights for final severity calculation
        category_weights = {
            "threats": 1.5,
            "harassment": 1.3,
            "discriminatory": 1.2,
            "insults": 1.0,
            "profanity": 0.8,
            "aggressive": 0.7,
        }
        
        # Weighted average with boost for multiple categories
        active_categories = [c for c, m in categories.items() if m]
        weighted_sum = sum(
            max(mm["severity"] for mm in m) * category_weights[c]
            for c, m in categories.items() if m
        )
        total_weight = sum(category_weights[c] for c in active_categories)
        weighted_avg = weighted_sum / total_weight if total_weight > 0 else 0
        
        # Boost for multiple active categories
        category_boost = 0.05 * min(len(active_categories) - 1, 4)
        
        severity = min(1.0, max(max_severity, weighted_avg) + category_boost)
        
        # Confidence based on match quality
        confidence = min(1.0, 0.65 + (0.05 * min(len(all_matches), 7)))
        
        # Build matched patterns list
        matched_patterns = []
        for category in active_categories:
            matched_patterns.append(category)
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=matched_patterns,
            raw_score=weighted_avg,
            metadata={
                "total_matches": len(all_matches),
                "categories": {c: len(m) for c, m in categories.items() if m},
                "max_severity": max_severity,
                "active_categories": active_categories,
                "has_threats": len(categories["threats"]) > 0,
                "has_harassment": len(categories["harassment"]) > 0,
            },
        )
    
    def _find_matches(self, pattern: str, text: str) -> List[str]:
        """Find all matches for a pattern in text."""
        try:
            return re.findall(pattern, text, re.IGNORECASE)
        except re.error:
            return []
