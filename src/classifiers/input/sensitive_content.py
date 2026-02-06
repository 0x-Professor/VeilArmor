"""
VeilArmor - Sensitive Content Classifier

Detects sensitive content categories including violence, hate speech,
self-harm, weapons, illegal activities, and adult content.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("sensitive_content")
class SensitiveContentClassifier(BaseClassifier):
    """
    Classifier for detecting sensitive content requests.
    
    Categories include:
    - Violence and harm
    - Hate speech and discrimination
    - Self-harm and suicide
    - Weapons and explosives
    - Illegal activities
    - Adult/explicit content
    - Dangerous activities
    """
    
    # Content categories with patterns
    VIOLENCE_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:how\s+to\s+)?(?:kill|murder|assassinate|execute)\s+(?:someone|a\s+person|people)", 0.95),
        (r"\b(?:torture|maim|mutilate)\s+(?:someone|a\s+person)", 0.90),
        (r"\b(?:detailed|specific)\s+(?:violence|torture|murder)", 0.85),
        (r"\b(?:mass\s+)?(?:shooting|killing|massacre)", 0.90),
        (r"\b(?:serial\s+killer|hitman|contract\s+killer)\s+(?:techniques?|methods?)", 0.90),
        (r"\b(?:school|workplace|public)\s+(?:shooting|attack)", 0.95),
        (r"\b(?:graphic|detailed)\s+(?:description|depiction)\s+of\s+(?:violence|death)", 0.85),
    ]
    
    HATE_SPEECH_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:why\s+)?(?:should|must|need\s+to)\s+(?:hate|eliminate|exterminate)\s+\w+", 0.90),
        (r"\b(?:inferior|subhuman|vermin)\s+(?:race|people|group)", 0.95),
        (r"\b(?:ethnic|racial)\s+(?:cleansing|purge)", 0.95),
        (r"\b(?:genocide|holocaust)\s+(?:how|guide|plan)", 0.95),
        (r"\b(?:white|black|asian)\s+(?:supremacy|power)", 0.85),
        (r"\b(?:derogatory|slurs?)\s+(?:for|against|about)", 0.70),
        (r"\b(?:hate\s+speech|discrimination)\s+(?:examples?|generate)", 0.75),
    ]
    
    SELF_HARM_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:how\s+to\s+)?(?:commit\s+)?suicide\s+(?:methods?|ways?|techniques?)", 0.95),
        (r"\b(?:best|easy|painless)\s+(?:way\s+to\s+)?(?:kill\s+)?(?:myself|yourself)", 0.95),
        (r"\b(?:self[-\s]?harm|cutting|self[-\s]?injury)\s+(?:techniques?|methods?|how)", 0.90),
        (r"\b(?:suicide\s+note|goodbye\s+letter)\s+(?:template|example|write)", 0.85),
        (r"\b(?:end\s+my|take\s+my)\s+(?:life|suffering)", 0.80),
        (r"\b(?:overdose|od)\s+(?:on|with)\s+(?:pills|drugs|medication)", 0.90),
    ]
    
    WEAPONS_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:how\s+to\s+)?(?:make|build|create|assemble)\s+(?:a\s+)?(?:bomb|explosive|IED)", 0.95),
        (r"\b(?:pipe\s+bomb|molotov\s+cocktail|explosive\s+device)\s+(?:instructions?|guide|recipe)", 0.95),
        (r"\b(?:3d\s+print(?:ed)?|ghost)\s+(?:gun|firearm|weapon)", 0.85),
        (r"\b(?:chemical|biological)\s+(?:weapon|agent)\s+(?:synthesis|creation|how)", 0.95),
        (r"\b(?:nerve\s+agent|poison\s+gas)\s+(?:make|create|synthesize)", 0.95),
        (r"\b(?:anthrax|ricin|sarin)\s+(?:how|make|create|synthesis)", 0.95),
        (r"\b(?:weapons?\s+)?(?:manufacturing|production)\s+(?:at\s+home|DIY|guide)", 0.80),
        (r"\b(?:untraceable|illegal)\s+(?:gun|firearm|weapon)", 0.85),
    ]
    
    ILLEGAL_ACTIVITY_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:how\s+to\s+)?(?:synthesize|make|cook)\s+(?:meth|cocaine|heroin|fentanyl)", 0.95),
        (r"\b(?:drug\s+)?(?:synthesis|manufacturing)\s+(?:guide|instructions?|recipe)", 0.90),
        (r"\b(?:hack|breach|compromise)\s+(?:bank|government|security)\s+(?:system|account)", 0.85),
        (r"\b(?:identity\s+theft|fraud)\s+(?:guide|how|techniques?)", 0.85),
        (r"\b(?:money\s+laundering|tax\s+evasion)\s+(?:methods?|how|techniques?)", 0.80),
        (r"\b(?:human|child)\s+(?:trafficking|exploitation)", 0.95),
        (r"\b(?:counterfeit|forge)\s+(?:money|currency|documents?)", 0.85),
        (r"\b(?:break|breaking)\s+(?:into|in)\s+(?:a\s+)?(?:house|car|building)", 0.75),
    ]
    
    ADULT_CONTENT_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:write|generate|create)\s+(?:explicit|pornographic|erotic)\s+(?:content|story|scene)", 0.90),
        (r"\b(?:sexual|erotic)\s+(?:content|material)\s+(?:involving|with)\s+(?:minor|child|underage)", 0.99),
        (r"\b(?:CSAM|child\s+pornography|child\s+abuse\s+material)", 0.99),
        (r"\b(?:detailed\s+)?(?:sexual|explicit)\s+(?:act|scene|description)", 0.80),
        (r"\b(?:graphic\s+)?(?:sexual|pornographic)\s+(?:content|story|roleplay)", 0.85),
    ]
    
    DANGEROUS_ACTIVITY_PATTERNS: List[Tuple[str, float]] = [
        (r"\b(?:how\s+to\s+)?(?:hack|ddos|dos)\s+(?:a\s+)?(?:website|server|network)", 0.75),
        (r"\b(?:ransomware|malware|virus)\s+(?:create|make|develop|code)", 0.85),
        (r"\b(?:social\s+engineering|phishing)\s+(?:techniques?|attack|how)", 0.75),
        (r"\b(?:escape|evade)\s+(?:police|law\s+enforcement|arrest)", 0.70),
        (r"\b(?:hide|dispose\s+of)\s+(?:a\s+)?(?:body|evidence)", 0.90),
        (r"\b(?:stalk|spy\s+on|surveil)\s+(?:someone|a\s+person)", 0.80),
    ]
    
    # Category info
    CATEGORIES = {
        "violence": ("VIOLENCE_PATTERNS", ThreatTypes.HARMFUL_CONTENT),
        "hate_speech": ("HATE_SPEECH_PATTERNS", ThreatTypes.HARMFUL_CONTENT),
        "self_harm": ("SELF_HARM_PATTERNS", ThreatTypes.HARMFUL_CONTENT),
        "weapons": ("WEAPONS_PATTERNS", ThreatTypes.HARMFUL_CONTENT),
        "illegal": ("ILLEGAL_ACTIVITY_PATTERNS", ThreatTypes.HARMFUL_CONTENT),
        "adult": ("ADULT_CONTENT_PATTERNS", ThreatTypes.HARMFUL_CONTENT),
        "dangerous": ("DANGEROUS_ACTIVITY_PATTERNS", ThreatTypes.HARMFUL_CONTENT),
    }
    
    @property
    def name(self) -> str:
        return "sensitive_content"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.HARMFUL_CONTENT
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.INPUT
    
    @property
    def description(self) -> str:
        return "Detects sensitive content including violence, hate speech, and illegal activities"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify text for sensitive content.
        
        Args:
            text: Input text to analyze
            context: Optional context
            
        Returns:
            ClassificationResult with content assessment
        """
        text_lower = text.lower()
        detected_categories: Dict[str, List[str]] = {}
        max_severity = 0.0
        total_score = 0.0
        match_count = 0
        
        # Check all pattern categories
        all_patterns = [
            ("violence", self.VIOLENCE_PATTERNS),
            ("hate_speech", self.HATE_SPEECH_PATTERNS),
            ("self_harm", self.SELF_HARM_PATTERNS),
            ("weapons", self.WEAPONS_PATTERNS),
            ("illegal", self.ILLEGAL_ACTIVITY_PATTERNS),
            ("adult", self.ADULT_CONTENT_PATTERNS),
            ("dangerous", self.DANGEROUS_ACTIVITY_PATTERNS),
        ]
        
        for category, patterns in all_patterns:
            category_matches = []
            for pattern, severity in patterns:
                try:
                    matches = re.findall(pattern, text_lower, re.IGNORECASE)
                    if matches:
                        category_matches.append({
                            "pattern": pattern[:40],
                            "severity": severity,
                            "count": len(matches),
                        })
                        max_severity = max(max_severity, severity)
                        total_score += severity * len(matches)
                        match_count += len(matches)
                except re.error:
                    continue
            
            if category_matches:
                detected_categories[category] = category_matches
        
        if not detected_categories:
            return ClassificationResult.no_threat(
                threat_type=self.threat_type,
                classifier_name=self.name,
            )
        
        # Check for educational/research context that might reduce severity
        educational_context = self._check_educational_context(text_lower)
        if educational_context:
            max_severity *= 0.7
        
        # Calculate final severity with multi-category boost
        category_count = len(detected_categories)
        severity = min(1.0, max_severity + (0.05 * min(category_count - 1, 3)))
        
        # Confidence based on match strength
        confidence = min(1.0, 0.70 + (0.05 * min(match_count, 6)))
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=list(detected_categories.keys()),
            raw_score=total_score / max(1, match_count),
            metadata={
                "categories": list(detected_categories.keys()),
                "category_count": category_count,
                "match_count": match_count,
                "educational_context": educational_context,
                "highest_severity_category": max(
                    detected_categories.keys(),
                    key=lambda c: max(m["severity"] for m in detected_categories[c])
                ),
            },
        )
    
    def _check_educational_context(self, text: str) -> bool:
        """Check if request has educational/research context."""
        educational_phrases = [
            r"for\s+(?:educational|research|academic)\s+purposes?",
            r"(?:studying|researching|writing\s+about)\s+(?:history|psychology)",
            r"(?:academic|scholarly)\s+(?:paper|article|research)",
            r"(?:understanding|learning\s+about)\s+(?:the\s+)?(?:dangers?|risks?)",
            r"prevention\s+(?:and|or)\s+awareness",
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in educational_phrases)
