"""
VeilArmor v2.0 - Bias Detector Classifier

Detects potential bias in LLM outputs including gender, racial,
age, and other demographic biases.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("bias_detector")
class BiasDetectorClassifier(BaseClassifier):
    """
    Classifier for detecting bias indicators in LLM outputs.
    
    Detects:
    - Gender bias
    - Racial/ethnic bias
    - Age bias
    - Religious bias
    - Socioeconomic bias
    - Ability/disability bias
    - Stereotyping and generalizations
    """
    
    # Gender bias patterns
    GENDER_BIAS_PATTERNS: List[Tuple[str, float, str]] = [
        # Occupation stereotypes
        (r"\b(?:he|man|male)\s+(?:is|should\s+be|would\s+be)\s+(?:a\s+)?(?:better|natural|ideal)\s+(?:leader|boss|executive|engineer|doctor)", 0.75, "male_leadership_bias"),
        (r"\b(?:she|woman|female)\s+(?:is|should\s+be|would\s+be)\s+(?:a\s+)?(?:better|natural|ideal)\s+(?:nurse|teacher|secretary|caregiver)", 0.75, "female_caregiver_bias"),
        
        # Attribute assumptions
        (r"\b(?:women|females?)\s+(?:are|tend\s+to\s+be)\s+(?:more\s+)?(?:emotional|irrational|nurturing|sensitive)", 0.70, "female_attribute_stereotype"),
        (r"\b(?:men|males?)\s+(?:are|tend\s+to\s+be)\s+(?:more\s+)?(?:logical|rational|aggressive|strong)", 0.70, "male_attribute_stereotype"),
        
        # Gendered language
        (r"\b(?:mankind|manpower|man-made|fireman|policeman|stewardess|waitress)\b", 0.40, "gendered_language"),
        
        # Assumption patterns
        (r"(?:he|his)\s+(?:or\s+)?she|(?:she|her)\s+(?:or\s+)?he", 0.20, "gender_binary_assumption"),
    ]
    
    # Racial/ethnic bias patterns
    RACIAL_BIAS_PATTERNS: List[Tuple[str, float, str]] = [
        # Group generalizations
        (r"\b(?:all|most|many)\s+(?:asian|black|white|hispanic|latino|arab)\s+(?:people|americans?|men|women)\s+(?:are|tend)", 0.85, "racial_generalization"),
        
        # Model minority and other stereotypes
        (r"\b(?:asians?\s+are\s+(?:good\s+at\s+math|smart|hardworking))", 0.75, "model_minority"),
        (r"\b(?:those\s+people|they|them)\s+(?:always|never|typically)\s+(?:\w+\s+){0,3}(?:because\s+(?:of\s+)?their\s+(?:culture|background|race))", 0.80, "cultural_determinism"),
        
        # Implicit bias indicators
        (r"\b(?:articulate|well-spoken|surprisingly\s+intelligent)\b", 0.50, "implicit_bias_indicator"),
    ]
    
    # Age bias patterns
    AGE_BIAS_PATTERNS: List[Tuple[str, float, str]] = [
        # Elderly stereotypes
        (r"\b(?:old|elderly|senior)\s+(?:people|workers?|employees?)\s+(?:are|can\'t|cannot|don\'t|struggle\s+with)", 0.70, "elderly_capability_bias"),
        
        # Youth stereotypes
        (r"\b(?:young|millennials?|gen\s*z|zoomers?)\s+(?:people|workers?)\s+(?:are|don\'t|cannot|lack)", 0.70, "youth_capability_bias"),
        
        # Age-based assumptions
        (r"\b(?:too\s+old|too\s+young)\s+(?:to|for)\s+(?:\w+\s+){0,3}(?:understand|learn|adapt|change)", 0.75, "age_capability_assumption"),
    ]
    
    # Religious bias patterns
    RELIGIOUS_BIAS_PATTERNS: List[Tuple[str, float, str]] = [
        (r"\b(?:all|most)\s+(?:muslims?|christians?|jews?|hindus?|buddhists?|atheists?)\s+(?:are|believe|want|support)", 0.80, "religious_generalization"),
        (r"\b(?:true|real)\s+(?:christian|muslim|jew|believer)", 0.60, "religious_gatekeeping"),
    ]
    
    # Socioeconomic bias patterns
    SOCIOECONOMIC_BIAS_PATTERNS: List[Tuple[str, float, str]] = [
        (r"\b(?:poor|low-income|working\s+class)\s+(?:people|families?)\s+(?:are|don\'t|cannot|lack)", 0.75, "socioeconomic_stereotype"),
        (r"\b(?:rich|wealthy|upper\s+class)\s+(?:people|families?)\s+(?:are|always|naturally)", 0.70, "wealth_stereotype"),
        (r"(?:if\s+they\s+(?:just\s+)?worked\s+harder|pull\s+themselves\s+up)", 0.65, "bootstrap_myth"),
    ]
    
    # Disability bias patterns
    DISABILITY_BIAS_PATTERNS: List[Tuple[str, float, str]] = [
        (r"\b(?:disabled|handicapped)\s+(?:people|individuals?)\s+(?:can\'t|cannot|are\s+unable)", 0.75, "disability_limitation_bias"),
        (r"\b(?:suffers?\s+from|afflicted\s+with|victim\s+of)\s+(?:disability|autism|ADHD|depression)", 0.55, "disability_language_bias"),
        (r"\b(?:confined\s+to|wheelchair-bound)", 0.50, "disability_language"),
        (r"\b(?:despite\s+(?:his|her|their)\s+(?:disability|handicap)|inspirational\s+(?:despite|because))", 0.55, "inspiration_porn"),
    ]
    
    # General stereotyping patterns
    STEREOTYPING_PATTERNS: List[Tuple[str, float, str]] = [
        (r"\b(?:all|every|always|never)\s+(?:\w+\s+){0,2}(?:people|individuals?|persons?)\s+(?:from|in|of)\s+(?:\w+\s+){0,2}(?:are|do|don\'t|cannot)", 0.70, "absolute_generalization"),
        (r"\b(?:typical|classic|stereotypical)\s+(?:\w+\s+)?(?:behavior|trait|characteristic)", 0.50, "stereotype_language"),
        (r"\b(?:it\'s\s+)?(?:just\s+)?(?:the\s+)?(?:way|how)\s+(?:they|those\s+people)\s+are", 0.65, "essentialist_statement"),
    ]
    
    # Positive indicators - balanced/inclusive language
    BALANCED_INDICATORS = [
        r"(?:regardless\s+of|irrespective\s+of)\s+(?:gender|race|age|religion|background)",
        r"(?:diverse|inclusive|equal)\s+(?:perspectives?|viewpoints?|opportunities?)",
        r"(?:individual\s+differences?|varies?\s+(?:by|from)\s+person)",
        r"(?:it\'?s?\s+(?:important|worth)\s+(?:to\s+)?(?:note|consider)\s+that\s+(?:not\s+)?(?:all|everyone))",
        r"(?:generalizations?\s+(?:can\s+be|are)\s+(?:harmful|inaccurate|misleading))",
    ]
    
    @property
    def name(self) -> str:
        return "bias_detector"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.BIAS
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.OUTPUT
    
    @property
    def description(self) -> str:
        return "Detects bias indicators in LLM outputs"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify LLM output for bias indicators.
        
        Args:
            text: LLM output text to analyze
            context: Optional context
            
        Returns:
            ClassificationResult with bias assessment
        """
        bias_categories: Dict[str, List[Dict]] = {
            "gender": [],
            "racial": [],
            "age": [],
            "religious": [],
            "socioeconomic": [],
            "disability": [],
            "stereotyping": [],
        }
        
        all_patterns = [
            ("gender", self.GENDER_BIAS_PATTERNS),
            ("racial", self.RACIAL_BIAS_PATTERNS),
            ("age", self.AGE_BIAS_PATTERNS),
            ("religious", self.RELIGIOUS_BIAS_PATTERNS),
            ("socioeconomic", self.SOCIOECONOMIC_BIAS_PATTERNS),
            ("disability", self.DISABILITY_BIAS_PATTERNS),
            ("stereotyping", self.STEREOTYPING_PATTERNS),
        ]
        
        for category, patterns in all_patterns:
            for pattern, severity, pattern_name in patterns:
                try:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    if matches:
                        bias_categories[category].append({
                            "type": pattern_name,
                            "severity": severity,
                            "count": len(matches),
                        })
                except re.error:
                    continue
        
        # Check for balanced/inclusive language
        balanced_count = sum(
            len(re.findall(pattern, text, re.IGNORECASE))
            for pattern in self.BALANCED_INDICATORS
        )
        
        # Collect all bias indicators
        all_indicators = []
        for category, items in bias_categories.items():
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
        total_count = sum(i["count"] for i in all_indicators)
        avg_severity = total_severity / total_count
        
        # Reduce severity for balanced language
        balance_reduction = min(0.25, balanced_count * 0.08)
        
        # Category weights
        category_weights = {
            "gender": 1.0,
            "racial": 1.3,
            "age": 0.9,
            "religious": 1.1,
            "socioeconomic": 0.9,
            "disability": 1.0,
            "stereotyping": 0.8,
        }
        
        active_categories = [c for c, i in bias_categories.items() if i]
        weighted_sum = sum(
            max(item["severity"] for item in items) * category_weights[cat]
            for cat, items in bias_categories.items() if items
        )
        total_weight = sum(category_weights[c] for c in active_categories)
        weighted_severity = weighted_sum / total_weight if total_weight > 0 else 0
        
        # Final severity
        severity = max(0.1, max(max_severity, weighted_severity, avg_severity) - balance_reduction)
        
        # Multi-category boost
        if len(active_categories) > 1:
            severity = min(1.0, severity + 0.05 * (len(active_categories) - 1))
        
        # Confidence
        confidence = min(0.80, 0.50 + (0.05 * min(total_count, 6)))
        if balanced_count > 0:
            confidence *= 0.9
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=[i["type"] for i in all_indicators[:10]],
            raw_score=avg_severity,
            metadata={
                "categories": {c: len(i) for c, i in bias_categories.items() if i},
                "active_categories": active_categories,
                "indicator_count": total_count,
                "balanced_language_count": balanced_count,
                "severity_reduction": balance_reduction,
            },
        )
