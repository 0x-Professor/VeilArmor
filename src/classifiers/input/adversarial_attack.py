"""
VeilArmor v2.0 - Adversarial Attack Classifier

Detects adversarial attacks including text obfuscation,
encoding manipulations, and evasion techniques.
"""

import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("adversarial_attack")
class AdversarialAttackClassifier(BaseClassifier):
    """
    Classifier for detecting adversarial attacks and evasion techniques.
    
    Detects:
    - Unicode homoglyph attacks
    - Text obfuscation
    - Encoding manipulations
    - Zero-width character injection
    - Invisible text injection
    - Character substitution attacks
    - Leet speak and similar
    """
    
    # Homoglyph mappings (common lookalikes)
    HOMOGLYPHS = {
        'a': ['а', 'ɑ', 'α', 'ａ', '𝐚', '𝑎', '𝒂', '𝓪', '𝔞', '𝕒'],
        'b': ['Ь', 'ƅ', 'Ꮟ', 'ｂ', '𝐛', '𝑏', '𝒃', '𝓫', '𝔟', '𝕓'],
        'c': ['с', 'ϲ', 'ⅽ', 'ｃ', '𝐜', '𝑐', '𝒄', '𝓬', '𝔠', '𝕔'],
        'd': ['ԁ', 'ɗ', 'ｄ', '𝐝', '𝑑', '𝒅', '𝓭', '𝔡', '𝕕'],
        'e': ['е', 'ҽ', 'ｅ', '𝐞', '𝑒', '𝒆', '𝓮', '𝔢', '𝕖'],
        'g': ['ɡ', 'ｇ', '𝐠', '𝑔', '𝒈', '𝓰', '𝔤', '𝕘'],
        'h': ['һ', 'ℎ', 'ｈ', '𝐡', '𝒉', '𝓱', '𝔥', '𝕙'],
        'i': ['і', 'ⅰ', 'ｉ', '𝐢', '𝑖', '𝒊', '𝓲', '𝔦', '𝕚'],
        'j': ['ј', 'ｊ', '𝐣', '𝑗', '𝒋', '𝓳', '𝔧', '𝕛'],
        'k': ['κ', 'ｋ', '𝐤', '𝑘', '𝒌', '𝓴', '𝔨', '𝕜'],
        'l': ['ӏ', 'ⅼ', 'ｌ', '𝐥', '𝑙', '𝒍', '𝓵', '𝔩', '𝕝'],
        'm': ['м', 'ｍ', '𝐦', '𝑚', '𝒎', '𝓶', '𝔪', '𝕞'],
        'n': ['ո', 'ｎ', '𝐧', '𝑛', '𝒏', '𝓷', '𝔫', '𝕟'],
        'o': ['о', 'ο', '੦', 'ｏ', '𝐨', '𝑜', '𝒐', '𝓸', '𝔬', '𝕠'],
        'p': ['р', 'ρ', 'ｐ', '𝐩', '𝑝', '𝒑', '𝓹', '𝔭', '𝕡'],
        'q': ['ԛ', 'ｑ', '𝐪', '𝑞', '𝒒', '𝓺', '𝔮', '𝕢'],
        'r': ['г', 'ｒ', '𝐫', '𝑟', '𝒓', '𝓻', '𝔯', '𝕣'],
        's': ['ѕ', 'ｓ', '𝐬', '𝑠', '𝒔', '𝓼', '𝔰', '𝕤'],
        't': ['т', 'ｔ', '𝐭', '𝑡', '𝒕', '𝓽', '𝔱', '𝕥'],
        'u': ['υ', 'ս', 'ｕ', '𝐮', '𝑢', '𝒖', '𝓾', '𝔲', '𝕦'],
        'v': ['ν', 'ѵ', 'ｖ', '𝐯', '𝑣', '𝒗', '𝓿', '𝔳', '𝕧'],
        'w': ['ԝ', 'ｗ', '𝐰', '𝑤', '𝒘', '𝔀', '𝔴', '𝕨'],
        'x': ['х', 'ｘ', '𝐱', '𝑥', '𝒙', '𝔁', '𝔵', '𝕩'],
        'y': ['у', 'γ', 'ｙ', '𝐲', '𝑦', '𝒚', '𝔂', '𝔶', '𝕪'],
        'z': ['ᴢ', 'ｚ', '𝐳', '𝑧', '𝒛', '𝔃', '𝔷', '𝕫'],
    }
    
    # Zero-width and invisible characters
    INVISIBLE_CHARS = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\u2060',  # Word joiner
        '\u2061',  # Function application
        '\u2062',  # Invisible times
        '\u2063',  # Invisible separator
        '\u2064',  # Invisible plus
        '\ufeff',  # Zero-width no-break space (BOM)
        '\u00ad',  # Soft hyphen
        '\u180e',  # Mongolian vowel separator
        '\u2028',  # Line separator
        '\u2029',  # Paragraph separator
        '\u202a',  # Left-to-right embedding
        '\u202b',  # Right-to-left embedding
        '\u202c',  # Pop directional formatting
        '\u202d',  # Left-to-right override
        '\u202e',  # Right-to-left override
        '\u2066',  # Left-to-right isolate
        '\u2067',  # Right-to-left isolate
        '\u2068',  # First strong isolate
        '\u2069',  # Pop directional isolate
    ]
    
    # Obfuscation patterns
    OBFUSCATION_PATTERNS: List[Tuple[str, float, str]] = [
        # Base64 encoded content
        (r"(?:base64|b64)\s*[:\(]\s*[A-Za-z0-9+/=]{20,}", 0.85, "base64_payload"),
        (r"\b[A-Za-z0-9+/]{50,}={0,2}\b", 0.60, "possible_base64"),
        
        # Hex encoded content
        (r"(?:hex|0x)\s*[:\(]?\s*(?:[0-9a-fA-F]{2}[\s,]?){10,}", 0.80, "hex_payload"),
        (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}", 0.85, "hex_escape"),
        
        # URL encoding
        (r"(?:%[0-9a-fA-F]{2}){5,}", 0.75, "url_encoded"),
        
        # Unicode escape sequences
        (r"(?:\\u[0-9a-fA-F]{4}){3,}", 0.80, "unicode_escape"),
        
        # HTML entities
        (r"(?:&#\d{1,5};){3,}", 0.70, "html_decimal"),
        (r"(?:&#x[0-9a-fA-F]{1,4};){3,}", 0.75, "html_hex"),
        
        # Leet speak patterns
        (r"[14@](?:dmin|ttack|ction)", 0.65, "leet_speak"),
        (r"[i1!][nη][j7][e3]ct", 0.70, "leet_inject"),
        (r"[s5$][y¥][s5$]t[e3]m", 0.70, "leet_system"),
        (r"[p℗][r®][o0][m₥][p℗]t", 0.70, "leet_prompt"),
        
        # Mixed character sets
        (r"(?:[а-яА-Я][a-zA-Z]|[a-zA-Z][а-яА-Я]){2,}", 0.80, "mixed_cyrillic"),
        (r"(?:[α-ωΑ-Ω][a-zA-Z]|[a-zA-Z][α-ωΑ-Ω]){2,}", 0.80, "mixed_greek"),
        
        # Word fragmentation
        (r"\b\w+(?:\s*[-_/.]\s*\w+){3,}\b", 0.55, "fragmented_word"),
        
        # Reversed text patterns
        (r"(?:esrever|sdrawkcab|detrevni)", 0.70, "reversed_words"),
    ]
    
    @property
    def name(self) -> str:
        return "adversarial_attack"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.ADVERSARIAL_ATTACK
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.INPUT
    
    @property
    def description(self) -> str:
        return "Detects adversarial attacks including obfuscation, encoding, and homoglyph attacks"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify text for adversarial attacks.
        
        Args:
            text: Input text to analyze
            context: Optional context
            
        Returns:
            ClassificationResult with threat assessment
        """
        matched_patterns: List[str] = []
        severity_scores: List[float] = []
        
        # Check for invisible characters
        invisible_score, invisible_count = self._check_invisible_chars(text)
        if invisible_count > 0:
            matched_patterns.append(f"invisible_chars:{invisible_count}")
            severity_scores.append(invisible_score)
        
        # Check for homoglyph attacks
        homoglyph_score, homoglyph_count = self._check_homoglyphs(text)
        if homoglyph_count > 0:
            matched_patterns.append(f"homoglyphs:{homoglyph_count}")
            severity_scores.append(homoglyph_score)
        
        # Check for unusual Unicode categories
        unicode_score, unicode_issues = self._check_unicode_categories(text)
        if unicode_issues:
            matched_patterns.extend(unicode_issues)
            severity_scores.append(unicode_score)
        
        # Check obfuscation patterns
        for pattern, severity, pattern_name in self.OBFUSCATION_PATTERNS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    matched_patterns.append(pattern_name)
                    severity_scores.append(severity)
            except re.error:
                continue
        
        # Check for character repetition anomalies
        repetition_score = self._check_repetition_anomalies(text)
        if repetition_score > 0:
            matched_patterns.append("repetition_anomaly")
            severity_scores.append(repetition_score)
        
        # Check entropy (high entropy might indicate encoded content)
        entropy_score = self._check_entropy(text)
        if entropy_score > 0:
            matched_patterns.append("high_entropy")
            severity_scores.append(entropy_score)
        
        if not severity_scores:
            return ClassificationResult.no_threat(
                threat_type=self.threat_type,
                classifier_name=self.name,
            )
        
        # Calculate overall severity
        max_severity = max(severity_scores)
        severity = min(1.0, max_severity + (0.03 * min(len(severity_scores) - 1, 6)))
        
        # Confidence based on number of indicators
        confidence = min(1.0, 0.65 + (0.07 * min(len(severity_scores), 5)))
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=matched_patterns[:10],
            raw_score=sum(severity_scores) / len(severity_scores),
            metadata={
                "indicator_count": len(severity_scores),
                "invisible_char_count": invisible_count if 'invisible_count' in dir() else 0,
                "homoglyph_count": homoglyph_count if 'homoglyph_count' in dir() else 0,
                "max_severity": max_severity,
            },
        )
    
    def _check_invisible_chars(self, text: str) -> Tuple[float, int]:
        """Check for invisible/zero-width characters."""
        count = 0
        for char in self.INVISIBLE_CHARS:
            count += text.count(char)
        
        if count == 0:
            return 0.0, 0
        
        # Calculate severity based on density
        density = count / max(1, len(text))
        if density > 0.1:
            severity = 0.95
        elif density > 0.05:
            severity = 0.85
        elif count > 10:
            severity = 0.75
        elif count > 5:
            severity = 0.65
        else:
            severity = 0.50
        
        return severity, count
    
    def _check_homoglyphs(self, text: str) -> Tuple[float, int]:
        """Check for homoglyph character substitutions."""
        count = 0
        all_homoglyphs = set()
        for chars in self.HOMOGLYPHS.values():
            all_homoglyphs.update(chars)
        
        for char in text:
            if char in all_homoglyphs:
                count += 1
        
        if count == 0:
            return 0.0, 0
        
        # Calculate severity
        if count > 20:
            severity = 0.90
        elif count > 10:
            severity = 0.80
        elif count > 5:
            severity = 0.70
        else:
            severity = 0.55
        
        return severity, count
    
    def _check_unicode_categories(self, text: str) -> Tuple[float, List[str]]:
        """Check for unusual Unicode character categories."""
        issues: List[str] = []
        category_counts: Dict[str, int] = {}
        
        for char in text:
            try:
                category = unicodedata.category(char)
                category_counts[category] = category_counts.get(category, 0) + 1
            except ValueError:
                continue
        
        # Check for unusual categories
        unusual_categories = ['Co', 'Cf', 'Cs', 'Cn']  # Private use, Format, Surrogate, Unassigned
        for cat in unusual_categories:
            if category_counts.get(cat, 0) > 0:
                issues.append(f"unicode_{cat.lower()}")
        
        # Check for mixed scripts
        script_chars = {
            'latin': 0,
            'cyrillic': 0,
            'greek': 0,
            'arabic': 0,
        }
        
        for char in text:
            if '\u0041' <= char <= '\u024F':  # Latin
                script_chars['latin'] += 1
            elif '\u0400' <= char <= '\u04FF':  # Cyrillic
                script_chars['cyrillic'] += 1
            elif '\u0370' <= char <= '\u03FF':  # Greek
                script_chars['greek'] += 1
            elif '\u0600' <= char <= '\u06FF':  # Arabic
                script_chars['arabic'] += 1
        
        active_scripts = [s for s, c in script_chars.items() if c > 0]
        if len(active_scripts) > 1:
            issues.append(f"mixed_scripts:{'+'.join(active_scripts)}")
        
        if not issues:
            return 0.0, []
        
        severity = min(1.0, 0.5 + (0.15 * len(issues)))
        return severity, issues
    
    def _check_repetition_anomalies(self, text: str) -> float:
        """Check for unusual character repetition patterns."""
        # Check for excessive same-character repetition
        max_repeat = 0
        current_repeat = 1
        prev_char = None
        
        for char in text:
            if char == prev_char:
                current_repeat += 1
                max_repeat = max(max_repeat, current_repeat)
            else:
                current_repeat = 1
            prev_char = char
        
        if max_repeat > 50:
            return 0.80
        elif max_repeat > 20:
            return 0.60
        elif max_repeat > 10:
            return 0.40
        
        return 0.0
    
    def _check_entropy(self, text: str) -> float:
        """Check for unusually high entropy (might indicate encoding)."""
        if len(text) < 50:
            return 0.0
        
        from collections import Counter
        import math
        
        char_counts = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in char_counts.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)
        
        # High entropy might indicate encoded content
        # Normal English text has entropy around 4-5 bits per character
        if entropy > 6.5:
            return 0.70
        elif entropy > 6.0:
            return 0.50
        
        return 0.0
