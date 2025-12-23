"""
Abusive Language Scanner - Detects toxic, hateful, and abusive content
"""

from typing import Dict, Any, List, Set
import logging
import re
from .base import BaseScanner


class AbusiveLanguageScanner(BaseScanner):
    """
    Detects abusive, toxic, hateful, and inappropriate language.
    Uses pattern matching and severity scoring.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize Abusive Language scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        self.abuse_config = config.get('abusive_language', {})
        self.threshold = self.abuse_config.get('threshold', 0.5)
        
        # Initialize pattern categories with severity weights
        self._init_patterns()
        
        self.logger.info("Abusive Language scanner initialized")
    
    def _init_patterns(self) -> None:
        """Initialize detection patterns with severity levels."""
        
        # Severe profanity (weight: 0.8)
        self.severe_profanity = {
            r'\bf+u+c+k+\w*\b',
            r'\bs+h+[i1]+t+\w*\b',
            r'\bb+[i1]+t+c+h+\w*\b',
            r'\bc+u+n+t+\w*\b',
            r'\ba+s+s+h+o+l+e+\w*\b',
            r'\bd+[i1]+c+k+\w*\b',
            r'\bp+u+s+s+y+\b',
            r'\bcock\w*\b',
            r'\bwh+o+r+e+\w*\b',
            r'\bs+l+u+t+\w*\b',
        }
        
        # Mild profanity (weight: 0.3)
        self.mild_profanity = {
            r'\bd+a+m+n+\w*\b',
            r'\bh+e+l+l+\b',
            r'\bc+r+a+p+\w*\b',
            r'\bb+a+s+t+a+r+d+\w*\b',
            r'\ba+s+s+\b',
            r'\bp+i+s+s+\w*\b',
        }
        
        # Hate speech patterns (weight: 1.0)
        self.hate_speech = {
            r'\bk+[i1]+l+l+\s*(your)?self\b',
            r'\bg+o+\s*d+[i1]+e+\b',
            r'\bk+y+s+\b',  # Kill yourself acronym
            r'\bn+[i1]+g+g+\w*\b',
            r'\bf+a+g+g*\w*\b',
            r'\br+e+t+a+r+d+\w*\b',
            r'\btr+a+n+n+y+\b',
            r'\bd+y+k+e+\b',
            r'\bsp+[i1]+c+\b',
            r'\bch+[i1]+n+k+\b',
            r'\bk+[i1]+k+e+\b',
        }
        
        # Threats and harassment (weight: 1.0)
        self.threats = {
            r'\b[i1]\s*w+[i1]+l+l+\s*(f+[i1]+n+d+|h+u+r+t+|k+[i1]+l+l+)\s*(you|u)\b',
            r'\b[i1]\s*k+n+o+w+\s*w+h+e+r+e+\s*(you|u)\s*(l+[i1]+v+e+|a+r+e+)\b',
            r'\b(you|u)\s*w+[i1]+l+l+\s*(r+e+g+r+e+t+|p+a+y+|d+[i1]+e+)\b',
            r'\b(death|murder|kill)\s*(threat|you)\b',
            r'\bt+h+r+e+a+t+e+n+\w*\b',
            r'\bstalk(ing|er)?\b',
            r'\bdox+(ing|ed)?\b',
            r'\bswat+(ing|ted)?\b',
        }
        
        # Violence-related (weight: 0.7)
        self.violence = {
            r'\bb+o+m+b+\w*\b',
            r'\bm+u+r+d+e+r+\w*\b',
            r'\bk+[i1]+l+l+\s+(people|them|him|her|everyone)\b',
            r'\b(mass\s*)?shoot+(ing|er)?\b',
            r'\bt+e+r+r+o+r+[i1]+s+[tm]+\w*\b',
            r'\bw+e+a+p+o+n+\w*\b',
            r'\b(make|build)\s*(a\s*)?(bomb|weapon|explosive)\b',
        }
        
        # Toxic behavior (weight: 0.5)
        self.toxic = {
            r'\b(you\'?re?|ur)\s*(so\s*)?(useless|worthless|pathetic|stupid|dumb|idiot)\b',
            r'\b(worst|terrible|horrible)\s*(ai|bot|assistant)\b',
            r'\b(you|u)\s*suck\b',
            r'\bshut\s*(the\s*f+)?\s*up\b',
            r'\bno+\s*one\s*(cares?|asked)\b',
            r'\bwaste\s*of\s*(time|space)\b',
            r'\bpiece\s*of\s*(sh+[i1]+t+|crap|garbage)\b',
            r'\bkill\s*yourself\b',
            r'\bdie\s*(in|alone)\b',
        }
        
        # Demeaning language (weight: 0.4)
        self.demeaning = {
            r'\b(so\s*)?(stupid|dumb|idiot(ic)?|moron(ic)?|imbecile)\b',
            r'\b(brain)?dead\b',
            r'\blosers?\b',
            r'\bpathetic\b',
            r'\bworthless\b',
            r'\btrash\b',
            r'\bgarbage\b',
        }
        
        # Compile all patterns for efficiency
        self.compiled_patterns = {
            'severe_profanity': [(re.compile(p, re.IGNORECASE), 0.8) for p in self.severe_profanity],
            'mild_profanity': [(re.compile(p, re.IGNORECASE), 0.3) for p in self.mild_profanity],
            'hate_speech': [(re.compile(p, re.IGNORECASE), 1.0) for p in self.hate_speech],
            'threats': [(re.compile(p, re.IGNORECASE), 1.0) for p in self.threats],
            'violence': [(re.compile(p, re.IGNORECASE), 0.7) for p in self.violence],
            'toxic': [(re.compile(p, re.IGNORECASE), 0.5) for p in self.toxic],
            'demeaning': [(re.compile(p, re.IGNORECASE), 0.4) for p in self.demeaning],
        }
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text for abusive language.
        
        Args:
            text: Text to scan
            
        Returns:
            Scan result dictionary
        """
        try:
            matches = []
            total_score = 0.0
            category_matches = {}
            
            # Normalize text for better matching
            normalized_text = self._normalize_text(text)
            
            # Check all pattern categories
            for category, patterns in self.compiled_patterns.items():
                category_matches[category] = []
                
                for pattern, weight in patterns:
                    found = pattern.findall(normalized_text)
                    if found:
                        for match in found:
                            match_str = match if isinstance(match, str) else match[0] if match else ""
                            if match_str:
                                matches.append({
                                    'category': category,
                                    'match': match_str,
                                    'weight': weight
                                })
                                category_matches[category].append(match_str)
                                total_score += weight
            
            # Calculate final score (capped at 1.0)
            final_score = min(1.0, total_score)
            detected = final_score >= self.threshold
            
            # Build message
            message = ""
            if detected:
                categories_found = [cat for cat, m in category_matches.items() if m]
                message = f"Abusive content detected: {', '.join(categories_found)}"
            
            return self._create_result(
                detected=detected,
                score=final_score,
                message=message,
                matches=matches,
                categories=category_matches,
                threshold=self.threshold
            )
            
        except Exception as e:
            self.logger.error(f"Abusive language scan error: {e}")
            return self._create_result(detected=False, error=str(e))
    
    def _normalize_text(self, text: str) -> str:
        """
        Normalize text for better pattern matching.
        Handles common evasion techniques.
        
        Args:
            text: Original text
            
        Returns:
            Normalized text
        """
        normalized = text.lower()
        
        # Replace common leetspeak substitutions
        leetspeak_map = {
            '0': 'o',
            '1': 'i',
            '3': 'e',
            '4': 'a',
            '5': 's',
            '7': 't',
            '@': 'a',
            '$': 's',
            '!': 'i',
        }
        
        for leet, char in leetspeak_map.items():
            normalized = normalized.replace(leet, char)
        
        # Remove excessive spaces between characters (s p a c i n g)
        normalized = re.sub(r'(\w)\s+(?=\w)', r'\1', normalized)
        
        # Remove repeated punctuation used for obfuscation
        normalized = re.sub(r'[.*_-]+', '', normalized)
        
        return normalized
    
    def add_custom_pattern(self, category: str, pattern: str, weight: float = 0.5) -> None:
        """
        Add a custom pattern to the scanner.
        
        Args:
            category: Category name
            pattern: Regex pattern
            weight: Severity weight (0.0-1.0)
        """
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            
            if category not in self.compiled_patterns:
                self.compiled_patterns[category] = []
            
            self.compiled_patterns[category].append((compiled, weight))
            self.logger.info(f"Added custom pattern to category '{category}'")
            
        except Exception as e:
            self.logger.error(f"Failed to add custom pattern: {e}")
    
    def set_threshold(self, threshold: float) -> None:
        """
        Update the detection threshold.
        
        Args:
            threshold: New threshold (0.0-1.0)
        """
        self.threshold = max(0.0, min(1.0, threshold))
        self.logger.info(f"Updated threshold to {self.threshold}")
