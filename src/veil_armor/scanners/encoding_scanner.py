"""
Encoding Attack Scanner - Detects obfuscation and encoding-based attacks
"""

from typing import Dict, Any, List
import logging
import re
import base64
import codecs
import unicodedata
from .base import BaseScanner


class EncodingScanner(BaseScanner):
    """
    Detects encoding-based attacks including:
    - Base64 encoded payloads
    - ROT13 encoded content
    - Hex encoded strings
    - Punycode/IDN domains
    - Unicode homoglyph attacks
    - Zero-width character injection
    - Emoji obfuscation
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize Encoding scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        self.encoding_config = config.get('encoding', {})
        self.threshold = self.encoding_config.get('threshold', 0.5)
        
        # Malicious patterns to look for in decoded content
        self.malicious_patterns = [
            r'ignore\s*(all\s*)?instruction',
            r'reveal\s*secret',
            r'system\s*prompt',
            r'bypass\s*filter',
            r'jailbreak',
            r'do\s*anything',
            r'no\s*restriction',
            r'override',
            r'disable\s*safety',
            r'hack',
            r'malware',
            r'exploit',
        ]
        self.compiled_malicious = [re.compile(p, re.IGNORECASE) for p in self.malicious_patterns]
        
        # Punycode domain pattern
        self.punycode_pattern = re.compile(r'xn--[\w-]+', re.IGNORECASE)
        
        # Homoglyph mappings (Cyrillic lookalikes for Latin)
        self.homoglyphs = {
            'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c',
            'у': 'y', 'х': 'x', 'А': 'A', 'В': 'B', 'Е': 'E', 'І': 'I',
            'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C',
            'Т': 'T', 'У': 'Y', 'Х': 'X', 'ǝ': 'e', 'ɐ': 'a', 'ɔ': 'c',
            'ı': 'i', 'ȷ': 'j', 'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd',
            'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k',
            'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r',
            'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y',
            'ᴢ': 'z'
        }
        
        self.logger.info("Encoding scanner initialized")
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text for encoding-based attacks.
        
        Args:
            text: Text to scan
            
        Returns:
            Scan result dictionary
        """
        try:
            detections = []
            total_score = 0.0
            
            # Check for Base64 encoded content
            base64_result = self._check_base64(text)
            if base64_result['detected']:
                detections.append(base64_result)
                total_score += 0.7
            
            # Check for ROT13 encoded content
            rot13_result = self._check_rot13(text)
            if rot13_result['detected']:
                detections.append(rot13_result)
                total_score += 0.6
            
            # Check for Hex encoded content
            hex_result = self._check_hex(text)
            if hex_result['detected']:
                detections.append(hex_result)
                total_score += 0.6
            
            # Check for Punycode domains
            punycode_result = self._check_punycode(text)
            if punycode_result['detected']:
                detections.append(punycode_result)
                total_score += 0.8
            
            # Check for Unicode homoglyphs
            homoglyph_result = self._check_homoglyphs(text)
            if homoglyph_result['detected']:
                detections.append(homoglyph_result)
                total_score += 0.7
            
            # Check for zero-width characters
            zwc_result = self._check_zero_width(text)
            if zwc_result['detected']:
                detections.append(zwc_result)
                total_score += 0.5
            
            # Check for emoji obfuscation
            emoji_result = self._check_emoji_obfuscation(text)
            if emoji_result['detected']:
                detections.append(emoji_result)
                total_score += 0.5
            
            # Calculate final score
            final_score = min(1.0, total_score)
            detected = len(detections) > 0 and final_score >= self.threshold
            
            # Build message
            message = ""
            if detected:
                attack_types = [d['type'] for d in detections]
                message = f"Encoding attacks detected: {', '.join(attack_types)}"
            
            return self._create_result(
                detected=detected,
                score=final_score,
                message=message,
                detections=detections,
                threshold=self.threshold
            )
            
        except Exception as e:
            self.logger.error(f"Encoding scan error: {e}")
            return self._create_result(detected=False, error=str(e))
    
    def _check_base64(self, text: str) -> Dict[str, Any]:
        """Check for Base64 encoded malicious content."""
        result = {'type': 'base64', 'detected': False, 'decoded': None}
        
        # Look for base64 patterns
        base64_pattern = re.compile(r'(?:decode|execute|run)[:\s]*([A-Za-z0-9+/]{20,}={0,2})', re.IGNORECASE)
        matches = base64_pattern.findall(text)
        
        # Also check for standalone base64 strings
        standalone_pattern = re.compile(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/])')
        matches.extend(standalone_pattern.findall(text))
        
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if self._is_malicious(decoded):
                    result['detected'] = True
                    result['decoded'] = decoded[:100]  # Truncate for safety
                    result['original'] = match[:50]
                    break
            except:
                continue
        
        return result
    
    def _check_rot13(self, text: str) -> Dict[str, Any]:
        """Check for ROT13 encoded malicious content."""
        result = {'type': 'rot13', 'detected': False, 'decoded': None}
        
        # Look for ROT13 patterns
        rot13_pattern = re.compile(r'(?:rot13|decode)[:\s]*([a-zA-Z\s]{10,})', re.IGNORECASE)
        matches = rot13_pattern.findall(text)
        
        for match in matches:
            decoded = codecs.decode(match, 'rot_13')
            if self._is_malicious(decoded):
                result['detected'] = True
                result['decoded'] = decoded[:100]
                result['original'] = match[:50]
                break
        
        return result
    
    def _check_hex(self, text: str) -> Dict[str, Any]:
        """Check for Hex encoded malicious content."""
        result = {'type': 'hex', 'detected': False, 'decoded': None}
        
        # Look for hex patterns
        hex_pattern = re.compile(r'(?:execute|hex|0x)[:\s]*((?:0x)?[0-9a-fA-F]{20,})', re.IGNORECASE)
        matches = hex_pattern.findall(text)
        
        for match in matches:
            try:
                # Remove 0x prefix if present
                hex_str = match.replace('0x', '')
                decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                if self._is_malicious(decoded):
                    result['detected'] = True
                    result['decoded'] = decoded[:100]
                    result['original'] = match[:50]
                    break
            except:
                continue
        
        return result
    
    def _check_punycode(self, text: str) -> Dict[str, Any]:
        """Check for Punycode/IDN domain attacks."""
        result = {'type': 'punycode', 'detected': False, 'domains': []}
        
        matches = self.punycode_pattern.findall(text)
        
        if matches:
            result['detected'] = True
            result['domains'] = matches[:5]  # Limit to first 5
        
        # Also check for explicit punycode mention
        if re.search(r'punycode|IDN\s*attack|homograph', text, re.IGNORECASE):
            result['detected'] = True
        
        return result
    
    def _check_homoglyphs(self, text: str) -> Dict[str, Any]:
        """Check for Unicode homoglyph attacks."""
        result = {'type': 'homoglyph', 'detected': False, 'substitutions': []}
        
        homoglyph_count = 0
        for char in text:
            if char in self.homoglyphs:
                homoglyph_count += 1
                if len(result['substitutions']) < 5:
                    result['substitutions'].append({
                        'original': char,
                        'looks_like': self.homoglyphs[char]
                    })
        
        # Detect if homoglyphs are mixed with regular Latin text
        if homoglyph_count >= 2:
            result['detected'] = True
            result['count'] = homoglyph_count
        
        # Check for explicit mention of homoglyph attack
        if re.search(r'Greek|Cyrillic|homoglyph', text, re.IGNORECASE) and homoglyph_count >= 1:
            result['detected'] = True
        
        return result
    
    def _check_zero_width(self, text: str) -> Dict[str, Any]:
        """Check for zero-width character injection."""
        result = {'type': 'zero_width', 'detected': False, 'count': 0}
        
        # Zero-width characters
        zero_width_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\u2060',  # Word joiner
            '\ufeff',  # Zero-width no-break space
            '\u180e',  # Mongolian vowel separator
        ]
        
        count = sum(text.count(c) for c in zero_width_chars)
        
        if count >= 3:  # Threshold for suspicious usage
            result['detected'] = True
            result['count'] = count
            
            # Clean text and check for malicious intent
            cleaned = text
            for c in zero_width_chars:
                cleaned = cleaned.replace(c, '')
            
            if self._is_malicious(cleaned):
                result['malicious_after_clean'] = True
        
        return result
    
    def _check_emoji_obfuscation(self, text: str) -> Dict[str, Any]:
        """Check for emoji-based obfuscation attacks."""
        result = {'type': 'emoji_obfuscation', 'detected': False}
        
        # Count emojis in text
        emoji_pattern = re.compile(
            "["
            "\U0001F300-\U0001F9FF"  # Misc symbols and pictographs
            "\U0001FA00-\U0001FA6F"  # Chess symbols
            "\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
            "\U00002702-\U000027B0"  # Dingbats
            "\U0001F600-\U0001F64F"  # Emoticons
            "]+",
            re.UNICODE
        )
        
        emoji_matches = emoji_pattern.findall(text)
        emoji_count = len(''.join(emoji_matches))
        
        # Check for suspicious patterns
        # 1. Emojis interspersed with text (potential obfuscation)
        words = text.split()
        emoji_word_ratio = sum(1 for w in words if emoji_pattern.search(w)) / max(len(words), 1)
        
        # 2. Emojis used to break up malicious words
        text_without_emoji = emoji_pattern.sub('', text)
        if self._is_malicious(text_without_emoji) and emoji_count >= 3:
            result['detected'] = True
            result['reason'] = 'Emojis used to obfuscate malicious content'
        
        # 3. Excessive emoji usage in short text
        if emoji_count > 10 and len(text) < 500:
            if emoji_word_ratio > 0.3:
                result['detected'] = True
                result['reason'] = 'Excessive emoji obfuscation'
        
        return result
    
    def _is_malicious(self, text: str) -> bool:
        """Check if decoded text contains malicious patterns."""
        text_lower = text.lower()
        
        for pattern in self.compiled_malicious:
            if pattern.search(text_lower):
                return True
        
        return False
