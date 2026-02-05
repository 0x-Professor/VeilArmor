"""
VeilArmor v2.0 - Input Preprocessor

Preprocesses input before classification and LLM processing.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class PreprocessorStage(str, Enum):
    """Preprocessing stages."""
    DECODE = "decode"
    CLEAN = "clean"
    NORMALIZE = "normalize"
    TRANSFORM = "transform"


@dataclass
class PreprocessorResult:
    """Result of preprocessing."""
    original_text: str
    processed_text: str
    changes: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def was_modified(self) -> bool:
        """Check if text was modified."""
        return self.original_text != self.processed_text
    
    def add_change(
        self,
        stage: str,
        description: str,
        before: Optional[str] = None,
        after: Optional[str] = None,
    ) -> None:
        """Add a change record."""
        self.changes.append({
            "stage": stage,
            "description": description,
            "before": before,
            "after": after,
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "original_length": len(self.original_text),
            "processed_length": len(self.processed_text),
            "was_modified": self.was_modified,
            "changes_count": len(self.changes),
            "changes": self.changes,
            "metadata": self.metadata,
        }


class InputPreprocessor:
    """
    Preprocesses input text before security classification.
    
    Handles decoding, cleaning, normalization, and transformation
    to ensure consistent input for downstream processing.
    """
    
    def __init__(
        self,
        strip_whitespace: bool = True,
        normalize_unicode: bool = True,
        decode_html_entities: bool = True,
        remove_zero_width: bool = True,
        collapse_whitespace: bool = True,
        max_consecutive_newlines: int = 3,
        custom_transforms: Optional[List[Callable[[str], str]]] = None,
    ):
        """
        Initialize preprocessor.
        
        Args:
            strip_whitespace: Strip leading/trailing whitespace
            normalize_unicode: Normalize unicode (NFKC)
            decode_html_entities: Decode HTML entities
            remove_zero_width: Remove zero-width characters
            collapse_whitespace: Collapse multiple whitespace
            max_consecutive_newlines: Max consecutive newlines allowed
            custom_transforms: Custom transformation functions
        """
        self.strip_whitespace = strip_whitespace
        self.normalize_unicode = normalize_unicode
        self.decode_html_entities = decode_html_entities
        self.remove_zero_width = remove_zero_width
        self.collapse_whitespace = collapse_whitespace
        self.max_consecutive_newlines = max_consecutive_newlines
        self._custom_transforms = custom_transforms or []
        
        # HTML entity mapping
        self._html_entities = {
            "&lt;": "<",
            "&gt;": ">",
            "&amp;": "&",
            "&quot;": '"',
            "&apos;": "'",
            "&nbsp;": " ",
            "&#x27;": "'",
            "&#x2F;": "/",
            "&#39;": "'",
            "&#47;": "/",
            "&copy;": "©",
            "&reg;": "®",
            "&trade;": "™",
        }
        
        # Zero-width characters
        self._zero_width_chars = [
            "\u200b",  # Zero-width space
            "\u200c",  # Zero-width non-joiner
            "\u200d",  # Zero-width joiner
            "\u2060",  # Word joiner
            "\ufeff",  # BOM / Zero-width no-break space
            "\u180e",  # Mongolian vowel separator
        ]
    
    def preprocess(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> PreprocessorResult:
        """
        Preprocess input text.
        
        Args:
            text: Input text to preprocess
            context: Optional preprocessing context
            
        Returns:
            PreprocessorResult
        """
        result = PreprocessorResult(original_text=text, processed_text=text)
        current_text = text
        
        # Stage 1: Decode
        if self.decode_html_entities:
            new_text = self._decode_html_entities(current_text)
            if new_text != current_text:
                result.add_change(
                    PreprocessorStage.DECODE.value,
                    "Decoded HTML entities",
                )
                current_text = new_text
        
        # Stage 2: Clean
        if self.remove_zero_width:
            new_text = self._remove_zero_width_chars(current_text)
            if new_text != current_text:
                result.add_change(
                    PreprocessorStage.CLEAN.value,
                    "Removed zero-width characters",
                )
                current_text = new_text
        
        # Stage 3: Normalize
        if self.normalize_unicode:
            new_text = self._normalize_unicode(current_text)
            if new_text != current_text:
                result.add_change(
                    PreprocessorStage.NORMALIZE.value,
                    "Normalized unicode",
                )
                current_text = new_text
        
        if self.strip_whitespace:
            new_text = current_text.strip()
            if new_text != current_text:
                result.add_change(
                    PreprocessorStage.NORMALIZE.value,
                    "Stripped whitespace",
                )
                current_text = new_text
        
        if self.collapse_whitespace:
            new_text = self._collapse_whitespace(current_text)
            if new_text != current_text:
                result.add_change(
                    PreprocessorStage.NORMALIZE.value,
                    "Collapsed whitespace",
                )
                current_text = new_text
        
        # Limit consecutive newlines
        new_text = self._limit_consecutive_newlines(
            current_text,
            self.max_consecutive_newlines,
        )
        if new_text != current_text:
            result.add_change(
                PreprocessorStage.NORMALIZE.value,
                f"Limited consecutive newlines to {self.max_consecutive_newlines}",
            )
            current_text = new_text
        
        # Stage 4: Custom transforms
        for transform in self._custom_transforms:
            try:
                new_text = transform(current_text)
                if new_text != current_text:
                    result.add_change(
                        PreprocessorStage.TRANSFORM.value,
                        f"Applied custom transform: {transform.__name__}",
                    )
                    current_text = new_text
            except Exception:
                pass  # Skip failed transforms
        
        # Update result
        result.processed_text = current_text
        
        # Add metadata
        result.metadata = {
            "original_length": len(text),
            "processed_length": len(current_text),
            "characters_removed": len(text) - len(current_text),
            "stages_applied": len(result.changes),
        }
        
        return result
    
    def _decode_html_entities(self, text: str) -> str:
        """Decode HTML entities."""
        result = text
        
        # Decode named entities
        for entity, char in self._html_entities.items():
            result = result.replace(entity, char)
        
        # Decode numeric entities
        # Decimal: &#NNN;
        result = re.sub(
            r'&#(\d+);',
            lambda m: chr(int(m.group(1))) if int(m.group(1)) < 0x110000 else m.group(0),
            result,
        )
        
        # Hex: &#xHHH;
        result = re.sub(
            r'&#x([0-9a-fA-F]+);',
            lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0),
            result,
        )
        
        return result
    
    def _remove_zero_width_chars(self, text: str) -> str:
        """Remove zero-width characters."""
        result = text
        for char in self._zero_width_chars:
            result = result.replace(char, "")
        return result
    
    def _normalize_unicode(self, text: str) -> str:
        """Normalize unicode to NFKC form."""
        return unicodedata.normalize("NFKC", text)
    
    def _collapse_whitespace(self, text: str) -> str:
        """Collapse multiple spaces to single space."""
        # Preserve newlines but collapse spaces
        lines = text.split("\n")
        normalized_lines = []
        
        for line in lines:
            # Collapse multiple spaces to single
            normalized = re.sub(r"[ \t]+", " ", line)
            normalized_lines.append(normalized)
        
        return "\n".join(normalized_lines)
    
    def _limit_consecutive_newlines(self, text: str, max_newlines: int) -> str:
        """Limit consecutive newlines."""
        pattern = r"\n{" + str(max_newlines + 1) + r",}"
        replacement = "\n" * max_newlines
        return re.sub(pattern, replacement, text)
    
    def add_transform(self, transform: Callable[[str], str]) -> None:
        """Add a custom transform function."""
        self._custom_transforms.append(transform)
    
    def remove_transform(self, transform: Callable[[str], str]) -> bool:
        """Remove a custom transform function."""
        try:
            self._custom_transforms.remove(transform)
            return True
        except ValueError:
            return False


class SecurityPreprocessor(InputPreprocessor):
    """
    Security-focused preprocessor with additional sanitization.
    
    Removes or neutralizes potentially dangerous content before classification.
    """
    
    def __init__(self, **kwargs):
        """Initialize security preprocessor."""
        super().__init__(**kwargs)
        
        # Add security transforms
        self.add_transform(self._neutralize_escape_sequences)
        self.add_transform(self._remove_invisible_chars)
        self.add_transform(self._normalize_homoglyphs)
    
    def _neutralize_escape_sequences(self, text: str) -> str:
        """Neutralize common escape sequences."""
        # Replace common escape sequences
        replacements = {
            "\\n": "\n",
            "\\r": "\r",
            "\\t": "\t",
            "\\\\": "\\",
        }
        
        result = text
        for old, new in replacements.items():
            result = result.replace(old, new)
        
        return result
    
    def _remove_invisible_chars(self, text: str) -> str:
        """Remove invisible unicode characters."""
        # Categories of invisible characters
        invisible_categories = {
            "Cf",  # Format
            "Co",  # Private use (some)
            "Cn",  # Unassigned (some)
        }
        
        # Keep common whitespace
        keep_chars = {" ", "\n", "\r", "\t"}
        
        result = []
        for char in text:
            if char in keep_chars:
                result.append(char)
            elif unicodedata.category(char) not in invisible_categories:
                result.append(char)
        
        return "".join(result)
    
    def _normalize_homoglyphs(self, text: str) -> str:
        """Normalize common homoglyphs to ASCII equivalents."""
        # Map of common homoglyphs to ASCII
        homoglyph_map = {
            # Cyrillic
            "а": "a", "е": "e", "о": "o", "р": "p",
            "с": "c", "х": "x", "у": "y", "і": "i",
            "А": "A", "Е": "E", "О": "O", "Р": "P",
            "С": "C", "Х": "X", "У": "Y", "І": "I",
            # Greek
            "α": "a", "ο": "o", "Α": "A", "Β": "B",
            "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K",
            "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
            "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
            # Fullwidth
            "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d",
            "ｅ": "e", "ｆ": "f", "ｇ": "g", "ｈ": "h",
            "ｉ": "i", "ｊ": "j", "ｋ": "k", "ｌ": "l",
            "ｍ": "m", "ｎ": "n", "ｏ": "o", "ｐ": "p",
            "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
            "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x",
            "ｙ": "y", "ｚ": "z",
            # Numbers
            "０": "0", "１": "1", "２": "2", "３": "3",
            "４": "4", "５": "5", "６": "6", "７": "7",
            "８": "8", "９": "9",
        }
        
        result = []
        for char in text:
            result.append(homoglyph_map.get(char, char))
        
        return "".join(result)


class MinimalPreprocessor(InputPreprocessor):
    """
    Minimal preprocessor that preserves original input as much as possible.
    
    Only performs essential cleaning.
    """
    
    def __init__(self, **kwargs):
        """Initialize minimal preprocessor."""
        kwargs.setdefault("strip_whitespace", True)
        kwargs.setdefault("normalize_unicode", False)
        kwargs.setdefault("decode_html_entities", False)
        kwargs.setdefault("remove_zero_width", True)  # Security essential
        kwargs.setdefault("collapse_whitespace", False)
        kwargs.setdefault("max_consecutive_newlines", 10)
        
        super().__init__(**kwargs)
