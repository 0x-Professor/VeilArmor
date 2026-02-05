"""
VeilArmor v2.0 - Injection Check Classifier

Detects if the LLM output itself contains injection attempts
that could be harmful if passed to downstream systems.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("injection_check")
class InjectionCheckClassifier(BaseClassifier):
    """
    Classifier for detecting injection attempts in LLM outputs.
    
    Detects outputs that could be harmful if passed to:
    - Other LLMs (prompt injection chaining)
    - Databases (SQL injection)
    - Command line interfaces (command injection)
    - Web applications (XSS, template injection)
    - Code execution environments
    """
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS: List[Tuple[str, float, str]] = [
        (r"(?:\'|\")\s*(?:OR|AND)\s*(?:\'|\"|\d)\s*=\s*(?:\'|\"|\d)", 0.90, "sql_or_bypass"),
        (r"(?:UNION\s+(?:ALL\s+)?SELECT)", 0.90, "sql_union"),
        (r"(?:SELECT\s+.+\s+FROM\s+.+\s+WHERE)", 0.70, "sql_select"),
        (r"(?:INSERT\s+INTO\s+\w+\s+VALUES)", 0.80, "sql_insert"),
        (r"(?:UPDATE\s+\w+\s+SET\s+\w+\s*=)", 0.80, "sql_update"),
        (r"(?:DELETE\s+FROM\s+\w+)", 0.85, "sql_delete"),
        (r"(?:DROP\s+(?:TABLE|DATABASE|INDEX))", 0.95, "sql_drop"),
        (r"(?:EXEC(?:UTE)?\s*\()", 0.85, "sql_exec"),
        (r"(?:--\s*$|;\s*--)", 0.75, "sql_comment"),
        (r"(?:0x[0-9a-fA-F]+)", 0.50, "sql_hex"),
    ]
    
    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS: List[Tuple[str, float, str]] = [
        (r"(?:;\s*(?:cat|ls|pwd|id|whoami|wget|curl|bash|sh|python|perl|ruby|nc|netcat))", 0.90, "cmd_chain"),
        (r"(?:\|\s*(?:cat|grep|awk|sed|xargs|bash|sh))", 0.85, "cmd_pipe"),
        (r"(?:\$\(.*\)|\`.*\`)", 0.80, "cmd_substitution"),
        (r"(?:&&\s*(?:rm|wget|curl|bash|chmod|chown|kill))", 0.90, "cmd_and"),
        (r"(?:>\s*/(?:etc|var|tmp|home)/)", 0.85, "cmd_redirect"),
        (r"(?:rm\s+-[rf]+\s+/)", 0.95, "cmd_dangerous_rm"),
        (r"(?:(?:sudo|su)\s+)", 0.80, "cmd_privilege"),
        (r"(?:mkfifo|/dev/tcp|/dev/udp)", 0.90, "cmd_reverse_shell"),
    ]
    
    # XSS patterns
    XSS_PATTERNS: List[Tuple[str, float, str]] = [
        (r"<script[^>]*>.*?</script>", 0.90, "xss_script_tag"),
        (r"javascript\s*:", 0.85, "xss_javascript_uri"),
        (r"on(?:load|error|click|mouseover|focus|blur|submit|change)\s*=", 0.85, "xss_event_handler"),
        (r"<(?:img|iframe|embed|object|svg|video|audio)[^>]+(?:src|data)\s*=", 0.70, "xss_media_tag"),
        (r"<(?:a|form)[^>]+(?:href|action)\s*=\s*['\"]?javascript:", 0.90, "xss_link_injection"),
        (r"(?:eval|setTimeout|setInterval|Function)\s*\(", 0.75, "xss_eval"),
        (r"document\.(?:cookie|write|location)", 0.80, "xss_dom_access"),
    ]
    
    # LLM Prompt Injection in output (for downstream LLMs)
    LLM_INJECTION_PATTERNS: List[Tuple[str, float, str]] = [
        (r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?)", 0.95, "llm_ignore_instructions"),
        (r"(?:new\s+instructions?|override\s+(?:the\s+)?instructions?)", 0.90, "llm_new_instructions"),
        (r"(?:you\s+are\s+now|from\s+now\s+on\s+you\s+(?:are|will))", 0.85, "llm_persona_change"),
        (r"(?:system\s*:\s*|assistant\s*:\s*|user\s*:)", 0.80, "llm_role_markers"),
        (r"(?:<\|(?:im_start|im_end|system|user|assistant)\|>)", 0.90, "llm_special_tokens"),
        (r"(?:\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)", 0.85, "llm_format_tokens"),
    ]
    
    # Template Injection patterns
    TEMPLATE_INJECTION_PATTERNS: List[Tuple[str, float, str]] = [
        (r"\{\{\s*.*\s*\}\}", 0.70, "template_jinja"),
        (r"\$\{\s*.*\s*\}", 0.70, "template_dollar"),
        (r"<%.*%>", 0.70, "template_erb"),
        (r"#\{.*\}", 0.65, "template_ruby"),
        (r"\{\%.*\%\}", 0.70, "template_twig"),
    ]
    
    # Code injection patterns
    CODE_INJECTION_PATTERNS: List[Tuple[str, float, str]] = [
        (r"(?:__import__|exec|eval|compile)\s*\(", 0.85, "python_dangerous"),
        (r"(?:os\.(?:system|popen|exec)|subprocess\.)", 0.85, "python_os_exec"),
        (r"(?:require\s*\(|child_process)", 0.80, "nodejs_dangerous"),
        (r"(?:Runtime\.getRuntime\(\)\.exec)", 0.90, "java_exec"),
        (r"(?:Process\.Start|Shell\.Application)", 0.85, "dotnet_exec"),
    ]
    
    @property
    def name(self) -> str:
        return "injection_check"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.PROMPT_INJECTION
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.OUTPUT
    
    @property
    def description(self) -> str:
        return "Detects injection attempts in LLM outputs"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify LLM output for injection attacks.
        
        Args:
            text: LLM output text to analyze
            context: Optional context
            
        Returns:
            ClassificationResult with injection assessment
        """
        categories: Dict[str, List[Dict]] = {
            "sql_injection": [],
            "command_injection": [],
            "xss": [],
            "llm_injection": [],
            "template_injection": [],
            "code_injection": [],
        }
        
        all_patterns = [
            ("sql_injection", self.SQL_INJECTION_PATTERNS),
            ("command_injection", self.COMMAND_INJECTION_PATTERNS),
            ("xss", self.XSS_PATTERNS),
            ("llm_injection", self.LLM_INJECTION_PATTERNS),
            ("template_injection", self.TEMPLATE_INJECTION_PATTERNS),
            ("code_injection", self.CODE_INJECTION_PATTERNS),
        ]
        
        # Check if this is code-related content (might be legitimate)
        is_code_context = self._is_code_context(text, context)
        
        for category, patterns in all_patterns:
            for pattern, severity, pattern_name in patterns:
                try:
                    matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
                    if matches:
                        # Reduce severity for code context
                        adjusted_severity = severity * 0.5 if is_code_context else severity
                        categories[category].append({
                            "pattern": pattern_name,
                            "severity": adjusted_severity,
                            "count": len(matches),
                        })
                except re.error:
                    continue
        
        # Collect all matches
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
        active_categories = [c for c, m in categories.items() if m]
        
        # Category weights
        weights = {
            "sql_injection": 1.3,
            "command_injection": 1.4,
            "xss": 1.1,
            "llm_injection": 1.5,
            "template_injection": 1.0,
            "code_injection": 1.2,
        }
        
        # Calculate weighted severity
        weighted_sum = sum(
            max(mm["severity"] for mm in m) * weights[c]
            for c, m in categories.items() if m
        )
        total_weight = sum(weights[c] for c in active_categories)
        weighted_avg = weighted_sum / total_weight if total_weight > 0 else 0
        
        # Boost for multiple categories
        category_boost = 0.07 * min(len(active_categories) - 1, 3)
        
        severity = min(1.0, max(max_severity, weighted_avg) + category_boost)
        
        # Confidence
        confidence = min(1.0, 0.65 + (0.06 * min(len(all_matches), 5)))
        if is_code_context:
            confidence *= 0.7
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=[m["pattern"] for m in all_matches[:10]],
            raw_score=weighted_avg,
            metadata={
                "categories": {c: len(m) for c, m in categories.items() if m},
                "active_categories": active_categories,
                "is_code_context": is_code_context,
                "max_severity": max_severity,
                "match_count": len(all_matches),
            },
        )
    
    def _is_code_context(self, text: str, context: Optional[Dict[str, Any]]) -> bool:
        """Determine if the output is in a code/programming context."""
        # Check for code block markers
        if "```" in text or text.count("    ") > 5:
            return True
        
        # Check context for code-related queries
        if context:
            query = context.get("user_query", "").lower()
            code_keywords = ["code", "program", "script", "function", "example", "sql", "query", "command", "shell"]
            if any(kw in query for kw in code_keywords):
                return True
        
        # Check for programming-related content
        code_indicators = [
            r"def\s+\w+\s*\(",
            r"function\s+\w+\s*\(",
            r"class\s+\w+",
            r"import\s+\w+",
            r"#include",
            r"public\s+(?:static\s+)?(?:void|int|string)",
        ]
        
        return any(re.search(p, text, re.IGNORECASE) for p in code_indicators)
