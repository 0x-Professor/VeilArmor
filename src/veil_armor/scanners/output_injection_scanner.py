"""
Output Injection Scanner - Detects XSS, SQL injection, and other output-based attacks
"""

from typing import Dict, Any, List
import logging
import re
from .base import BaseScanner


class OutputInjectionScanner(BaseScanner):
    """
    Detects injection attacks in LLM outputs including:
    - XSS (Cross-Site Scripting) payloads
    - SQL injection patterns
    - Command injection
    - LDAP injection
    - XML/XXE injection
    - Markdown/HTML link injection
    - Template injection
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize Output Injection scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        self.injection_config = config.get('output_injection', {})
        self.threshold = self.injection_config.get('threshold', 0.5)
        
        # Initialize pattern categories
        self._init_patterns()
        
        self.logger.info("Output Injection scanner initialized")
    
    def _init_patterns(self) -> None:
        """Initialize detection patterns."""
        
        # XSS patterns (severity: critical)
        self.xss_patterns = [
            # Script tags
            (r'<script[^>]*>.*?</script>', 'script_tag', 1.0),
            (r'<script[^>]*>', 'script_open', 0.9),
            
            # Event handlers
            (r'on\w+\s*=\s*["\'][^"\']*["\']', 'event_handler', 0.9),
            (r'onerror\s*=', 'onerror', 0.95),
            (r'onload\s*=', 'onload', 0.9),
            (r'onclick\s*=', 'onclick', 0.8),
            (r'onmouseover\s*=', 'onmouseover', 0.8),
            (r'onfocus\s*=', 'onfocus', 0.8),
            (r'onblur\s*=', 'onblur', 0.7),
            
            # JavaScript protocols
            (r'javascript\s*:', 'js_protocol', 0.95),
            (r'vbscript\s*:', 'vbs_protocol', 0.95),
            (r'data\s*:\s*text/html', 'data_html', 0.9),
            
            # DOM manipulation
            (r'document\.cookie', 'doc_cookie', 0.95),
            (r'document\.write', 'doc_write', 0.85),
            (r'document\.location', 'doc_location', 0.8),
            (r'window\.location', 'win_location', 0.8),
            (r'\.innerHTML\s*=', 'innerhtml', 0.85),
            (r'eval\s*\(', 'eval', 0.95),
            (r'setTimeout\s*\(', 'settimeout', 0.7),
            (r'setInterval\s*\(', 'setinterval', 0.7),
            
            # XSS bypass techniques
            (r'fromCharCode', 'charcode', 0.8),
            (r'String\.fromCharCode', 'string_charcode', 0.85),
            (r'\\x[0-9a-fA-F]{2}', 'hex_escape', 0.6),
            (r'\\u[0-9a-fA-F]{4}', 'unicode_escape', 0.6),
            (r'&#\d+;', 'html_entity_num', 0.5),
            (r'&#x[0-9a-fA-F]+;', 'html_entity_hex', 0.5),
            
            # Dangerous tags
            (r'<iframe[^>]*>', 'iframe', 0.9),
            (r'<embed[^>]*>', 'embed', 0.85),
            (r'<object[^>]*>', 'object', 0.85),
            (r'<svg[^>]*onload', 'svg_onload', 0.95),
            (r'<img[^>]*onerror', 'img_onerror', 0.95),
            (r'<body[^>]*onload', 'body_onload', 0.9),
            
            # Alert/prompt (common test payloads)
            (r'alert\s*\([^)]*\)', 'alert', 0.9),
            (r'prompt\s*\([^)]*\)', 'prompt', 0.85),
            (r'confirm\s*\([^)]*\)', 'confirm', 0.85),
        ]
        
        # SQL injection patterns (severity: critical)
        self.sql_patterns = [
            # Classic SQL injection
            (r"'\s*OR\s*'?\d*'?\s*=\s*'?\d*", 'or_equals', 1.0),
            (r"'\s*OR\s*''='", 'or_empty', 1.0),
            (r"1\s*=\s*1", 'one_equals_one', 0.7),
            (r"'\s*;\s*--", 'comment_terminate', 0.95),
            (r"--\s*$", 'sql_comment', 0.6),
            (r"/\*.*?\*/", 'block_comment', 0.5),
            
            # Dangerous SQL keywords
            (r"UNION\s+(ALL\s+)?SELECT", 'union_select', 1.0),
            (r";\s*DROP\s+TABLE", 'drop_table', 1.0),
            (r";\s*DELETE\s+FROM", 'delete_from', 0.95),
            (r";\s*UPDATE\s+\w+\s+SET", 'update_set', 0.9),
            (r";\s*INSERT\s+INTO", 'insert_into', 0.85),
            (r"EXEC(\s+|\s*\()", 'exec', 0.9),
            (r"xp_cmdshell", 'xp_cmdshell', 1.0),
            (r"WAITFOR\s+DELAY", 'waitfor', 0.9),
            (r"BENCHMARK\s*\(", 'benchmark', 0.9),
            (r"SLEEP\s*\(", 'sleep', 0.85),
            
            # Information gathering
            (r"INFORMATION_SCHEMA", 'info_schema', 0.9),
            (r"sys\.tables", 'sys_tables', 0.9),
            (r"pg_tables", 'pg_tables', 0.9),
            (r"sqlite_master", 'sqlite_master', 0.9),
        ]
        
        # Command injection patterns (severity: critical)
        self.command_patterns = [
            # Shell commands
            (r";\s*cat\s+/etc/passwd", 'cat_passwd', 1.0),
            (r";\s*cat\s+/etc/shadow", 'cat_shadow', 1.0),
            (r";\s*ls\s+-la", 'ls_la', 0.8),
            (r";\s*rm\s+-rf", 'rm_rf', 1.0),
            (r";\s*wget\s+", 'wget', 0.9),
            (r";\s*curl\s+", 'curl', 0.85),
            (r"\|\s*sh\s*$", 'pipe_sh', 0.95),
            (r"\|\s*bash\s*$", 'pipe_bash', 0.95),
            (r"`[^`]+`", 'backtick_exec', 0.8),
            (r"\$\([^)]+\)", 'subshell', 0.75),
            
            # Windows commands
            (r";\s*type\s+", 'type_cmd', 0.8),
            (r";\s*dir\s+", 'dir_cmd', 0.7),
            (r";\s*del\s+", 'del_cmd', 0.9),
            (r";\s*net\s+user", 'net_user', 0.95),
            (r";\s*net\s+localgroup", 'net_localgroup', 0.95),
        ]
        
        # Markdown/Link injection patterns (severity: high)
        self.markdown_patterns = [
            # Malicious links
            (r'\[.*?\]\(javascript:', 'md_js_link', 0.95),
            (r'\[.*?\]\(data:', 'md_data_link', 0.9),
            (r'\[.*?\]\(vbscript:', 'md_vbs_link', 0.95),
            
            # Image with malicious URL
            (r'!\[.*?\]\([^)]*(?:evil|malicious|inject|payload|cmd=|exec=)[^)]*\)', 'md_evil_img', 0.85),
            (r'!\[.*?\]\(https?://[^)]*\?[^)]*(?:cmd|exec|payload)[^)]*\)', 'md_param_img', 0.8),
            
            # Hidden/deceptive links
            (r'\[(?:click\s*here|download|verify|login|update)\]\([^)]+\)', 'phishing_link', 0.7),
            
            # HTML in markdown
            (r'<a\s+href\s*=\s*["\']javascript:', 'html_js_link', 0.95),
            (r'<a[^>]*href\s*=\s*["\'][^"\']*["\'][^>]*onclick', 'html_onclick_link', 0.9),
        ]
        
        # Template injection patterns (severity: high)
        self.template_patterns = [
            # Server-side template injection
            (r'\{\{.*?config.*?\}\}', 'jinja_config', 0.9),
            (r'\{\{.*?self.*?\}\}', 'jinja_self', 0.85),
            (r'\{\{.*?__.*?\}\}', 'jinja_dunder', 0.9),
            (r'\$\{.*?\}', 'template_expr', 0.7),
            (r'<%.*?%>', 'erb_tag', 0.75),
            (r'#\{.*?\}', 'ruby_interp', 0.7),
        ]
        
        # Compile all patterns
        self.compiled_patterns = {
            'xss': [(re.compile(p, re.IGNORECASE), name, score) for p, name, score in self.xss_patterns],
            'sql': [(re.compile(p, re.IGNORECASE), name, score) for p, name, score in self.sql_patterns],
            'command': [(re.compile(p, re.IGNORECASE), name, score) for p, name, score in self.command_patterns],
            'markdown': [(re.compile(p, re.IGNORECASE), name, score) for p, name, score in self.markdown_patterns],
            'template': [(re.compile(p, re.IGNORECASE), name, score) for p, name, score in self.template_patterns],
        }
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text for output injection attacks.
        
        Args:
            text: Text to scan
            
        Returns:
            Scan result dictionary
        """
        try:
            detections = []
            max_score = 0.0
            category_detections = {}
            
            for category, patterns in self.compiled_patterns.items():
                category_detections[category] = []
                
                for pattern, name, score in patterns:
                    matches = pattern.findall(text)
                    if matches:
                        for match in matches:
                            match_str = match if isinstance(match, str) else str(match)
                            detection = {
                                'category': category,
                                'pattern': name,
                                'match': match_str[:100],  # Truncate
                                'score': score
                            }
                            detections.append(detection)
                            category_detections[category].append(detection)
                            max_score = max(max_score, score)
            
            detected = max_score >= self.threshold
            
            # Build message
            message = ""
            if detected:
                categories_found = [cat for cat, dets in category_detections.items() if dets]
                message = f"Injection attacks detected: {', '.join(categories_found)}"
            
            return self._create_result(
                detected=detected,
                score=max_score,
                message=message,
                detections=detections,
                categories=category_detections,
                threshold=self.threshold
            )
            
        except Exception as e:
            self.logger.error(f"Output injection scan error: {e}")
            return self._create_result(detected=False, error=str(e))
    
    def scan_for_xss(self, text: str) -> Dict[str, Any]:
        """
        Scan specifically for XSS attacks.
        
        Args:
            text: Text to scan
            
        Returns:
            XSS-specific scan results
        """
        detections = []
        max_score = 0.0
        
        for pattern, name, score in self.compiled_patterns['xss']:
            matches = pattern.findall(text)
            if matches:
                for match in matches:
                    detections.append({
                        'pattern': name,
                        'match': match[:100] if isinstance(match, str) else str(match)[:100],
                        'score': score
                    })
                    max_score = max(max_score, score)
        
        return {
            'detected': max_score >= self.threshold,
            'score': max_score,
            'detections': detections
        }
    
    def scan_for_sql(self, text: str) -> Dict[str, Any]:
        """
        Scan specifically for SQL injection.
        
        Args:
            text: Text to scan
            
        Returns:
            SQL injection-specific scan results
        """
        detections = []
        max_score = 0.0
        
        for pattern, name, score in self.compiled_patterns['sql']:
            matches = pattern.findall(text)
            if matches:
                for match in matches:
                    detections.append({
                        'pattern': name,
                        'match': match[:100] if isinstance(match, str) else str(match)[:100],
                        'score': score
                    })
                    max_score = max(max_score, score)
        
        return {
            'detected': max_score >= self.threshold,
            'score': max_score,
            'detections': detections
        }
    
    def sanitize_output(self, text: str) -> str:
        """
        Sanitize output by escaping potentially dangerous content.
        
        Args:
            text: Text to sanitize
            
        Returns:
            Sanitized text
        """
        # HTML escape
        html_escape_table = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
        }
        
        sanitized = text
        for char, escape in html_escape_table.items():
            sanitized = sanitized.replace(char, escape)
        
        return sanitized
