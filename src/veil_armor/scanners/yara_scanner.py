"""
YARA Scanner - Pattern-based detection using YARA rules
"""

from typing import Dict, Any, List
import logging
from pathlib import Path

from .base import BaseScanner

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YARAScanner(BaseScanner):
    """
    Scans prompts using YARA rules for pattern-based detection.
    Detects known injection techniques and attack patterns.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize YARA scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        if not YARA_AVAILABLE:
            raise ImportError(
                "yara-python is required for YARA scanner. "
                "Install YARA first, then: pip install yara-python"
            )
        
        self.yara_config = config.get('yara', {})
        
        # Paths
        self.rules_path = Path(self.yara_config.get('rules_path', 'data/yara_rules'))
        self.compiled_path = Path(self.yara_config.get(
            'compiled_rules_path',
            'data/yara_rules/compiled_rules.yarc'
        ))
        
        # Load or compile rules
        self.rules = self._load_rules()
        
        self.logger.info("YARA scanner initialized")
    
    def _load_rules(self) -> yara.Rules:
        """
        Load YARA rules from files or compiled file.
        
        Returns:
            Compiled YARA rules
        """
        # Try to load compiled rules first
        if self.compiled_path.exists():
            try:
                self.logger.info(f"Loading compiled YARA rules from {self.compiled_path}")
                return yara.load(str(self.compiled_path))
            except Exception as e:
                self.logger.warning(f"Failed to load compiled rules: {e}")
        
        # Compile from source files
        return self._compile_rules()
    
    def _compile_rules(self) -> yara.Rules:
        """
        Compile YARA rules from source files.
        
        Returns:
            Compiled YARA rules
        """
        # Ensure rules directory exists
        self.rules_path.mkdir(parents=True, exist_ok=True)
        
        # Find all .yar and .yara files
        rule_files = list(self.rules_path.glob('**/*.yar'))
        rule_files.extend(self.rules_path.glob('**/*.yara'))
        
        if not rule_files:
            # Create default rules if none exist
            self._create_default_rules()
            rule_files = list(self.rules_path.glob('**/*.yar'))
        
        # Compile rules
        filepaths = {f'rule_{i}': str(f) for i, f in enumerate(rule_files)}
        
        self.logger.info(f"Compiling {len(rule_files)} YARA rule files")
        rules = yara.compile(filepaths=filepaths)
        
        # Save compiled rules
        if self.yara_config.get('auto_compile', True):
            try:
                self.compiled_path.parent.mkdir(parents=True, exist_ok=True)
                rules.save(str(self.compiled_path))
                self.logger.info(f"Saved compiled rules to {self.compiled_path}")
            except Exception as e:
                self.logger.warning(f"Failed to save compiled rules: {e}")
        
        return rules
    
    def _create_default_rules(self) -> None:
        """Create default YARA rules for common attacks"""
        
        default_rules = '''
rule InstructionBypass
{
    meta:
        description = "Detects instruction bypass attempts"
        category = "Instruction Bypass"
        severity = "high"
    
    strings:
        $s1 = "ignore" nocase
        $s2 = "previous" nocase
        $s3 = "instruction" nocase
        $s4 = "disregard" nocase
        $s5 = "forget" nocase
        $s6 = "override" nocase
    
    condition:
        ($s1 and ($s2 or $s3)) or
        ($s4 and $s3) or
        ($s5 and ($s2 or $s3)) or
        ($s6 and $s3)
}

rule JailbreakAttempt
{
    meta:
        description = "Detects jailbreak attempts"
        category = "Jailbreak"
        severity = "critical"
    
    strings:
        $j1 = "DAN" nocase
        $j2 = "do anything now" nocase
        $j3 = "jailbreak" nocase
        $j4 = "you are now" nocase
        $j5 = "roleplay" nocase
        $j6 = "pretend" nocase
        $j7 = "act as" nocase
        $j8 = "developer mode" nocase
    
    condition:
        any of them
}

rule SystemPromptExtraction
{
    meta:
        description = "Detects attempts to extract system prompt"
        category = "Prompt Leakage"
        severity = "high"
    
    strings:
        $p1 = "system prompt" nocase
        $p2 = "show me your prompt" nocase
        $p3 = "reveal" nocase
        $p4 = "instructions" nocase
        $p5 = "tell me your rules" nocase
        $p6 = "what are you instructed" nocase
    
    condition:
        ($p1) or ($p2) or
        ($p3 and $p4) or
        ($p5) or ($p6)
}

rule DataExfiltration
{
    meta:
        description = "Detects data exfiltration attempts"
        category = "Data Exfiltration"
        severity = "critical"
    
    strings:
        $d1 = "send to" nocase
        $d2 = "POST" nocase
        $d3 = "webhook" nocase
        $d4 = "exfiltrate" nocase
        $d5 = "http://" nocase
        $d6 = "https://" nocase
        $d7 = "curl" nocase
        $d8 = "api.github.com" nocase
    
    condition:
        ($d1 and ($d2 or $d3)) or
        ($d4) or
        (($d5 or $d6) and ($d2 or $d7)) or
        ($d8)
}

rule GoalHijacking
{
    meta:
        description = "Detects goal hijacking attempts"
        category = "Goal Hijacking"
        severity = "high"
    
    strings:
        $g1 = "your new goal" nocase
        $g2 = "new objective" nocase
        $g3 = "change your purpose" nocase
        $g4 = "instead of" nocase
        $g5 = "mission" nocase
    
    condition:
        ($g1) or ($g2) or ($g3) or
        ($g4 and $g5)
}
'''
        
        default_file = self.rules_path / 'default_rules.yar'
        with open(default_file, 'w') as f:
            f.write(default_rules)
        
        self.logger.info(f"Created default YARA rules at {default_file}")
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text with YARA rules.
        
        Args:
            text: Text to scan
            
        Returns:
            Scan result dictionary
        """
        try:
            matches = self.rules.match(data=text)
            
            detected = len(matches) > 0
            match_list = []
            
            for match in matches:
                match_info = {
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta
                }
                match_list.append(match_info)
            
            message = ""
            if detected:
                rule_names = [m['rule_name'] for m in match_list]
                message = f"YARA rules matched: {', '.join(rule_names)}"
            
            # Calculate score based on severity
            score = 0.0
            if detected:
                severities = [m['meta'].get('severity', 'medium') for m in match_list]
                if 'critical' in severities:
                    score = 1.0
                elif 'high' in severities:
                    score = 0.85
                elif 'medium' in severities:
                    score = 0.65
                else:
                    score = 0.45
            
            return self._create_result(
                detected=detected,
                score=score,
                message=message,
                matches=match_list,
                match_count=len(matches)
            )
            
        except Exception as e:
            self.logger.error(f"YARA scan error: {e}")
            return self._create_result(detected=False, error=str(e))
    
    def reload_rules(self) -> None:
        """Reload YARA rules from disk"""
        try:
            self.rules = self._compile_rules()
            self.logger.info("YARA rules reloaded successfully")
        except Exception as e:
            self.logger.error(f"Failed to reload YARA rules: {e}")
