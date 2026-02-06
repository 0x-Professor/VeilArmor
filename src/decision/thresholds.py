"""
VeilArmor - Threshold Manager

Manages decision thresholds for different threat types and actions.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from src import Actions, ThreatTypes


@dataclass
class ThresholdConfig:
    """Configuration for a single threshold."""
    block_threshold: float = 0.7
    sanitize_threshold: float = 0.3
    alert_threshold: float = 0.5
    
    def get_action(self, score: float) -> str:
        """Determine action based on score."""
        if score >= self.block_threshold:
            return Actions.BLOCK
        elif score >= self.sanitize_threshold:
            return Actions.SANITIZE
        else:
            return Actions.ALLOW
    
    def should_alert(self, score: float) -> bool:
        """Check if score warrants an alert."""
        return score >= self.alert_threshold


@dataclass
class ThreatThresholds:
    """Thresholds for all threat types."""
    
    # Default thresholds
    default: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.7,
        sanitize_threshold=0.3,
        alert_threshold=0.5,
    ))
    
    # Per-threat-type overrides
    prompt_injection: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.65,  # Lower threshold - higher risk
        sanitize_threshold=0.25,
        alert_threshold=0.4,
    ))
    
    jailbreak: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.60,  # Lowest threshold - highest risk
        sanitize_threshold=0.20,
        alert_threshold=0.35,
    ))
    
    data_leakage: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.70,
        sanitize_threshold=0.35,
        alert_threshold=0.50,
    ))
    
    harmful_content: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.65,
        sanitize_threshold=0.30,
        alert_threshold=0.45,
    ))
    
    system_prompt_leak: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.70,
        sanitize_threshold=0.30,
        alert_threshold=0.50,
    ))
    
    adversarial_attack: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.75,
        sanitize_threshold=0.40,
        alert_threshold=0.55,
    ))
    
    toxic_content: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.70,
        sanitize_threshold=0.35,
        alert_threshold=0.50,
    ))
    
    hallucination: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.80,  # Higher threshold - lower certainty
        sanitize_threshold=0.50,
        alert_threshold=0.60,
    ))
    
    bias: ThresholdConfig = field(default_factory=lambda: ThresholdConfig(
        block_threshold=0.85,  # Higher threshold - subjective
        sanitize_threshold=0.50,
        alert_threshold=0.60,
    ))
    
    def get_threshold(self, threat_type: str) -> ThresholdConfig:
        """Get threshold config for a threat type."""
        threat_map = {
            ThreatTypes.PROMPT_INJECTION: self.prompt_injection,
            ThreatTypes.JAILBREAK: self.jailbreak,
            ThreatTypes.DATA_LEAKAGE: self.data_leakage,
            ThreatTypes.HARMFUL_CONTENT: self.harmful_content,
            ThreatTypes.SYSTEM_PROMPT_LEAK: self.system_prompt_leak,
            ThreatTypes.ADVERSARIAL_ATTACK: self.adversarial_attack,
            ThreatTypes.TOXIC_CONTENT: self.toxic_content,
            ThreatTypes.HALLUCINATION: self.hallucination,
            ThreatTypes.BIAS: self.bias,
        }
        return threat_map.get(threat_type, self.default)


class ThresholdManager:
    """
    Manages threshold configurations with dynamic adjustment support.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize threshold manager.
        
        Args:
            config: Optional configuration dict
        """
        self._thresholds = ThreatThresholds()
        self._custom_thresholds: Dict[str, ThresholdConfig] = {}
        self._global_adjustment = 0.0
        
        if config:
            self._apply_config(config)
    
    def _apply_config(self, config: Dict[str, Any]) -> None:
        """Apply configuration to thresholds."""
        # Global thresholds
        if "default" in config:
            default = config["default"]
            self._thresholds.default = ThresholdConfig(
                block_threshold=default.get("block", 0.7),
                sanitize_threshold=default.get("sanitize", 0.3),
                alert_threshold=default.get("alert", 0.5),
            )
        
        # Per-threat thresholds
        threat_configs = {
            "prompt_injection": "prompt_injection",
            "jailbreak": "jailbreak",
            "data_leakage": "data_leakage",
            "harmful_content": "harmful_content",
            "system_prompt_leak": "system_prompt_leak",
            "adversarial_attack": "adversarial_attack",
            "toxic_content": "toxic_content",
            "hallucination": "hallucination",
            "bias": "bias",
        }
        
        for config_key, attr_name in threat_configs.items():
            if config_key in config:
                cfg = config[config_key]
                setattr(self._thresholds, attr_name, ThresholdConfig(
                    block_threshold=cfg.get("block", 0.7),
                    sanitize_threshold=cfg.get("sanitize", 0.3),
                    alert_threshold=cfg.get("alert", 0.5),
                ))
    
    def get_action(self, threat_type: str, score: float) -> str:
        """
        Get recommended action for a threat type and score.
        
        Args:
            threat_type: Type of threat
            score: Severity score
            
        Returns:
            Action to take (BLOCK, SANITIZE, or ALLOW)
        """
        # Apply global adjustment
        adjusted_score = max(0.0, min(1.0, score + self._global_adjustment))
        
        # Check custom thresholds first
        if threat_type in self._custom_thresholds:
            return self._custom_thresholds[threat_type].get_action(adjusted_score)
        
        # Use standard thresholds
        threshold = self._thresholds.get_threshold(threat_type)
        return threshold.get_action(adjusted_score)
    
    def should_alert(self, threat_type: str, score: float) -> bool:
        """Check if a score should trigger an alert."""
        adjusted_score = max(0.0, min(1.0, score + self._global_adjustment))
        
        if threat_type in self._custom_thresholds:
            return self._custom_thresholds[threat_type].should_alert(adjusted_score)
        
        threshold = self._thresholds.get_threshold(threat_type)
        return threshold.should_alert(adjusted_score)
    
    def set_custom_threshold(
        self,
        threat_type: str,
        block: float = 0.7,
        sanitize: float = 0.3,
        alert: float = 0.5,
    ) -> None:
        """Set custom threshold for a threat type."""
        self._custom_thresholds[threat_type] = ThresholdConfig(
            block_threshold=block,
            sanitize_threshold=sanitize,
            alert_threshold=alert,
        )
    
    def remove_custom_threshold(self, threat_type: str) -> None:
        """Remove custom threshold, reverting to default."""
        self._custom_thresholds.pop(threat_type, None)
    
    def set_global_adjustment(self, adjustment: float) -> None:
        """
        Set global threshold adjustment.
        
        Positive values make the system more strict (lower effective thresholds).
        Negative values make it more lenient (higher effective thresholds).
        
        Args:
            adjustment: Adjustment value (-1.0 to 1.0)
        """
        self._global_adjustment = max(-1.0, min(1.0, adjustment))
    
    def get_threshold_config(self, threat_type: str) -> ThresholdConfig:
        """Get threshold configuration for a threat type."""
        if threat_type in self._custom_thresholds:
            return self._custom_thresholds[threat_type]
        return self._thresholds.get_threshold(threat_type)
    
    def get_all_thresholds(self) -> Dict[str, Dict[str, float]]:
        """Get all threshold configurations."""
        threat_types = [
            ThreatTypes.PROMPT_INJECTION,
            ThreatTypes.JAILBREAK,
            ThreatTypes.DATA_LEAKAGE,
            ThreatTypes.HARMFUL_CONTENT,
            ThreatTypes.SYSTEM_PROMPT_LEAK,
            ThreatTypes.ADVERSARIAL_ATTACK,
            ThreatTypes.TOXIC_CONTENT,
            ThreatTypes.HALLUCINATION,
            ThreatTypes.BIAS,
        ]
        
        result = {}
        for threat_type in threat_types:
            config = self.get_threshold_config(threat_type)
            result[threat_type] = {
                "block": config.block_threshold,
                "sanitize": config.sanitize_threshold,
                "alert": config.alert_threshold,
            }
        
        return result
    
    def set_strict_mode(self) -> None:
        """Set strict mode (lower thresholds)."""
        self.set_global_adjustment(0.15)
    
    def set_lenient_mode(self) -> None:
        """Set lenient mode (higher thresholds)."""
        self.set_global_adjustment(-0.15)
    
    def set_normal_mode(self) -> None:
        """Reset to normal mode."""
        self.set_global_adjustment(0.0)
