"""
VeilArmor v2.0 - Rule Engine

Configurable rule-based decision making with conditions and actions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
import re

from src import Actions, ThreatTypes
from src.classifiers.base import ClassificationResult


class RuleOperator(str, Enum):
    """Operators for rule conditions."""
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUALS = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUALS = "lte"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"  # Regex match
    IN = "in"
    NOT_IN = "not_in"


@dataclass
class RuleCondition:
    """
    A single condition in a rule.
    
    Examples:
        - severity >= 0.7
        - threat_type in ["prompt_injection", "jailbreak"]
        - matched_patterns contains "sql_injection"
    """
    field: str
    operator: RuleOperator
    value: Any
    
    def evaluate(self, data: Dict[str, Any]) -> bool:
        """
        Evaluate condition against data.
        
        Args:
            data: Data dict to evaluate against
            
        Returns:
            True if condition is met
        """
        actual_value = self._get_field_value(data)
        
        if actual_value is None:
            return False
        
        try:
            if self.operator == RuleOperator.EQUALS:
                return actual_value == self.value
            elif self.operator == RuleOperator.NOT_EQUALS:
                return actual_value != self.value
            elif self.operator == RuleOperator.GREATER_THAN:
                return actual_value > self.value
            elif self.operator == RuleOperator.GREATER_THAN_OR_EQUALS:
                return actual_value >= self.value
            elif self.operator == RuleOperator.LESS_THAN:
                return actual_value < self.value
            elif self.operator == RuleOperator.LESS_THAN_OR_EQUALS:
                return actual_value <= self.value
            elif self.operator == RuleOperator.CONTAINS:
                if isinstance(actual_value, str):
                    return self.value in actual_value
                elif isinstance(actual_value, (list, set, tuple)):
                    return self.value in actual_value
                return False
            elif self.operator == RuleOperator.NOT_CONTAINS:
                if isinstance(actual_value, str):
                    return self.value not in actual_value
                elif isinstance(actual_value, (list, set, tuple)):
                    return self.value not in actual_value
                return True
            elif self.operator == RuleOperator.MATCHES:
                if isinstance(actual_value, str):
                    return bool(re.search(self.value, actual_value, re.IGNORECASE))
                return False
            elif self.operator == RuleOperator.IN:
                return actual_value in self.value
            elif self.operator == RuleOperator.NOT_IN:
                return actual_value not in self.value
            else:
                return False
        except (TypeError, ValueError):
            return False
    
    def _get_field_value(self, data: Dict[str, Any]) -> Any:
        """Get field value from data, supporting nested fields."""
        parts = self.field.split(".")
        value = data
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value


@dataclass
class Rule:
    """
    A rule with conditions and actions.
    
    Rules can have multiple conditions (AND logic by default)
    and specify an action to take when conditions are met.
    """
    name: str
    conditions: List[RuleCondition]
    action: str
    priority: int = 0  # Higher priority rules are evaluated first
    enabled: bool = True
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Logic for combining conditions
    require_all: bool = True  # True = AND, False = OR
    
    def evaluate(self, data: Dict[str, Any]) -> bool:
        """
        Evaluate all conditions against data.
        
        Args:
            data: Data to evaluate
            
        Returns:
            True if rule matches
        """
        if not self.enabled or not self.conditions:
            return False
        
        if self.require_all:
            return all(c.evaluate(data) for c in self.conditions)
        else:
            return any(c.evaluate(data) for c in self.conditions)
    
    @classmethod
    def block_on_high_severity(cls, threat_type: str, threshold: float = 0.8) -> "Rule":
        """Create a rule to block high severity threats."""
        return cls(
            name=f"block_{threat_type}_high_severity",
            conditions=[
                RuleCondition("threat_type", RuleOperator.EQUALS, threat_type),
                RuleCondition("severity", RuleOperator.GREATER_THAN_OR_EQUALS, threshold),
            ],
            action=Actions.BLOCK,
            priority=100,
            description=f"Block {threat_type} with severity >= {threshold}",
        )
    
    @classmethod
    def sanitize_on_pattern(cls, threat_type: str, pattern: str) -> "Rule":
        """Create a rule to sanitize when a pattern is matched."""
        return cls(
            name=f"sanitize_{threat_type}_{pattern}",
            conditions=[
                RuleCondition("threat_type", RuleOperator.EQUALS, threat_type),
                RuleCondition("matched_patterns", RuleOperator.CONTAINS, pattern),
            ],
            action=Actions.SANITIZE,
            priority=50,
            description=f"Sanitize {threat_type} when {pattern} detected",
        )


class RuleEngine:
    """
    Rule engine for evaluating rules against classification results.
    """
    
    def __init__(self):
        """Initialize rule engine."""
        self._rules: List[Rule] = []
        self._custom_actions: Dict[str, Callable[[Dict[str, Any]], str]] = {}
    
    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine."""
        self._rules.append(rule)
        # Sort by priority (descending)
        self._rules.sort(key=lambda r: r.priority, reverse=True)
    
    def add_rules(self, rules: List[Rule]) -> None:
        """Add multiple rules."""
        self._rules.extend(rules)
        self._rules.sort(key=lambda r: r.priority, reverse=True)
    
    def remove_rule(self, name: str) -> bool:
        """Remove a rule by name."""
        for i, rule in enumerate(self._rules):
            if rule.name == name:
                self._rules.pop(i)
                return True
        return False
    
    def enable_rule(self, name: str) -> bool:
        """Enable a rule by name."""
        for rule in self._rules:
            if rule.name == name:
                rule.enabled = True
                return True
        return False
    
    def disable_rule(self, name: str) -> bool:
        """Disable a rule by name."""
        for rule in self._rules:
            if rule.name == name:
                rule.enabled = False
                return True
        return False
    
    def evaluate(
        self,
        result: ClassificationResult,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Evaluate rules against a classification result.
        
        Args:
            result: Classification result
            context: Additional context
            
        Returns:
            Action from first matching rule, or None if no match
        """
        data = self._result_to_dict(result, context)
        
        for rule in self._rules:
            if rule.evaluate(data):
                return rule.action
        
        return None
    
    def evaluate_all(
        self,
        results: List[ClassificationResult],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, List[Rule]]:
        """
        Evaluate rules against all classification results.
        
        Args:
            results: List of classification results
            context: Additional context
            
        Returns:
            Dict mapping actions to matching rules
        """
        matched: Dict[str, List[Rule]] = {
            Actions.BLOCK: [],
            Actions.SANITIZE: [],
            Actions.ALLOW: [],
            Actions.FLAG: [],
        }
        
        for result in results:
            data = self._result_to_dict(result, context)
            
            for rule in self._rules:
                if rule.evaluate(data):
                    if rule.action in matched:
                        matched[rule.action].append(rule)
        
        return matched
    
    def get_first_match(
        self,
        results: List[ClassificationResult],
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[tuple]:
        """
        Get first matching rule across all results.
        
        Returns:
            Tuple of (rule, result) or None
        """
        for result in results:
            data = self._result_to_dict(result, context)
            
            for rule in self._rules:
                if rule.evaluate(data):
                    return (rule, result)
        
        return None
    
    def _result_to_dict(
        self,
        result: ClassificationResult,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Convert classification result to dict for rule evaluation."""
        data = {
            "threat_type": result.threat_type,
            "severity": result.severity,
            "confidence": result.confidence,
            "matched_patterns": result.matched_patterns,
            "raw_score": result.raw_score,
            "metadata": result.metadata,
        }
        
        if context:
            data["context"] = context
        
        return data
    
    def register_custom_action(
        self,
        name: str,
        handler: Callable[[Dict[str, Any]], str],
    ) -> None:
        """Register a custom action handler."""
        self._custom_actions[name] = handler
    
    def get_rules(self, enabled_only: bool = True) -> List[Rule]:
        """Get all rules."""
        if enabled_only:
            return [r for r in self._rules if r.enabled]
        return self._rules.copy()
    
    def clear_rules(self) -> None:
        """Clear all rules."""
        self._rules.clear()
    
    @classmethod
    def create_default_rules(cls) -> "RuleEngine":
        """Create a rule engine with default rules."""
        engine = cls()
        
        # High-priority block rules
        engine.add_rules([
            Rule.block_on_high_severity(ThreatTypes.PROMPT_INJECTION, 0.8),
            Rule.block_on_high_severity(ThreatTypes.JAILBREAK, 0.75),
            Rule.block_on_high_severity(ThreatTypes.HARMFUL_CONTENT, 0.85),
            Rule.block_on_high_severity(ThreatTypes.SYSTEM_PROMPT_LEAK, 0.8),
            
            # Special rule for combined threats
            Rule(
                name="block_multiple_high_threats",
                conditions=[
                    RuleCondition("severity", RuleOperator.GREATER_THAN_OR_EQUALS, 0.6),
                    RuleCondition("confidence", RuleOperator.GREATER_THAN_OR_EQUALS, 0.7),
                ],
                action=Actions.BLOCK,
                priority=90,
                description="Block when severity and confidence are both high",
            ),
        ])
        
        # Medium-priority sanitize rules
        engine.add_rules([
            Rule(
                name="sanitize_pii",
                conditions=[
                    RuleCondition("threat_type", RuleOperator.EQUALS, ThreatTypes.DATA_LEAKAGE),
                    RuleCondition("severity", RuleOperator.GREATER_THAN_OR_EQUALS, 0.3),
                ],
                action=Actions.SANITIZE,
                priority=60,
                description="Sanitize PII detections",
            ),
            Rule(
                name="sanitize_toxic_content",
                conditions=[
                    RuleCondition("threat_type", RuleOperator.EQUALS, ThreatTypes.TOXIC_CONTENT),
                    RuleCondition("severity", RuleOperator.GREATER_THAN_OR_EQUALS, 0.4),
                    RuleCondition("severity", RuleOperator.LESS_THAN, 0.7),
                ],
                action=Actions.SANITIZE,
                priority=55,
                description="Sanitize moderate toxic content",
            ),
        ])
        
        # Low-priority flag rules
        engine.add_rules([
            Rule(
                name="flag_hallucination",
                conditions=[
                    RuleCondition("threat_type", RuleOperator.EQUALS, ThreatTypes.HALLUCINATION),
                    RuleCondition("severity", RuleOperator.GREATER_THAN_OR_EQUALS, 0.4),
                ],
                action=Actions.FLAG,
                priority=30,
                description="Flag potential hallucinations",
            ),
            Rule(
                name="flag_bias",
                conditions=[
                    RuleCondition("threat_type", RuleOperator.EQUALS, ThreatTypes.BIAS),
                    RuleCondition("severity", RuleOperator.GREATER_THAN_OR_EQUALS, 0.5),
                ],
                action=Actions.FLAG,
                priority=25,
                description="Flag potential bias",
            ),
        ])
        
        return engine
