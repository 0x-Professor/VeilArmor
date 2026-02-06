"""
VeilArmor - Decision Engine

Main decision-making engine that combines scoring, thresholds, and rules
to determine the appropriate action for classified content.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from src import Actions, ThreatTypes
from src.classifiers.base import ClassificationResult
from src.decision.scorer import Scorer, ScoringResult, ScoringStrategy
from src.decision.thresholds import ThresholdManager
from src.decision.rules import RuleEngine, Rule


@dataclass
class Decision:
    """
    The final decision made by the decision engine.
    """
    action: str
    severity: float
    confidence: float
    reason: str
    threat_types: List[str]
    matched_rules: List[str]
    scoring_result: Optional[ScoringResult] = None
    contributing_results: List[ClassificationResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def should_block(self) -> bool:
        """Check if action is block."""
        return self.action == Actions.BLOCK
    
    @property
    def should_sanitize(self) -> bool:
        """Check if action is sanitize."""
        return self.action == Actions.SANITIZE
    
    @property
    def should_flag(self) -> bool:
        """Check if action is flag."""
        return self.action == Actions.FLAG
    
    @property
    def is_allowed(self) -> bool:
        """Check if action is allow."""
        return self.action == Actions.ALLOW
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary."""
        return {
            "action": self.action,
            "severity": self.severity,
            "confidence": self.confidence,
            "reason": self.reason,
            "threat_types": self.threat_types,
            "matched_rules": self.matched_rules,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


class DecisionEngine:
    """
    Main decision engine for VeilArmor.
    
    Combines:
    - Classification results from multiple classifiers
    - Scoring strategies for aggregation
    - Threshold-based decisions
    - Rule-based overrides
    
    Decision flow:
    1. Aggregate classification results using scorer
    2. Apply rules to check for overrides
    3. If no rule match, use thresholds to determine action
    4. Return final decision with all context
    """
    
    def __init__(
        self,
        scorer: Optional[Scorer] = None,
        threshold_manager: Optional[ThresholdManager] = None,
        rule_engine: Optional[RuleEngine] = None,
        scoring_strategy: ScoringStrategy = ScoringStrategy.WEIGHTED_AVERAGE,
        classifier_weights: Optional[Dict[str, float]] = None,
    ):
        """
        Initialize decision engine.
        
        Args:
            scorer: Scorer instance
            threshold_manager: Threshold manager instance
            rule_engine: Rule engine instance
            scoring_strategy: Default scoring strategy
            classifier_weights: Weights for classifiers
        """
        self.scorer = scorer or Scorer(
            default_strategy=scoring_strategy,
            classifier_weights=classifier_weights or self._default_weights(),
        )
        self.threshold_manager = threshold_manager or ThresholdManager()
        self.rule_engine = rule_engine or RuleEngine.create_default_rules()
        self._scoring_strategy = scoring_strategy
    
    def _default_weights(self) -> Dict[str, float]:
        """Get default classifier weights."""
        return {
            # Input classifiers
            "prompt_injection": 1.5,
            "jailbreak": 1.5,
            "pii_detector": 1.2,
            "sensitive_content": 1.3,
            "system_prompt_leak": 1.4,
            "adversarial_attack": 1.3,
            "toxicity": 1.2,
            # Output classifiers
            "content_safety": 1.4,
            "pii_leakage": 1.3,
            "injection_check": 1.4,
            "hallucination": 0.9,
            "bias_detector": 0.8,
        }
    
    def decide(
        self,
        results: List[ClassificationResult],
        context: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        """
        Make a decision based on classification results.
        
        Args:
            results: Classification results from all classifiers
            context: Additional context for decision making
            
        Returns:
            Decision with action and supporting information
        """
        context = context or {}
        
        # Filter to results with threats
        threat_results = [r for r in results if r.severity > 0]
        
        if not threat_results:
            return Decision(
                action=Actions.ALLOW,
                severity=0.0,
                confidence=1.0,
                reason="No threats detected",
                threat_types=[],
                matched_rules=[],
                contributing_results=[],
            )
        
        # Step 1: Score the results
        scoring_result = self.scorer.score(
            threat_results,
            strategy=self._scoring_strategy,
        )
        
        # Step 2: Check rules for any overrides
        matched_rules = self.rule_engine.evaluate_all(threat_results, context)
        
        # Get highest priority action from rules
        rule_action = None
        rule_names = []
        
        # Priority: BLOCK > SANITIZE > FLAG > ALLOW
        if matched_rules[Actions.BLOCK]:
            rule_action = Actions.BLOCK
            rule_names = [r.name for r in matched_rules[Actions.BLOCK]]
        elif matched_rules[Actions.SANITIZE]:
            rule_action = Actions.SANITIZE
            rule_names = [r.name for r in matched_rules[Actions.SANITIZE]]
        elif matched_rules[Actions.FLAG]:
            rule_action = Actions.FLAG
            rule_names = [r.name for r in matched_rules[Actions.FLAG]]
        
        # Step 3: Determine action based on rules or thresholds
        threat_types = list(set(r.threat_type for r in threat_results))
        
        if rule_action:
            # Rule-based decision
            action = rule_action
            reason = f"Rule triggered: {', '.join(rule_names[:3])}"
        else:
            # Threshold-based decision
            # Use the threat type with highest severity for threshold check
            primary_result = max(threat_results, key=lambda r: r.severity)
            action = self.threshold_manager.get_action(
                primary_result.threat_type,
                scoring_result.final_score,
            )
            
            if action == Actions.BLOCK:
                reason = f"Severity {scoring_result.final_score:.2f} exceeds block threshold"
            elif action == Actions.SANITIZE:
                reason = f"Severity {scoring_result.final_score:.2f} exceeds sanitize threshold"
            else:
                reason = f"Severity {scoring_result.final_score:.2f} below thresholds"
        
        # Build metadata
        metadata = {
            "primary_threat": max(threat_results, key=lambda r: r.severity).threat_type,
            "threat_count": len(threat_types),
            "result_count": len(threat_results),
            "scoring_strategy": self._scoring_strategy.value,
            "rule_based": bool(rule_action),
        }
        
        # Add alert information
        should_alert = any(
            self.threshold_manager.should_alert(r.threat_type, r.severity)
            for r in threat_results
        )
        metadata["should_alert"] = should_alert
        
        return Decision(
            action=action,
            severity=scoring_result.final_score,
            confidence=scoring_result.confidence,
            reason=reason,
            threat_types=threat_types,
            matched_rules=rule_names,
            scoring_result=scoring_result,
            contributing_results=scoring_result.contributing_results,
            metadata=metadata,
        )
    
    def decide_by_threat_type(
        self,
        results: List[ClassificationResult],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Decision]:
        """
        Make separate decisions for each threat type.
        
        Args:
            results: Classification results
            context: Additional context
            
        Returns:
            Dict mapping threat type to decision
        """
        # Group results by threat type
        by_type: Dict[str, List[ClassificationResult]] = {}
        for result in results:
            if result.severity > 0:
                if result.threat_type not in by_type:
                    by_type[result.threat_type] = []
                by_type[result.threat_type].append(result)
        
        # Make decision for each type
        decisions = {}
        for threat_type, type_results in by_type.items():
            decisions[threat_type] = self.decide(type_results, context)
        
        return decisions
    
    def get_aggregate_action(
        self,
        results: List[ClassificationResult],
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Get the most restrictive action across all results.
        
        Args:
            results: Classification results
            context: Additional context
            
        Returns:
            Most restrictive action
        """
        decision = self.decide(results, context)
        return decision.action
    
    def set_scoring_strategy(self, strategy: ScoringStrategy) -> None:
        """Set the scoring strategy."""
        self._scoring_strategy = strategy
    
    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine."""
        self.rule_engine.add_rule(rule)
    
    def set_strict_mode(self) -> None:
        """Enable strict mode (lower thresholds)."""
        self.threshold_manager.set_strict_mode()
    
    def set_lenient_mode(self) -> None:
        """Enable lenient mode (higher thresholds)."""
        self.threshold_manager.set_lenient_mode()
    
    def set_normal_mode(self) -> None:
        """Reset to normal mode."""
        self.threshold_manager.set_normal_mode()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current engine status."""
        return {
            "scoring_strategy": self._scoring_strategy.value,
            "rules_count": len(self.rule_engine.get_rules()),
            "thresholds": self.threshold_manager.get_all_thresholds(),
        }


class AsyncDecisionEngine(DecisionEngine):
    """
    Async version of the decision engine for high-throughput scenarios.
    """
    
    async def decide_async(
        self,
        results: List[ClassificationResult],
        context: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        """
        Make a decision asynchronously.
        
        For the decision engine itself, this is mostly I/O-free,
        but can be useful when decisions need to be made in an
        async context.
        """
        # Run sync decision in executor to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.decide(results, context),
        )
    
    async def decide_batch_async(
        self,
        batch: List[Tuple[List[ClassificationResult], Optional[Dict[str, Any]]]],
    ) -> List[Decision]:
        """
        Make decisions for a batch of inputs asynchronously.
        
        Args:
            batch: List of (results, context) tuples
            
        Returns:
            List of decisions
        """
        tasks = [
            self.decide_async(results, context)
            for results, context in batch
        ]
        return await asyncio.gather(*tasks)
