"""
VeilArmor v2.0 - Scorer

Scoring strategies for aggregating classification results.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from src.classifiers.base import ClassificationResult


class ScoringStrategy(str, Enum):
    """Available scoring strategies."""
    WEIGHTED_AVERAGE = "weighted_average"
    MAX_SEVERITY = "max_severity"
    CONFIDENCE_WEIGHTED = "confidence_weighted"
    THRESHOLD_COUNT = "threshold_count"
    CUSTOM = "custom"


@dataclass
class ScoringResult:
    """Result from scoring aggregation."""
    final_score: float
    confidence: float
    contributing_results: List[ClassificationResult]
    strategy_used: ScoringStrategy
    breakdown: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_threat(self) -> bool:
        """Check if the score indicates a threat."""
        return self.final_score > 0.0


class BaseScoringStrategy(ABC):
    """Base class for scoring strategies."""
    
    @property
    @abstractmethod
    def name(self) -> ScoringStrategy:
        """Strategy name."""
        pass
    
    @abstractmethod
    def calculate(
        self,
        results: List[ClassificationResult],
        weights: Optional[Dict[str, float]] = None,
    ) -> ScoringResult:
        """
        Calculate aggregated score from classification results.
        
        Args:
            results: List of classification results
            weights: Optional classifier weights
            
        Returns:
            ScoringResult with aggregated score
        """
        pass


class WeightedAverageStrategy(BaseScoringStrategy):
    """
    Weighted average scoring strategy.
    
    Formula: final_score = sum(severity * weight * confidence) / sum(weights)
    """
    
    @property
    def name(self) -> ScoringStrategy:
        return ScoringStrategy.WEIGHTED_AVERAGE
    
    def calculate(
        self,
        results: List[ClassificationResult],
        weights: Optional[Dict[str, float]] = None,
    ) -> ScoringResult:
        if not results:
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                contributing_results=[],
                strategy_used=self.name,
            )
        
        weights = weights or {}
        
        total_weighted_score = 0.0
        total_weight = 0.0
        total_confidence = 0.0
        contributing = []
        breakdown = {}
        
        for result in results:
            if result.severity <= 0:
                continue
            
            # Get weight for this classifier (default 1.0)
            classifier_name = result.metadata.get("classifier_name", "unknown")
            weight = weights.get(classifier_name, 1.0)
            
            # Calculate weighted contribution
            contribution = result.severity * weight * result.confidence
            total_weighted_score += contribution
            total_weight += weight
            total_confidence += result.confidence
            
            contributing.append(result)
            breakdown[classifier_name] = {
                "severity": result.severity,
                "weight": weight,
                "confidence": result.confidence,
                "contribution": contribution,
            }
        
        if total_weight == 0:
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                contributing_results=[],
                strategy_used=self.name,
            )
        
        final_score = total_weighted_score / total_weight
        avg_confidence = total_confidence / len(contributing) if contributing else 0.0
        
        return ScoringResult(
            final_score=min(1.0, final_score),
            confidence=avg_confidence,
            contributing_results=contributing,
            strategy_used=self.name,
            breakdown=breakdown,
        )


class MaxSeverityStrategy(BaseScoringStrategy):
    """
    Maximum severity scoring strategy.
    
    Uses the highest severity score among all results.
    """
    
    @property
    def name(self) -> ScoringStrategy:
        return ScoringStrategy.MAX_SEVERITY
    
    def calculate(
        self,
        results: List[ClassificationResult],
        weights: Optional[Dict[str, float]] = None,
    ) -> ScoringResult:
        if not results:
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                contributing_results=[],
                strategy_used=self.name,
            )
        
        # Find maximum severity
        max_result = max(results, key=lambda r: r.severity)
        
        if max_result.severity <= 0:
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                contributing_results=[],
                strategy_used=self.name,
            )
        
        # Contributing results are those with severity > 0
        contributing = [r for r in results if r.severity > 0]
        
        breakdown = {
            "max_severity_source": max_result.threat_type,
            "all_severities": {
                r.metadata.get("classifier_name", "unknown"): r.severity
                for r in contributing
            },
        }
        
        return ScoringResult(
            final_score=max_result.severity,
            confidence=max_result.confidence,
            contributing_results=contributing,
            strategy_used=self.name,
            breakdown=breakdown,
        )


class ConfidenceWeightedStrategy(BaseScoringStrategy):
    """
    Confidence-weighted scoring strategy.
    
    Weights severity scores by confidence level.
    """
    
    @property
    def name(self) -> ScoringStrategy:
        return ScoringStrategy.CONFIDENCE_WEIGHTED
    
    def calculate(
        self,
        results: List[ClassificationResult],
        weights: Optional[Dict[str, float]] = None,
    ) -> ScoringResult:
        if not results:
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                contributing_results=[],
                strategy_used=self.name,
            )
        
        weights = weights or {}
        
        total_score = 0.0
        total_confidence_weight = 0.0
        contributing = []
        breakdown = {}
        
        for result in results:
            if result.severity <= 0:
                continue
            
            classifier_name = result.metadata.get("classifier_name", "unknown")
            base_weight = weights.get(classifier_name, 1.0)
            
            # Weight by confidence
            confidence_weight = base_weight * result.confidence
            contribution = result.severity * confidence_weight
            
            total_score += contribution
            total_confidence_weight += confidence_weight
            
            contributing.append(result)
            breakdown[classifier_name] = {
                "severity": result.severity,
                "confidence": result.confidence,
                "confidence_weight": confidence_weight,
                "contribution": contribution,
            }
        
        if total_confidence_weight == 0:
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                contributing_results=[],
                strategy_used=self.name,
            )
        
        final_score = total_score / total_confidence_weight
        avg_confidence = sum(r.confidence for r in contributing) / len(contributing)
        
        return ScoringResult(
            final_score=min(1.0, final_score),
            confidence=avg_confidence,
            contributing_results=contributing,
            strategy_used=self.name,
            breakdown=breakdown,
        )


class ThresholdCountStrategy(BaseScoringStrategy):
    """
    Threshold count scoring strategy.
    
    Counts how many classifiers exceed a threshold and scores based on that.
    """
    
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
    
    @property
    def name(self) -> ScoringStrategy:
        return ScoringStrategy.THRESHOLD_COUNT
    
    def calculate(
        self,
        results: List[ClassificationResult],
        weights: Optional[Dict[str, float]] = None,
    ) -> ScoringResult:
        if not results:
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                contributing_results=[],
                strategy_used=self.name,
            )
        
        # Count results exceeding threshold
        exceeding = [r for r in results if r.severity >= self.threshold]
        contributing = [r for r in results if r.severity > 0]
        
        if not exceeding:
            # No results exceed threshold, but still report if any positive
            if contributing:
                max_severity = max(r.severity for r in contributing)
                return ScoringResult(
                    final_score=max_severity * 0.5,  # Penalized score
                    confidence=sum(r.confidence for r in contributing) / len(contributing),
                    contributing_results=contributing,
                    strategy_used=self.name,
                    breakdown={
                        "threshold": self.threshold,
                        "exceeding_count": 0,
                        "total_positive": len(contributing),
                    },
                )
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                contributing_results=[],
                strategy_used=self.name,
            )
        
        # Score based on proportion exceeding and max severity
        proportion = len(exceeding) / len(results)
        max_severity = max(r.severity for r in exceeding)
        avg_severity = sum(r.severity for r in exceeding) / len(exceeding)
        
        # Combine proportion and severity
        final_score = (proportion * 0.3) + (max_severity * 0.5) + (avg_severity * 0.2)
        
        breakdown = {
            "threshold": self.threshold,
            "exceeding_count": len(exceeding),
            "total_count": len(results),
            "proportion": proportion,
            "max_severity": max_severity,
            "avg_severity": avg_severity,
        }
        
        return ScoringResult(
            final_score=min(1.0, final_score),
            confidence=sum(r.confidence for r in exceeding) / len(exceeding),
            contributing_results=exceeding,
            strategy_used=self.name,
            breakdown=breakdown,
        )


class Scorer:
    """
    Main scorer class that orchestrates scoring strategies.
    """
    
    # Available strategies
    _strategies: Dict[ScoringStrategy, BaseScoringStrategy] = {
        ScoringStrategy.WEIGHTED_AVERAGE: WeightedAverageStrategy(),
        ScoringStrategy.MAX_SEVERITY: MaxSeverityStrategy(),
        ScoringStrategy.CONFIDENCE_WEIGHTED: ConfidenceWeightedStrategy(),
        ScoringStrategy.THRESHOLD_COUNT: ThresholdCountStrategy(),
    }
    
    def __init__(
        self,
        default_strategy: ScoringStrategy = ScoringStrategy.WEIGHTED_AVERAGE,
        classifier_weights: Optional[Dict[str, float]] = None,
    ):
        """
        Initialize scorer.
        
        Args:
            default_strategy: Default scoring strategy
            classifier_weights: Default weights for classifiers
        """
        self.default_strategy = default_strategy
        self.classifier_weights = classifier_weights or {}
    
    def score(
        self,
        results: List[ClassificationResult],
        strategy: Optional[ScoringStrategy] = None,
        weights: Optional[Dict[str, float]] = None,
    ) -> ScoringResult:
        """
        Score classification results.
        
        Args:
            results: Classification results to score
            strategy: Scoring strategy (uses default if not provided)
            weights: Classifier weights (uses default if not provided)
            
        Returns:
            ScoringResult with aggregated score
        """
        strategy = strategy or self.default_strategy
        weights = weights or self.classifier_weights
        
        strategy_impl = self._strategies.get(strategy)
        if not strategy_impl:
            raise ValueError(f"Unknown scoring strategy: {strategy}")
        
        return strategy_impl.calculate(results, weights)
    
    def score_with_multiple_strategies(
        self,
        results: List[ClassificationResult],
        strategies: Optional[List[ScoringStrategy]] = None,
        weights: Optional[Dict[str, float]] = None,
    ) -> Dict[ScoringStrategy, ScoringResult]:
        """
        Score using multiple strategies.
        
        Args:
            results: Classification results
            strategies: List of strategies (uses all if not provided)
            weights: Classifier weights
            
        Returns:
            Dict mapping strategy to result
        """
        strategies = strategies or list(self._strategies.keys())
        weights = weights or self.classifier_weights
        
        return {
            strategy: self.score(results, strategy, weights)
            for strategy in strategies
        }
    
    def register_strategy(
        self,
        name: ScoringStrategy,
        strategy: BaseScoringStrategy,
    ) -> None:
        """Register a custom scoring strategy."""
        self._strategies[name] = strategy
    
    def set_classifier_weight(self, classifier_name: str, weight: float) -> None:
        """Set weight for a specific classifier."""
        self.classifier_weights[classifier_name] = weight
    
    def get_available_strategies(self) -> List[ScoringStrategy]:
        """Get list of available strategies."""
        return list(self._strategies.keys())
