"""
VeilArmor - Classifier Manager

Manages parallel execution of multiple classifiers with proper error handling,
circuit breaker pattern, and result aggregation.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Type

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType
from src.config import get_settings
from src.logging import get_logger
from src import Layers

logger = get_logger(__name__, layer=Layers.CLASSIFICATION_ENGINE)


class CircuitState(str, Enum):
    """Circuit breaker state."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject calls
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class CircuitBreaker:
    """
    Circuit breaker for classifier fault tolerance.
    
    Attributes:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds before attempting recovery
        half_open_max_calls: Max calls in half-open state
    """
    
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 3
    
    # State tracking
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    half_open_calls: int = 0
    
    def record_success(self) -> None:
        """Record a successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.half_open_max_calls:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
        else:
            self.failure_count = 0
    
    def record_failure(self) -> None:
        """Record a failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.half_open_calls = 0
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
    
    def can_execute(self) -> bool:
        """Check if execution is allowed."""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.half_open_calls = 0
                self.success_count = 0
                return True
            return False
        
        # Half-open state
        if self.half_open_calls < self.half_open_max_calls:
            self.half_open_calls += 1
            return True
        return False


@dataclass
class AggregatedResults:
    """
    Aggregated results from multiple classifiers.
    
    Attributes:
        results: List of individual classification results
        total_processing_time_ms: Total time for all classifiers
        classifier_count: Number of classifiers run
        threat_count: Number of threats detected
        max_severity: Maximum severity score
        aggregated_score: Weighted aggregated score
    """
    
    results: List[ClassificationResult] = field(default_factory=list)
    total_processing_time_ms: float = 0.0
    classifier_count: int = 0
    threat_count: int = 0
    max_severity: float = 0.0
    aggregated_score: float = 0.0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_result(self, result: ClassificationResult, weight: float = 1.0) -> None:
        """Add a classification result."""
        self.results.append(result)
        self.classifier_count += 1
        self.total_processing_time_ms += result.processing_time_ms
        
        if result.is_threat:
            self.threat_count += 1
            self.max_severity = max(self.max_severity, result.severity)
        
        # Check for error
        if result.metadata.get("status") == "error":
            self.errors.append({
                "classifier": result.classifier_name,
                "error": result.metadata.get("error", "Unknown error"),
            })
    
    def get_threats(self) -> List[ClassificationResult]:
        """Get all results that indicate threats."""
        return [r for r in self.results if r.is_threat]
    
    def get_by_threat_type(self, threat_type: str) -> Optional[ClassificationResult]:
        """Get result for a specific threat type."""
        for result in self.results:
            if result.threat_type == threat_type:
                return result
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "results": [r.to_dict() for r in self.results],
            "total_processing_time_ms": self.total_processing_time_ms,
            "classifier_count": self.classifier_count,
            "threat_count": self.threat_count,
            "max_severity": self.max_severity,
            "aggregated_score": self.aggregated_score,
            "errors": self.errors,
            "has_errors": len(self.errors) > 0,
        }


class ClassifierManager:
    """
    Manages registration and parallel execution of classifiers.
    
    Features:
    - Parallel classifier execution using asyncio.gather
    - Circuit breaker pattern for fault tolerance
    - Configurable timeouts per classifier
    - Result aggregation with weighted scoring
    - Health monitoring for all classifiers
    """
    
    def __init__(
        self,
        parallel_execution: bool = True,
        max_concurrent: int = 10,
        fail_fast: bool = False,
        default_timeout: float = 5.0,
    ) -> None:
        """
        Initialize the classifier manager.
        
        Args:
            parallel_execution: Whether to run classifiers in parallel
            max_concurrent: Maximum concurrent classifier executions
            fail_fast: Stop on first high-severity threat
            default_timeout: Default timeout for classifiers
        """
        self.parallel_execution = parallel_execution
        self.max_concurrent = max_concurrent
        self.fail_fast = fail_fast
        self.default_timeout = default_timeout
        
        # Classifier storage
        self._input_classifiers: Dict[str, BaseClassifier] = {}
        self._output_classifiers: Dict[str, BaseClassifier] = {}
        
        # Circuit breakers per classifier
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        
        # Semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(max_concurrent)
        
        logger.info(
            "Classifier manager initialized",
            parallel_execution=parallel_execution,
            max_concurrent=max_concurrent,
            fail_fast=fail_fast,
        )
    
    def register(self, classifier: BaseClassifier) -> None:
        """
        Register a classifier.
        
        Args:
            classifier: Classifier instance to register
        """
        if classifier.classifier_type == ClassifierType.INPUT:
            self._input_classifiers[classifier.name] = classifier
        else:
            self._output_classifiers[classifier.name] = classifier
        
        # Create circuit breaker
        self._circuit_breakers[classifier.name] = CircuitBreaker()
        
        logger.debug(
            "Classifier registered",
            classifier=classifier.name,
            type=classifier.classifier_type.value,
            enabled=classifier.enabled,
        )
    
    def unregister(self, name: str) -> bool:
        """
        Unregister a classifier by name.
        
        Args:
            name: Classifier name
            
        Returns:
            True if classifier was found and removed
        """
        removed = False
        
        if name in self._input_classifiers:
            del self._input_classifiers[name]
            removed = True
        
        if name in self._output_classifiers:
            del self._output_classifiers[name]
            removed = True
        
        if name in self._circuit_breakers:
            del self._circuit_breakers[name]
        
        if removed:
            logger.debug("Classifier unregistered", classifier=name)
        
        return removed
    
    def get_classifier(self, name: str) -> Optional[BaseClassifier]:
        """
        Get a classifier by name.
        
        Args:
            name: Classifier name
            
        Returns:
            Classifier instance or None
        """
        return self._input_classifiers.get(name) or self._output_classifiers.get(name)
    
    def get_input_classifiers(self) -> List[BaseClassifier]:
        """Get all input classifiers."""
        return list(self._input_classifiers.values())
    
    def get_output_classifiers(self) -> List[BaseClassifier]:
        """Get all output classifiers."""
        return list(self._output_classifiers.values())
    
    def get_enabled_classifiers(
        self,
        classifier_type: Optional[ClassifierType] = None
    ) -> List[BaseClassifier]:
        """
        Get all enabled classifiers.
        
        Args:
            classifier_type: Filter by classifier type
            
        Returns:
            List of enabled classifiers
        """
        classifiers = []
        
        if classifier_type is None or classifier_type == ClassifierType.INPUT:
            classifiers.extend([c for c in self._input_classifiers.values() if c.enabled])
        
        if classifier_type is None or classifier_type == ClassifierType.OUTPUT:
            classifiers.extend([c for c in self._output_classifiers.values() if c.enabled])
        
        return classifiers
    
    async def _run_with_circuit_breaker(
        self,
        classifier: BaseClassifier,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ClassificationResult:
        """
        Run a classifier with circuit breaker protection.
        
        Args:
            classifier: Classifier to run
            text: Text to classify
            context: Optional context
            
        Returns:
            Classification result
        """
        circuit_breaker = self._circuit_breakers.get(classifier.name)
        
        if circuit_breaker and not circuit_breaker.can_execute():
            logger.warning(
                "Circuit breaker open, skipping classifier",
                component=classifier.name,
            )
            return ClassificationResult.error_result(
                threat_type=classifier.threat_type,
                classifier_name=classifier.name,
                error_message="Circuit breaker open",
            )
        
        async with self._semaphore:
            try:
                # Apply timeout
                result = await asyncio.wait_for(
                    classifier.run(text, context),
                    timeout=classifier.timeout_seconds,
                )
                
                # Record success
                if circuit_breaker:
                    if result.metadata.get("status") != "error":
                        circuit_breaker.record_success()
                    else:
                        circuit_breaker.record_failure()
                
                return result
                
            except asyncio.TimeoutError:
                logger.warning(
                    "Classifier timeout",
                    component=classifier.name,
                    timeout=classifier.timeout_seconds,
                )
                
                if circuit_breaker:
                    circuit_breaker.record_failure()
                
                return ClassificationResult.error_result(
                    threat_type=classifier.threat_type,
                    classifier_name=classifier.name,
                    error_message=f"Timeout after {classifier.timeout_seconds}s",
                    processing_time_ms=classifier.timeout_seconds * 1000,
                )
            
            except Exception as e:
                logger.error(
                    "Classifier execution error",
                    component=classifier.name,
                    error=str(e),
                )
                
                if circuit_breaker:
                    circuit_breaker.record_failure()
                
                return ClassificationResult.error_result(
                    threat_type=classifier.threat_type,
                    classifier_name=classifier.name,
                    error_message=str(e),
                )
    
    def _calculate_aggregated_score(
        self,
        results: List[ClassificationResult],
        classifiers: List[BaseClassifier],
    ) -> float:
        """
        Calculate weighted aggregated score.
        
        Only threat results contribute to the score. Non-threat and error
        results are excluded so they don't dilute the aggregated score.
        
        Formula: sum(severity * weight * confidence) / sum(weight) for threats only
        
        Args:
            results: Classification results
            classifiers: Corresponding classifiers (for weights)
            
        Returns:
            Aggregated score (0.0 - 1.0)
        """
        total_weighted_score = 0.0
        total_weight = 0.0
        
        # Build classifier lookup
        classifier_lookup = {c.name: c for c in classifiers}
        
        for result in results:
            # Skip non-threat and error results to avoid diluting the score
            if not result.is_threat or result.metadata.get("status") == "error":
                continue
            classifier = classifier_lookup.get(result.classifier_name)
            if classifier:
                weight = classifier.weight
                total_weighted_score += result.severity * weight * result.confidence
                total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return total_weighted_score / total_weight
    
    async def classify_input(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        classifiers: Optional[List[str]] = None,
    ) -> AggregatedResults:
        """
        Run input classifiers on the given text.
        
        Args:
            text: Text to classify
            context: Optional context
            classifiers: Optional list of specific classifier names to run
            
        Returns:
            Aggregated classification results
        """
        return await self._classify(
            text=text,
            context=context,
            classifier_type=ClassifierType.INPUT,
            classifier_names=classifiers,
        )
    
    async def classify_output(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        classifiers: Optional[List[str]] = None,
    ) -> AggregatedResults:
        """
        Run output classifiers on the given text.
        
        Args:
            text: Text to classify
            context: Optional context
            classifiers: Optional list of specific classifier names to run
            
        Returns:
            Aggregated classification results
        """
        return await self._classify(
            text=text,
            context=context,
            classifier_type=ClassifierType.OUTPUT,
            classifier_names=classifiers,
        )
    
    async def _classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        classifier_type: Optional[ClassifierType] = None,
        classifier_names: Optional[List[str]] = None,
    ) -> AggregatedResults:
        """
        Internal method to run classifiers.
        
        Args:
            text: Text to classify
            context: Optional context
            classifier_type: Type of classifiers to run
            classifier_names: Optional specific classifier names
            
        Returns:
            Aggregated results
        """
        start_time = time.perf_counter()
        
        # Get classifiers to run
        if classifier_names:
            classifiers = []
            for name in classifier_names:
                classifier = self.get_classifier(name)
                if classifier and classifier.enabled:
                    classifiers.append(classifier)
        else:
            classifiers = self.get_enabled_classifiers(classifier_type)
        
        if not classifiers:
            logger.warning("No enabled classifiers to run")
            return AggregatedResults()
        
        logger.info(
            "Running classifiers",
            classifier_count=len(classifiers),
            classifier_type=classifier_type.value if classifier_type else "all",
            text_length=len(text),
            parallel=self.parallel_execution,
        )
        
        # Run classifiers
        aggregated = AggregatedResults()
        
        if self.parallel_execution:
            # Parallel execution
            tasks = [
                self._run_with_circuit_breaker(c, text, context)
                for c in classifiers
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    # Handle unexpected exceptions
                    classifier = classifiers[i]
                    logger.error(
                        "Unexpected classifier error",
                        component=classifier.name,
                        error=str(result),
                    )
                    # Record failure on circuit breaker
                    cb = self._circuit_breakers.get(classifier.name)
                    if cb:
                        cb.record_failure()
                    aggregated.add_result(
                        ClassificationResult.error_result(
                            threat_type=classifier.threat_type,
                            classifier_name=classifier.name,
                            error_message=str(result),
                        ),
                        classifier.weight,
                    )
                else:
                    classifier = classifiers[i]
                    aggregated.add_result(result, classifier.weight)
                    
                    # Check for fail-fast
                    if self.fail_fast and result.severity >= 0.7:
                        logger.warning(
                            "Fail-fast triggered by high severity threat",
                            classifier=result.classifier_name,
                            severity=result.severity,
                        )
                        break
        else:
            # Sequential execution
            for classifier in classifiers:
                result = await self._run_with_circuit_breaker(classifier, text, context)
                aggregated.add_result(result, classifier.weight)
                
                # Check for fail-fast
                if self.fail_fast and result.severity >= 0.7:
                    logger.warning(
                        "Fail-fast triggered by high severity threat",
                        classifier=result.classifier_name,
                        severity=result.severity,
                    )
                    break
        
        # Calculate aggregated score
        aggregated.aggregated_score = self._calculate_aggregated_score(
            aggregated.results, classifiers
        )
        
        total_time = (time.perf_counter() - start_time) * 1000
        
        logger.info(
            "Classification complete",
            classifier_count=aggregated.classifier_count,
            threat_count=aggregated.threat_count,
            max_severity=aggregated.max_severity,
            aggregated_score=aggregated.aggregated_score,
            total_time_ms=total_time,
            error_count=len(aggregated.errors),
        )
        
        return aggregated
    
    def get_health(self) -> Dict[str, Any]:
        """
        Get health status of all classifiers.
        
        Returns:
            Dictionary with health information
        """
        input_health = [c.get_health() for c in self._input_classifiers.values()]
        output_health = [c.get_health() for c in self._output_classifiers.values()]
        
        circuit_breaker_status = {
            name: cb.state.value
            for name, cb in self._circuit_breakers.items()
        }
        
        return {
            "input_classifiers": input_health,
            "output_classifiers": output_health,
            "circuit_breakers": circuit_breaker_status,
            "total_input_classifiers": len(self._input_classifiers),
            "total_output_classifiers": len(self._output_classifiers),
            "enabled_input_classifiers": len([c for c in self._input_classifiers.values() if c.enabled]),
            "enabled_output_classifiers": len([c for c in self._output_classifiers.values() if c.enabled]),
        }
    
    def reset_circuit_breakers(self) -> None:
        """Reset all circuit breakers to closed state."""
        for cb in self._circuit_breakers.values():
            cb.state = CircuitState.CLOSED
            cb.failure_count = 0
            cb.success_count = 0
        
        logger.info("All circuit breakers reset")


# Global classifier manager instance
_manager: Optional[ClassifierManager] = None


def get_classifier_manager() -> ClassifierManager:
    """Get the global classifier manager instance."""
    global _manager
    if _manager is None:
        settings = get_settings()
        _manager = ClassifierManager(
            parallel_execution=settings.classifiers.parallel_execution,
            max_concurrent=settings.classifiers.max_concurrent,
            fail_fast=settings.classifiers.fail_fast,
        )
    return _manager


def reset_classifier_manager() -> None:
    """Reset the global classifier manager."""
    global _manager
    _manager = None
