"""
VeilArmor - Metrics Collection

Collects and exposes metrics for monitoring and observability.
Supports Prometheus-compatible metrics format.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Dict, List, Optional

try:
    from prometheus_client import Counter, Gauge, Histogram, Info, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


@dataclass
class TimingMetric:
    """Stores timing statistics."""
    count: int = 0
    total_ms: float = 0.0
    min_ms: float = float("inf")
    max_ms: float = 0.0
    
    def record(self, duration_ms: float) -> None:
        """Record a timing measurement."""
        self.count += 1
        self.total_ms += duration_ms
        self.min_ms = min(self.min_ms, duration_ms)
        self.max_ms = max(self.max_ms, duration_ms)
    
    @property
    def avg_ms(self) -> float:
        """Calculate average duration."""
        return self.total_ms / self.count if self.count > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "count": self.count,
            "total_ms": self.total_ms,
            "avg_ms": self.avg_ms,
            "min_ms": self.min_ms if self.min_ms != float("inf") else 0.0,
            "max_ms": self.max_ms,
        }


@dataclass
class CounterMetric:
    """Stores counter statistics."""
    value: int = 0
    
    def increment(self, amount: int = 1) -> None:
        """Increment counter."""
        self.value += amount
    
    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary."""
        return {"value": self.value}


class MetricsCollector:
    """
    Centralized metrics collector for VeilArmor.
    
    Tracks:
    - Request counts and latencies
    - Classification results
    - Decision distributions
    - Cache hit/miss rates
    - LLM provider metrics
    - Error counts by type
    """
    
    _instance: Optional["MetricsCollector"] = None
    _lock: Lock = Lock()
    
    def __new__(cls) -> "MetricsCollector":
        """Singleton pattern for metrics collector."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self) -> None:
        """Initialize metrics collector."""
        if self._initialized:
            return
        
        self._initialized = True
        self._metrics_lock = Lock()
        
        # Request metrics
        self.requests_total = CounterMetric()
        self.requests_by_status: Dict[int, CounterMetric] = defaultdict(CounterMetric)
        self.request_latency = TimingMetric()
        
        # Classification metrics
        self.classifications_total = CounterMetric()
        self.classifications_by_threat: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        self.classification_latency = TimingMetric()
        self.classifier_latency: Dict[str, TimingMetric] = defaultdict(TimingMetric)
        
        # Decision metrics
        self.decisions_total = CounterMetric()
        self.decisions_by_action: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        
        # Sanitization metrics
        self.sanitizations_total = CounterMetric()
        self.sanitization_latency = TimingMetric()
        self.patterns_matched: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        
        # Cache metrics
        self.cache_hits = CounterMetric()
        self.cache_misses = CounterMetric()
        self.cache_latency = TimingMetric()
        
        # LLM provider metrics
        self.llm_requests_total = CounterMetric()
        self.llm_requests_by_provider: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        self.llm_latency = TimingMetric()
        self.llm_latency_by_provider: Dict[str, TimingMetric] = defaultdict(TimingMetric)
        self.llm_tokens_input = CounterMetric()
        self.llm_tokens_output = CounterMetric()
        self.llm_errors_by_provider: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        
        # Error metrics
        self.errors_total = CounterMetric()
        self.errors_by_type: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        self.errors_by_layer: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        
        # Conversation metrics
        self.conversations_total = CounterMetric()
        self.conversation_turns_total = CounterMetric()
        self.active_conversations = CounterMetric()
        
        # Initialize Prometheus metrics if available
        self._init_prometheus_metrics()
    
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics collectors."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        # Request metrics
        self.prom_requests_total = Counter(
            "veilarmor_requests_total",
            "Total number of requests",
            ["status_code"]
        )
        self.prom_request_latency = Histogram(
            "veilarmor_request_latency_seconds",
            "Request latency in seconds",
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        # Classification metrics
        self.prom_classifications = Counter(
            "veilarmor_classifications_total",
            "Total number of classifications",
            ["threat_type"]
        )
        self.prom_classification_latency = Histogram(
            "veilarmor_classification_latency_seconds",
            "Classification latency in seconds",
            ["classifier"]
        )
        
        # Decision metrics
        self.prom_decisions = Counter(
            "veilarmor_decisions_total",
            "Total number of decisions",
            ["action"]
        )
        
        # Cache metrics
        self.prom_cache_operations = Counter(
            "veilarmor_cache_operations_total",
            "Total cache operations",
            ["operation", "result"]
        )
        
        # LLM metrics
        self.prom_llm_requests = Counter(
            "veilarmor_llm_requests_total",
            "Total LLM requests",
            ["provider", "model"]
        )
        self.prom_llm_latency = Histogram(
            "veilarmor_llm_latency_seconds",
            "LLM request latency in seconds",
            ["provider"]
        )
        self.prom_llm_tokens = Counter(
            "veilarmor_llm_tokens_total",
            "Total LLM tokens",
            ["direction"]
        )
        
        # Error metrics
        self.prom_errors = Counter(
            "veilarmor_errors_total",
            "Total errors",
            ["type", "layer"]
        )
    
    # ==========================================================================
    # Request Metrics
    # ==========================================================================
    
    def record_request(self, status_code: int, latency_ms: float) -> None:
        """Record a request with status code and latency."""
        with self._metrics_lock:
            self.requests_total.increment()
            self.requests_by_status[status_code].increment()
            self.request_latency.record(latency_ms)
        
        if PROMETHEUS_AVAILABLE:
            self.prom_requests_total.labels(status_code=str(status_code)).inc()
            self.prom_request_latency.observe(latency_ms / 1000)
    
    # ==========================================================================
    # Classification Metrics
    # ==========================================================================
    
    def record_classification(
        self,
        threat_type: str,
        classifier_name: str,
        latency_ms: float
    ) -> None:
        """Record a classification result."""
        with self._metrics_lock:
            self.classifications_total.increment()
            self.classifications_by_threat[threat_type].increment()
            self.classification_latency.record(latency_ms)
            self.classifier_latency[classifier_name].record(latency_ms)
        
        if PROMETHEUS_AVAILABLE:
            self.prom_classifications.labels(threat_type=threat_type).inc()
            self.prom_classification_latency.labels(classifier=classifier_name).observe(
                latency_ms / 1000
            )
    
    # ==========================================================================
    # Decision Metrics
    # ==========================================================================
    
    def record_decision(self, action: str) -> None:
        """Record a decision action."""
        with self._metrics_lock:
            self.decisions_total.increment()
            self.decisions_by_action[action].increment()
        
        if PROMETHEUS_AVAILABLE:
            self.prom_decisions.labels(action=action).inc()
    
    # ==========================================================================
    # Cache Metrics
    # ==========================================================================
    
    def record_cache_hit(self, latency_ms: float = 0) -> None:
        """Record a cache hit."""
        with self._metrics_lock:
            self.cache_hits.increment()
            if latency_ms > 0:
                self.cache_latency.record(latency_ms)
        
        if PROMETHEUS_AVAILABLE:
            self.prom_cache_operations.labels(operation="get", result="hit").inc()
    
    def record_cache_miss(self, latency_ms: float = 0) -> None:
        """Record a cache miss."""
        with self._metrics_lock:
            self.cache_misses.increment()
            if latency_ms > 0:
                self.cache_latency.record(latency_ms)
        
        if PROMETHEUS_AVAILABLE:
            self.prom_cache_operations.labels(operation="get", result="miss").inc()
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.cache_hits.value + self.cache_misses.value
        return self.cache_hits.value / total if total > 0 else 0.0
    
    # ==========================================================================
    # LLM Provider Metrics
    # ==========================================================================
    
    def record_llm_request(
        self,
        provider: str,
        model: str,
        latency_ms: float,
        input_tokens: int,
        output_tokens: int
    ) -> None:
        """Record an LLM request."""
        with self._metrics_lock:
            self.llm_requests_total.increment()
            self.llm_requests_by_provider[provider].increment()
            self.llm_latency.record(latency_ms)
            self.llm_latency_by_provider[provider].record(latency_ms)
            self.llm_tokens_input.increment(input_tokens)
            self.llm_tokens_output.increment(output_tokens)
        
        if PROMETHEUS_AVAILABLE:
            self.prom_llm_requests.labels(provider=provider, model=model).inc()
            self.prom_llm_latency.labels(provider=provider).observe(latency_ms / 1000)
            self.prom_llm_tokens.labels(direction="input").inc(input_tokens)
            self.prom_llm_tokens.labels(direction="output").inc(output_tokens)
    
    def record_llm_error(self, provider: str, error_type: str) -> None:
        """Record an LLM error."""
        with self._metrics_lock:
            self.llm_errors_by_provider[provider].increment()
            self.errors_by_type[error_type].increment()
    
    # ==========================================================================
    # Error Metrics
    # ==========================================================================
    
    def record_error(self, error_type: str, layer: str) -> None:
        """Record an error."""
        with self._metrics_lock:
            self.errors_total.increment()
            self.errors_by_type[error_type].increment()
            self.errors_by_layer[layer].increment()
        
        if PROMETHEUS_AVAILABLE:
            self.prom_errors.labels(type=error_type, layer=layer).inc()
    
    # ==========================================================================
    # Sanitization Metrics
    # ==========================================================================
    
    def record_sanitization(self, latency_ms: float, patterns: List[str]) -> None:
        """Record a sanitization operation."""
        with self._metrics_lock:
            self.sanitizations_total.increment()
            self.sanitization_latency.record(latency_ms)
            for pattern in patterns:
                self.patterns_matched[pattern].increment()
    
    # ==========================================================================
    # Conversation Metrics
    # ==========================================================================
    
    def record_conversation_created(self) -> None:
        """Record a new conversation."""
        with self._metrics_lock:
            self.conversations_total.increment()
            self.active_conversations.increment()
    
    def record_conversation_turn(self) -> None:
        """Record a conversation turn."""
        with self._metrics_lock:
            self.conversation_turns_total.increment()
    
    def record_conversation_ended(self) -> None:
        """Record a conversation end."""
        with self._metrics_lock:
            self.active_conversations.value -= 1
    
    # ==========================================================================
    # Export Methods
    # ==========================================================================
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics as dictionary."""
        with self._metrics_lock:
            return {
                "requests": {
                    "total": self.requests_total.value,
                    "by_status": {k: v.value for k, v in self.requests_by_status.items()},
                    "latency": self.request_latency.to_dict(),
                },
                "classifications": {
                    "total": self.classifications_total.value,
                    "by_threat": {k: v.value for k, v in self.classifications_by_threat.items()},
                    "latency": self.classification_latency.to_dict(),
                    "latency_by_classifier": {
                        k: v.to_dict() for k, v in self.classifier_latency.items()
                    },
                },
                "decisions": {
                    "total": self.decisions_total.value,
                    "by_action": {k: v.value for k, v in self.decisions_by_action.items()},
                },
                "cache": {
                    "hits": self.cache_hits.value,
                    "misses": self.cache_misses.value,
                    "hit_rate": self.cache_hit_rate,
                    "latency": self.cache_latency.to_dict(),
                },
                "llm": {
                    "requests_total": self.llm_requests_total.value,
                    "by_provider": {k: v.value for k, v in self.llm_requests_by_provider.items()},
                    "latency": self.llm_latency.to_dict(),
                    "tokens_input": self.llm_tokens_input.value,
                    "tokens_output": self.llm_tokens_output.value,
                    "errors_by_provider": {
                        k: v.value for k, v in self.llm_errors_by_provider.items()
                    },
                },
                "errors": {
                    "total": self.errors_total.value,
                    "by_type": {k: v.value for k, v in self.errors_by_type.items()},
                    "by_layer": {k: v.value for k, v in self.errors_by_layer.items()},
                },
                "conversations": {
                    "total": self.conversations_total.value,
                    "turns_total": self.conversation_turns_total.value,
                    "active": self.active_conversations.value,
                },
            }
    
    def get_prometheus_metrics(self) -> Optional[bytes]:
        """Get Prometheus-formatted metrics."""
        if not PROMETHEUS_AVAILABLE:
            return None
        return generate_latest()
    
    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        with self._metrics_lock:
            self.__init__()
            self._initialized = True


# Global metrics instance
_metrics: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics
