"""
VeilArmor v2.0 - Security Pipeline

Main security pipeline orchestrating the complete security flow:
Input Processing -> Classification -> Decision -> Sanitization -> LLM -> Output Validation -> Output Sanitization
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.classifiers import ClassifierManager, ClassificationResult
from src.classifiers.manager import AggregatedResults
from src.classifiers.base import get_classifier_class, list_registered_classifiers, ClassifierType
from src.sanitization import InputSanitizer, OutputSanitizer
from src.llm import LLMGateway, LLMRequest, LLMResponse, Message, get_llm_gateway
from src.core.config import Settings, get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------

class Action(str, Enum):
    """Possible actions for a request."""
    ALLOW = "ALLOW"
    PASS = "PASS"  # Alias for ALLOW
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    """Threat severity levels."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PipelineStage(str, Enum):
    """Pipeline processing stages."""
    INPUT_PROCESSING = "input_processing"
    INPUT_CLASSIFICATION = "input_classification"
    DECISION = "decision"
    INPUT_SANITIZATION = "input_sanitization"
    CACHE_CHECK = "cache_check"
    LLM_CALL = "llm_call"
    OUTPUT_CLASSIFICATION = "output_classification"
    OUTPUT_VALIDATION = "output_validation"
    OUTPUT_SANITIZATION = "output_sanitization"


# ---------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------

@dataclass
class StageResult:
    """Result from a pipeline stage."""
    stage: PipelineStage
    success: bool
    duration_ms: float
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class PipelineContext:
    """Context passed through the pipeline."""
    request_id: str
    user_id: Optional[str]
    conversation_id: Optional[str]
    original_prompt: str
    processed_prompt: Optional[str] = None
    sanitized_prompt: Optional[str] = None
    llm_response: Optional[str] = None
    final_response: Optional[str] = None
    classification: Optional[AggregatedResults] = None
    output_classification: Optional[AggregatedResults] = None
    action: Action = Action.ALLOW
    severity: Severity = Severity.NONE
    threats_detected: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    stage_results: List[StageResult] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    cache_hit: bool = False


@dataclass
class PipelineResult:
    """Result from the security pipeline."""
    success: bool
    action: Action
    response: Optional[str] = None
    original_prompt: Optional[str] = None
    sanitized_prompt: Optional[str] = None
    threats_detected: List[str] = field(default_factory=list)
    severity: Severity = Severity.NONE
    message: Optional[str] = None
    request_id: Optional[str] = None
    processing_time_ms: float = 0.0
    cache_hit: bool = False
    stage_results: List[StageResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "action": self.action.value,
            "response": self.response,
            "threats_detected": self.threats_detected,
            "severity": self.severity.value,
            "message": self.message,
            "request_id": self.request_id,
            "processing_time_ms": self.processing_time_ms,
            "cache_hit": self.cache_hit,
        }


@dataclass
class PipelineConfig:
    """Pipeline configuration."""
    enable_input_processing: bool = True
    enable_input_classification: bool = True
    enable_input_sanitization: bool = True
    enable_cache: bool = True
    enable_output_classification: bool = True
    enable_output_validation: bool = True
    enable_output_sanitization: bool = True
    fail_open: bool = False  # If True, allow on error
    timeout_seconds: float = 30.0
    max_retries: int = 2


# ---------------------------------------------------------------------
# Pipeline Hooks
# ---------------------------------------------------------------------

class PipelineHooks:
    """Hooks for pipeline events."""
    
    def __init__(self):
        self._pre_process: List[Callable] = []
        self._post_process: List[Callable] = []
        self._on_block: List[Callable] = []
        self._on_error: List[Callable] = []
    
    def add_pre_process(self, hook: Callable) -> None:
        """Add pre-process hook."""
        self._pre_process.append(hook)
    
    def add_post_process(self, hook: Callable) -> None:
        """Add post-process hook."""
        self._post_process.append(hook)
    
    def add_on_block(self, hook: Callable) -> None:
        """Add on-block hook."""
        self._on_block.append(hook)
    
    def add_on_error(self, hook: Callable) -> None:
        """Add on-error hook."""
        self._on_error.append(hook)
    
    async def run_pre_process(self, ctx: PipelineContext) -> None:
        """Run pre-process hooks."""
        for hook in self._pre_process:
            if asyncio.iscoroutinefunction(hook):
                await hook(ctx)
            else:
                hook(ctx)
    
    async def run_post_process(self, ctx: PipelineContext, result: PipelineResult) -> None:
        """Run post-process hooks."""
        for hook in self._post_process:
            if asyncio.iscoroutinefunction(hook):
                await hook(ctx, result)
            else:
                hook(ctx, result)
    
    async def run_on_block(self, ctx: PipelineContext) -> None:
        """Run on-block hooks."""
        for hook in self._on_block:
            if asyncio.iscoroutinefunction(hook):
                await hook(ctx)
            else:
                hook(ctx)
    
    async def run_on_error(self, ctx: PipelineContext, error: Exception) -> None:
        """Run on-error hooks."""
        for hook in self._on_error:
            if asyncio.iscoroutinefunction(hook):
                await hook(ctx, error)
            else:
                hook(ctx, error)


# ---------------------------------------------------------------------
# Security Pipeline
# ---------------------------------------------------------------------

class SecurityPipeline:
    """
    Main security pipeline orchestrating the complete security flow.
    
    Pipeline Stages:
    1. Input Processing (validation, preprocessing, normalization)
    2. Input Classification (threat detection)
    3. Decision (block/sanitize/allow)
    4. Input Sanitization (if needed)
    5. Cache Check (semantic cache lookup)
    6. LLM Call (generate response)
    7. Output Classification (response analysis)
    8. Output Validation (quality checks)
    9. Output Sanitization (PII/credential removal)
    
    Features:
    - Configurable stages
    - Plugin hooks
    - Detailed metrics
    - Error handling with fail-open/fail-closed
    - Request correlation
    """
    
    def __init__(
        self,
        settings: Optional[Settings] = None,
        config: Optional[PipelineConfig] = None,
    ):
        """
        Initialize security pipeline.
        
        Args:
            settings: Application settings
            config: Pipeline configuration
        """
        self.settings = settings or get_settings()
        self.config = config or PipelineConfig()
        
        # Initialize components
        self.classifier = ClassifierManager()
        self._load_classifiers()  # Register all available classifiers
        self.input_sanitizer = InputSanitizer()
        self.output_sanitizer = OutputSanitizer()
        self.llm_gateway = get_llm_gateway(self.settings)
        
        # Optional components (lazy loaded)
        self._input_processor = None
        self._validation_engine = None
        self._semantic_cache = None
        self._conversation_manager = None
        
        # Hooks
        self.hooks = PipelineHooks()
        
        # Metrics
        self._total_requests = 0
        self._blocked_requests = 0
        self._sanitized_requests = 0
        self._cache_hits = 0
        self._errors = 0
        
        logger.info(
            f"Security pipeline initialized (cache={self.config.enable_cache})"
        )
    
    def _load_classifiers(self) -> None:
        """
        Load and register all classifiers from the registry.
        
        Uses the @register_classifier decorator registry to discover
        available classifier classes, then instantiates and registers
        them with the ClassifierManager using config from settings.
        """
        # Get per-classifier config from settings if available
        classifier_config = getattr(self.settings.security, 'classifier', None)
        enabled_list = getattr(classifier_config, 'enabled_classifiers', None) if classifier_config else None
        
        registered_names = list_registered_classifiers()
        loaded_count = 0
        
        for name in registered_names:
            cls = get_classifier_class(name)
            if cls is None:
                continue
            
            # Determine if this classifier should be enabled
            enabled = True
            if enabled_list is not None:
                # Map config names to registry names (e.g. "pii" -> "pii_detector")
                enabled = name in enabled_list or any(
                    name.startswith(e) for e in enabled_list
                )
            
            try:
                instance = cls(enabled=enabled)
                self.classifier.register(instance)
                loaded_count += 1
            except Exception as e:
                logger.warning(
                    f"Failed to load classifier '{name}': {e}"
                )
        
        logger.info(
            f"Loaded {loaded_count} classifiers from registry "
            f"({len(self.classifier.get_input_classifiers())} input, "
            f"{len(self.classifier.get_output_classifiers())} output)"
        )
    
    # -----------------------------------------------------------------
    # Properties for Optional Components
    # -----------------------------------------------------------------
    
    @property
    def input_processor(self):
        """Get input processor (lazy loaded)."""
        if self._input_processor is None:
            try:
                from src.processing import InputProcessor
                self._input_processor = InputProcessor()
            except ImportError:
                pass
        return self._input_processor
    
    @property
    def validation_engine(self):
        """Get validation engine (lazy loaded)."""
        if self._validation_engine is None:
            try:
                from src.validation import ValidationEngine
                self._validation_engine = ValidationEngine()
            except ImportError:
                pass
        return self._validation_engine
    
    @property
    def semantic_cache(self):
        """Get semantic cache (lazy loaded)."""
        if self._semantic_cache is None and self.config.enable_cache:
            try:
                from src.cache import SemanticCache
                self._semantic_cache = SemanticCache()
            except ImportError:
                pass
        return self._semantic_cache
    
    @property
    def conversation_manager(self):
        """Get conversation manager (lazy loaded)."""
        if self._conversation_manager is None:
            try:
                from src.conversation import ConversationManager
                self._conversation_manager = ConversationManager()
            except ImportError:
                pass
        return self._conversation_manager
    
    # -----------------------------------------------------------------
    # Main Processing
    # -----------------------------------------------------------------
    
    async def process(
        self,
        prompt: str,
        user_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """
        Process a user prompt through the security pipeline.
        
        Args:
            prompt: User's input prompt
            user_id: Optional user identifier
            conversation_id: Optional conversation ID
            metadata: Additional metadata
            
        Returns:
            PipelineResult with action taken and response
        """
        # Create context
        ctx = PipelineContext(
            request_id=str(uuid.uuid4()),
            user_id=user_id,
            conversation_id=conversation_id,
            original_prompt=prompt,
            metadata=metadata or {},
        )
        
        self._total_requests += 1
        
        logger.info(
            f"Processing request {ctx.request_id} (user={user_id})"
        )
        
        try:
            # Run pre-process hooks
            await self.hooks.run_pre_process(ctx)
            
            # Execute pipeline stages
            result = await self._execute_pipeline(ctx)
            
            # Run post-process hooks
            await self.hooks.run_post_process(ctx, result)
            
            return result
            
        except asyncio.TimeoutError:
            self._errors += 1
            logger.error(
                f"Pipeline timeout for request {ctx.request_id}"
            )
            
            if self.config.fail_open:
                return self._create_error_result(ctx, "Request timed out")
            else:
                return self._create_block_result(ctx, "Request timed out for security")
                
        except Exception as e:
            self._errors += 1
            await self.hooks.run_on_error(ctx, e)
            
            logger.error(
                f"Pipeline error for request {ctx.request_id}: {str(e)}"
            )
            
            if self.config.fail_open:
                return self._create_error_result(ctx, str(e))
            else:
                return self._create_block_result(ctx, "Request blocked due to error")
    
    async def _execute_pipeline(self, ctx: PipelineContext) -> PipelineResult:
        """Execute the pipeline stages."""
        
        # Stage 1: Input Processing
        if self.config.enable_input_processing:
            await self._stage_input_processing(ctx)
        else:
            ctx.processed_prompt = ctx.original_prompt
        
        # Stage 2: Input Classification
        if self.config.enable_input_classification:
            await self._stage_input_classification(ctx)
        
        # Stage 3: Decision
        await self._stage_decision(ctx)
        
        # Check if blocked
        if ctx.action == Action.BLOCK:
            self._blocked_requests += 1
            await self.hooks.run_on_block(ctx)
            return self._create_block_result(ctx)
        
        # Stage 4: Input Sanitization
        if self.config.enable_input_sanitization and ctx.action == Action.SANITIZE:
            await self._stage_input_sanitization(ctx)
            self._sanitized_requests += 1
        else:
            ctx.sanitized_prompt = ctx.processed_prompt
        
        # Stage 5: Cache Check
        if self.config.enable_cache:
            cached = await self._stage_cache_check(ctx)
            if cached:
                self._cache_hits += 1
                return self._create_success_result(ctx)
        
        # Stage 6: LLM Call
        await self._stage_llm_call(ctx)
        
        # Stage 7: Output Classification
        if self.config.enable_output_classification:
            await self._stage_output_classification(ctx)
        
        # Stage 8: Output Validation
        if self.config.enable_output_validation:
            await self._stage_output_validation(ctx)
        
        # Stage 9: Output Sanitization
        if self.config.enable_output_sanitization:
            await self._stage_output_sanitization(ctx)
        else:
            ctx.final_response = ctx.llm_response
        
        # Cache response
        if self.config.enable_cache and self.semantic_cache:
            await self._cache_response(ctx)
        
        return self._create_success_result(ctx)
    
    # -----------------------------------------------------------------
    # Pipeline Stages
    # -----------------------------------------------------------------
    
    async def _stage_input_processing(self, ctx: PipelineContext) -> None:
        """Stage 1: Input processing."""
        start = time.time()
        
        try:
            if self.input_processor:
                result = self.input_processor.process(ctx.original_prompt)
                ctx.processed_prompt = result.processed_text if result.success else ctx.original_prompt
            else:
                ctx.processed_prompt = ctx.original_prompt
            
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.INPUT_PROCESSING,
                success=True,
                duration_ms=(time.time() - start) * 1000,
            ))
            
        except Exception as e:
            ctx.processed_prompt = ctx.original_prompt
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.INPUT_PROCESSING,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
    
    async def _stage_input_classification(self, ctx: PipelineContext) -> None:
        """Stage 2: Input classification."""
        start = time.time()
        
        try:
            ctx.classification = await self.classifier.classify_input(
                ctx.processed_prompt or ctx.original_prompt
            )
            # Extract threat types from results that are actual threats
            ctx.threats_detected = [
                r.threat_type for r in ctx.classification.get_threats()
            ]
            ctx.severity = self._map_severity(ctx.classification.max_severity)
            
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.INPUT_CLASSIFICATION,
                success=True,
                duration_ms=(time.time() - start) * 1000,
                data={
                    "threats": ctx.threats_detected,
                    "severity": ctx.severity.value,
                    "aggregated_score": ctx.classification.aggregated_score,
                },
            ))
            
            logger.debug(
                f"Classification complete for {ctx.request_id}: "
                f"threats={ctx.threats_detected}, severity={ctx.severity.value}"
            )
            
        except Exception as e:
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.INPUT_CLASSIFICATION,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
    
    async def _stage_decision(self, ctx: PipelineContext) -> None:
        """Stage 3: Decision making."""
        start = time.time()
        
        try:
            ctx.action = self._decide_action(ctx.classification)
            
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.DECISION,
                success=True,
                duration_ms=(time.time() - start) * 1000,
                data={"action": ctx.action.value},
            ))
            
            logger.info(
                f"Decision made for {ctx.request_id}: action={ctx.action.value}"
            )
            
        except Exception as e:
            ctx.action = Action.BLOCK if not self.config.fail_open else Action.ALLOW
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.DECISION,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
    
    async def _stage_input_sanitization(self, ctx: PipelineContext) -> None:
        """Stage 4: Input sanitization."""
        start = time.time()
        
        try:
            result = self.input_sanitizer.sanitize(
                ctx.processed_prompt or ctx.original_prompt
            )
            ctx.sanitized_prompt = result.sanitized_text
            
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.INPUT_SANITIZATION,
                success=True,
                duration_ms=(time.time() - start) * 1000,
                data={
                    "was_modified": result.was_modified,
                    "strategies_applied": result.strategies_applied,
                },
            ))
            
        except Exception as e:
            ctx.sanitized_prompt = ctx.processed_prompt or ctx.original_prompt
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.INPUT_SANITIZATION,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
    
    async def _stage_cache_check(self, ctx: PipelineContext) -> bool:
        """Stage 5: Cache check."""
        start = time.time()
        
        try:
            if not self.semantic_cache:
                return False
            
            prompt = ctx.sanitized_prompt or ctx.processed_prompt or ctx.original_prompt
            result = await self.semantic_cache.get(prompt)
            
            if result and result.hit:
                ctx.llm_response = result.response
                ctx.final_response = result.response
                ctx.cache_hit = True
                
                ctx.stage_results.append(StageResult(
                    stage=PipelineStage.CACHE_CHECK,
                    success=True,
                    duration_ms=(time.time() - start) * 1000,
                    data={"hit": True, "similarity": result.similarity},
                ))
                
                logger.debug(
                    f"Cache hit for {ctx.request_id} (similarity={result.similarity})"
                )
                
                return True
            
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.CACHE_CHECK,
                success=True,
                duration_ms=(time.time() - start) * 1000,
                data={"hit": False},
            ))
            
            return False
            
        except Exception as e:
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.CACHE_CHECK,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
            return False
    
    async def _stage_llm_call(self, ctx: PipelineContext) -> None:
        """Stage 6: LLM call."""
        start = time.time()
        
        try:
            prompt = ctx.sanitized_prompt or ctx.processed_prompt or ctx.original_prompt
            llm_request = LLMRequest(
                messages=[Message(role="user", content=prompt)],
            )
            response = await self.llm_gateway.generate(llm_request)
            ctx.llm_response = response.content
            
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.LLM_CALL,
                success=True,
                duration_ms=(time.time() - start) * 1000,
                data={
                    "model": response.model,
                    "provider": response.provider,
                    "total_tokens": response.total_tokens,
                },
            ))
            
        except Exception as e:
            ctx.llm_response = None
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.LLM_CALL,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
            raise
    
    async def _stage_output_classification(self, ctx: PipelineContext) -> None:
        """Stage 7: Output classification."""
        start = time.time()
        
        try:
            if ctx.llm_response:
                ctx.output_classification = await self.classifier.classify_output(
                    ctx.llm_response
                )
                
                output_threats = [
                    r.threat_type for r in ctx.output_classification.get_threats()
                ]
                
                # Merge output threats into the context so they appear in the result
                if output_threats:
                    ctx.threats_detected.extend(output_threats)
                    output_severity = self._map_severity(
                        ctx.output_classification.max_severity
                    )
                    # Escalate severity if output is worse than input
                    if output_severity.value > ctx.severity.value:
                        ctx.severity = output_severity
                    logger.warning(
                        f"Output threats detected for {ctx.request_id}: {output_threats}"
                    )
                
                ctx.stage_results.append(StageResult(
                    stage=PipelineStage.OUTPUT_CLASSIFICATION,
                    success=True,
                    duration_ms=(time.time() - start) * 1000,
                    data={
                        "threats": output_threats,
                        "max_severity": ctx.output_classification.max_severity,
                    },
                ))
            
        except Exception as e:
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.OUTPUT_CLASSIFICATION,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
    
    async def _stage_output_validation(self, ctx: PipelineContext) -> None:
        """Stage 8: Output validation."""
        start = time.time()
        
        try:
            if self.validation_engine and ctx.llm_response:
                result = await self.validation_engine.validate(ctx.llm_response)
                
                # Enforce validation: if invalid, flag the response
                if not result.is_valid:
                    logger.warning(
                        f"Output validation failed for {ctx.request_id}: "
                        f"{len(result.violations)} violations"
                    )
                    ctx.metadata["validation_failed"] = True
                    ctx.metadata["validation_violations"] = [
                        {"rule": v.rule_name, "message": v.message}
                        for v in result.violations
                    ]
                
                ctx.stage_results.append(StageResult(
                    stage=PipelineStage.OUTPUT_VALIDATION,
                    success=result.is_valid,
                    duration_ms=(time.time() - start) * 1000,
                    data={
                        "is_valid": result.is_valid,
                        "violations": len(result.violations),
                    },
                ))
            
        except Exception as e:
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.OUTPUT_VALIDATION,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
    
    async def _stage_output_sanitization(self, ctx: PipelineContext) -> None:
        """Stage 9: Output sanitization."""
        start = time.time()
        
        try:
            if ctx.llm_response:
                result = self.output_sanitizer.sanitize(ctx.llm_response)
                ctx.final_response = result.sanitized_text
            else:
                ctx.final_response = None
            
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.OUTPUT_SANITIZATION,
                success=True,
                duration_ms=(time.time() - start) * 1000,
            ))
            
        except Exception as e:
            ctx.final_response = ctx.llm_response
            ctx.stage_results.append(StageResult(
                stage=PipelineStage.OUTPUT_SANITIZATION,
                success=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e),
            ))
    
    async def _cache_response(self, ctx: PipelineContext) -> None:
        """Cache the response."""
        try:
            if self.semantic_cache and ctx.final_response:
                prompt = ctx.sanitized_prompt or ctx.processed_prompt or ctx.original_prompt
                await self.semantic_cache.set(prompt, ctx.final_response)
        except Exception as e:
            logger.warning(f"Failed to cache response: {str(e)}")
    
    # -----------------------------------------------------------------
    # Decision Making
    # -----------------------------------------------------------------
    
    @staticmethod
    def _map_severity(score: float) -> Severity:
        """Map a numeric severity score (0.0-1.0) to a Severity enum."""
        if score >= 0.8:
            return Severity.CRITICAL
        elif score >= 0.6:
            return Severity.HIGH
        elif score >= 0.4:
            return Severity.MEDIUM
        elif score >= 0.2:
            return Severity.LOW
        return Severity.NONE

    def _decide_action(self, classification: Optional[AggregatedResults]) -> Action:
        """Decide what action to take based on classification."""
        if classification is None:
            return Action.ALLOW
        
        severity = self._map_severity(classification.max_severity)
        
        # Check if should block
        if severity.value in self.settings.security.block_severity:
            return Action.BLOCK
        
        # Check if should sanitize
        if severity.value in self.settings.security.sanitize_severity:
            return Action.SANITIZE
        
        # Any detected threats with moderate score -> sanitize
        if classification.threat_count > 0 and classification.aggregated_score >= 0.3:
            return Action.SANITIZE
        
        return Action.ALLOW
    
    # -----------------------------------------------------------------
    # Result Creation
    # -----------------------------------------------------------------
    
    def _create_success_result(self, ctx: PipelineContext) -> PipelineResult:
        """Create success result."""
        return PipelineResult(
            success=True,
            action=ctx.action,
            response=ctx.final_response,
            original_prompt=ctx.original_prompt,
            sanitized_prompt=ctx.sanitized_prompt if ctx.action == Action.SANITIZE else None,
            threats_detected=ctx.threats_detected,
            severity=ctx.severity,
            message="Request processed successfully",
            request_id=ctx.request_id,
            processing_time_ms=(time.time() - ctx.start_time) * 1000,
            cache_hit=ctx.cache_hit,
            stage_results=ctx.stage_results,
        )
    
    def _create_block_result(
        self,
        ctx: PipelineContext,
        message: str = "Request blocked due to security policy",
    ) -> PipelineResult:
        """Create block result."""
        return PipelineResult(
            success=False,
            action=Action.BLOCK,
            original_prompt=ctx.original_prompt,
            threats_detected=ctx.threats_detected,
            severity=ctx.severity,
            message=message,
            request_id=ctx.request_id,
            processing_time_ms=(time.time() - ctx.start_time) * 1000,
            stage_results=ctx.stage_results,
        )
    
    def _create_error_result(
        self,
        ctx: PipelineContext,
        error: str,
    ) -> PipelineResult:
        """Create error result."""
        return PipelineResult(
            success=False,
            action=Action.ALLOW,
            message=f"Error: {error}",
            request_id=ctx.request_id,
            processing_time_ms=(time.time() - ctx.start_time) * 1000,
            stage_results=ctx.stage_results,
        )
    
    # -----------------------------------------------------------------
    # Metrics
    # -----------------------------------------------------------------
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get pipeline metrics."""
        return {
            "total_requests": self._total_requests,
            "blocked_requests": self._blocked_requests,
            "sanitized_requests": self._sanitized_requests,
            "cache_hits": self._cache_hits,
            "errors": self._errors,
            "block_rate": (
                self._blocked_requests / self._total_requests
                if self._total_requests > 0 else 0
            ),
            "cache_hit_rate": (
                self._cache_hits / self._total_requests
                if self._total_requests > 0 else 0
            ),
        }


# ---------------------------------------------------------------------
# Factory Functions
# ---------------------------------------------------------------------

def create_pipeline(
    settings: Optional[Settings] = None,
    **config_kwargs,
) -> SecurityPipeline:
    """
    Create a security pipeline.
    
    Args:
        settings: Application settings
        **config_kwargs: Pipeline configuration options
        
    Returns:
        Configured SecurityPipeline
    """
    config = PipelineConfig(**config_kwargs)
    return SecurityPipeline(settings=settings, config=config)


def create_minimal_pipeline(settings: Optional[Settings] = None) -> SecurityPipeline:
    """Create a minimal pipeline with only essential stages."""
    config = PipelineConfig(
        enable_input_processing=False,
        enable_cache=False,
        enable_output_classification=False,
        enable_output_validation=False,
    )
    return SecurityPipeline(settings=settings, config=config)


def create_strict_pipeline(settings: Optional[Settings] = None) -> SecurityPipeline:
    """Create a strict pipeline with all security features."""
    config = PipelineConfig(
        enable_input_processing=True,
        enable_input_classification=True,
        enable_input_sanitization=True,
        enable_cache=True,
        enable_output_classification=True,
        enable_output_validation=True,
        enable_output_sanitization=True,
        fail_open=False,
    )
    return SecurityPipeline(settings=settings, config=config)