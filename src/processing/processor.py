"""
VeilArmor - Input Processor

Orchestrates the complete input processing pipeline.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from src.processing.validator import (
    InputValidator,
    StrictInputValidator,
    APIInputValidator,
    ValidationResult,
)
from src.processing.preprocessor import (
    InputPreprocessor,
    SecurityPreprocessor,
    MinimalPreprocessor,
    PreprocessorResult,
)
from src.processing.normalizer import (
    InputNormalizer,
    SemanticNormalizer,
    CacheKeyNormalizer,
    NormalizerResult,
    NormalizationLevel,
)


class ProcessingStage(str, Enum):
    """Processing pipeline stages."""
    VALIDATION = "validation"
    PREPROCESSING = "preprocessing"
    NORMALIZATION = "normalization"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class StageResult:
    """Result from a single processing stage."""
    stage: ProcessingStage
    success: bool
    input_text: str
    output_text: str
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class ProcessingResult:
    """Complete processing result."""
    success: bool
    original_text: str
    processed_text: str
    stage_results: List[StageResult] = field(default_factory=list)
    cache_key: str = ""
    total_duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def validation_result(self) -> Optional[StageResult]:
        """Get validation stage result."""
        for result in self.stage_results:
            if result.stage == ProcessingStage.VALIDATION:
                return result
        return None
    
    @property
    def preprocessing_result(self) -> Optional[StageResult]:
        """Get preprocessing stage result."""
        for result in self.stage_results:
            if result.stage == ProcessingStage.PREPROCESSING:
                return result
        return None
    
    @property
    def normalization_result(self) -> Optional[StageResult]:
        """Get normalization stage result."""
        for result in self.stage_results:
            if result.stage == ProcessingStage.NORMALIZATION:
                return result
        return None
    
    @property
    def was_modified(self) -> bool:
        """Check if input was modified."""
        return self.original_text != self.processed_text
    
    @property
    def failed_stage(self) -> Optional[ProcessingStage]:
        """Get failed stage if any."""
        for result in self.stage_results:
            if not result.success:
                return result.stage
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "was_modified": self.was_modified,
            "original_length": len(self.original_text),
            "processed_length": len(self.processed_text),
            "cache_key": self.cache_key,
            "total_duration_ms": self.total_duration_ms,
            "stages": [
                {
                    "stage": r.stage.value,
                    "success": r.success,
                    "duration_ms": r.duration_ms,
                    "error": r.error,
                }
                for r in self.stage_results
            ],
            "metadata": self.metadata,
        }


class InputProcessor:
    """
    Orchestrates the complete input processing pipeline.
    
    Combines validation, preprocessing, and normalization into
    a single processing flow.
    """
    
    # Processing mode presets
    MODES = {
        "strict": {
            "validator": StrictInputValidator,
            "preprocessor": SecurityPreprocessor,
            "normalizer": InputNormalizer,
        },
        "standard": {
            "validator": InputValidator,
            "preprocessor": InputPreprocessor,
            "normalizer": InputNormalizer,
        },
        "minimal": {
            "validator": InputValidator,
            "preprocessor": MinimalPreprocessor,
            "normalizer": InputNormalizer,
        },
        "api": {
            "validator": APIInputValidator,
            "preprocessor": InputPreprocessor,
            "normalizer": InputNormalizer,
        },
        "semantic": {
            "validator": InputValidator,
            "preprocessor": InputPreprocessor,
            "normalizer": SemanticNormalizer,
        },
    }
    
    def __init__(
        self,
        mode: str = "standard",
        validator: Optional[InputValidator] = None,
        preprocessor: Optional[InputPreprocessor] = None,
        normalizer: Optional[InputNormalizer] = None,
        generate_cache_key: bool = True,
        fail_on_validation_error: bool = True,
        fail_on_validation_warning: bool = False,
    ):
        """
        Initialize input processor.
        
        Args:
            mode: Processing mode preset
            validator: Custom validator (overrides mode)
            preprocessor: Custom preprocessor (overrides mode)
            normalizer: Custom normalizer (overrides mode)
            generate_cache_key: Generate cache key for processed text
            fail_on_validation_error: Fail processing on validation error
            fail_on_validation_warning: Fail processing on validation warning
        """
        self.mode = mode
        self.generate_cache_key = generate_cache_key
        self.fail_on_validation_error = fail_on_validation_error
        self.fail_on_validation_warning = fail_on_validation_warning
        
        # Initialize components based on mode or custom
        mode_config = self.MODES.get(mode, self.MODES["standard"])
        
        self.validator = validator or mode_config["validator"]()
        self.preprocessor = preprocessor or mode_config["preprocessor"]()
        self.normalizer = normalizer or mode_config["normalizer"]()
        
        # Cache key normalizer
        self._cache_key_normalizer = CacheKeyNormalizer()
        
        # Metrics
        self._total_processed = 0
        self._total_failed = 0
        self._total_modified = 0
    
    def process(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ProcessingResult:
        """
        Process input text through the pipeline.
        
        Args:
            text: Input text to process
            context: Optional processing context
            
        Returns:
            ProcessingResult
        """
        start_time = time.time()
        stage_results = []
        current_text = text
        ctx = context or {}
        
        # Stage 1: Validation
        validation_stage = self._run_validation(current_text, ctx)
        stage_results.append(validation_stage)
        
        if not validation_stage.success:
            self._total_failed += 1
            return ProcessingResult(
                success=False,
                original_text=text,
                processed_text=text,
                stage_results=stage_results,
                total_duration_ms=(time.time() - start_time) * 1000,
            )
        
        current_text = validation_stage.output_text
        
        # Stage 2: Preprocessing
        preprocessing_stage = self._run_preprocessing(current_text, ctx)
        stage_results.append(preprocessing_stage)
        
        if not preprocessing_stage.success:
            self._total_failed += 1
            return ProcessingResult(
                success=False,
                original_text=text,
                processed_text=current_text,
                stage_results=stage_results,
                total_duration_ms=(time.time() - start_time) * 1000,
            )
        
        current_text = preprocessing_stage.output_text
        
        # Stage 3: Normalization
        normalization_stage = self._run_normalization(current_text, ctx)
        stage_results.append(normalization_stage)
        
        if not normalization_stage.success:
            self._total_failed += 1
            return ProcessingResult(
                success=False,
                original_text=text,
                processed_text=current_text,
                stage_results=stage_results,
                total_duration_ms=(time.time() - start_time) * 1000,
            )
        
        current_text = normalization_stage.output_text
        
        # Generate cache key
        cache_key = ""
        if self.generate_cache_key:
            cache_key = self._cache_key_normalizer.generate_cache_key(current_text)
        
        # Calculate total duration
        total_duration = (time.time() - start_time) * 1000
        
        # Update metrics
        self._total_processed += 1
        if text != current_text:
            self._total_modified += 1
        
        return ProcessingResult(
            success=True,
            original_text=text,
            processed_text=current_text,
            stage_results=stage_results,
            cache_key=cache_key,
            total_duration_ms=total_duration,
            metadata={
                "mode": self.mode,
                "stages_completed": len(stage_results),
            },
        )
    
    async def process_async(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ProcessingResult:
        """
        Async version of process.
        
        Args:
            text: Input text to process
            context: Optional processing context
            
        Returns:
            ProcessingResult
        """
        # Run in thread pool for CPU-bound operations
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.process(text, context),
        )
    
    def _run_validation(
        self,
        text: str,
        context: Dict[str, Any],
    ) -> StageResult:
        """Run validation stage."""
        start_time = time.time()
        
        try:
            result = self.validator.validate(text, context)
            
            success = result.is_valid
            if not success and not self.fail_on_validation_error:
                # Continue despite errors
                success = True
            
            if result.has_warnings() and self.fail_on_validation_warning:
                success = False
            
            return StageResult(
                stage=ProcessingStage.VALIDATION,
                success=success,
                input_text=text,
                output_text=text,  # Validation doesn't modify text
                duration_ms=(time.time() - start_time) * 1000,
                details=result.to_dict(),
                error=result.errors[0]["message"] if result.errors else None,
            )
        except Exception as e:
            return StageResult(
                stage=ProcessingStage.VALIDATION,
                success=False,
                input_text=text,
                output_text=text,
                duration_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )
    
    def _run_preprocessing(
        self,
        text: str,
        context: Dict[str, Any],
    ) -> StageResult:
        """Run preprocessing stage."""
        start_time = time.time()
        
        try:
            result = self.preprocessor.preprocess(text, context)
            
            return StageResult(
                stage=ProcessingStage.PREPROCESSING,
                success=True,
                input_text=text,
                output_text=result.processed_text,
                duration_ms=(time.time() - start_time) * 1000,
                details=result.to_dict(),
            )
        except Exception as e:
            return StageResult(
                stage=ProcessingStage.PREPROCESSING,
                success=False,
                input_text=text,
                output_text=text,
                duration_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )
    
    def _run_normalization(
        self,
        text: str,
        context: Dict[str, Any],
    ) -> StageResult:
        """Run normalization stage."""
        start_time = time.time()
        
        try:
            result = self.normalizer.normalize(text, context)
            
            return StageResult(
                stage=ProcessingStage.NORMALIZATION,
                success=True,
                input_text=text,
                output_text=result.normalized_text,
                duration_ms=(time.time() - start_time) * 1000,
                details=result.to_dict(),
            )
        except Exception as e:
            return StageResult(
                stage=ProcessingStage.NORMALIZATION,
                success=False,
                input_text=text,
                output_text=text,
                duration_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )
    
    def set_mode(self, mode: str) -> None:
        """
        Set processing mode.
        
        Args:
            mode: Processing mode name
        """
        if mode not in self.MODES:
            raise ValueError(f"Unknown mode: {mode}")
        
        self.mode = mode
        mode_config = self.MODES[mode]
        
        self.validator = mode_config["validator"]()
        self.preprocessor = mode_config["preprocessor"]()
        self.normalizer = mode_config["normalizer"]()
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get processing metrics."""
        return {
            "total_processed": self._total_processed,
            "total_failed": self._total_failed,
            "total_modified": self._total_modified,
            "success_rate": (
                (self._total_processed - self._total_failed) / self._total_processed
                if self._total_processed > 0
                else 0.0
            ),
            "modification_rate": (
                self._total_modified / self._total_processed
                if self._total_processed > 0
                else 0.0
            ),
        }
    
    def reset_metrics(self) -> None:
        """Reset processing metrics."""
        self._total_processed = 0
        self._total_failed = 0
        self._total_modified = 0


class BatchInputProcessor:
    """
    Batch processor for handling multiple inputs.
    """
    
    def __init__(
        self,
        processor: Optional[InputProcessor] = None,
        max_concurrent: int = 10,
    ):
        """
        Initialize batch processor.
        
        Args:
            processor: Input processor instance
            max_concurrent: Maximum concurrent processing
        """
        self.processor = processor or InputProcessor()
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_batch(
        self,
        texts: List[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ProcessingResult]:
        """
        Process multiple texts concurrently.
        
        Args:
            texts: List of texts to process
            context: Optional shared context
            
        Returns:
            List of ProcessingResults
        """
        async def process_one(text: str) -> ProcessingResult:
            async with self._semaphore:
                return await self.processor.process_async(text, context)
        
        tasks = [process_one(text) for text in texts]
        return await asyncio.gather(*tasks)
    
    def process_batch_sync(
        self,
        texts: List[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ProcessingResult]:
        """
        Synchronous batch processing.
        
        Args:
            texts: List of texts to process
            context: Optional shared context
            
        Returns:
            List of ProcessingResults
        """
        return [self.processor.process(text, context) for text in texts]
