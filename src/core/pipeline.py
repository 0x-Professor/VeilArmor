"""Main security pipeline orchestrator"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any

from src.classifier import ThreatClassifier, ClassificationResult
from src.sanitizer import InputSanitizer, OutputSanitizer
from src.llm import LLMGateway, get_llm_gateway
from src.core.config import Settings, get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class Action(str, Enum):
    """Possible actions for a request"""
    PASS = "PASS"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    """Threat severity levels"""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class PipelineResult:
    """Result from the security pipeline"""
    success: bool
    action: Action
    response: Optional[str] = None
    original_prompt: Optional[str] = None
    sanitized_prompt: Optional[str] = None
    threats_detected: List[str] = None
    severity: Severity = Severity.NONE
    message: Optional[str] = None
    
    def __post_init__(self):
        if self.threats_detected is None:
            self.threats_detected = []
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "action": self.action.value,
            "response": self.response,
            "threats_detected": self.threats_detected,
            "severity": self.severity.value,
            "message": self.message
        }


class SecurityPipeline:
    """
    Main security pipeline that orchestrates:
    1. Classification of threats
    2. Decision making (block/sanitize/pass)
    3. Sanitization if needed
    4. LLM gateway
    5. Response analysis
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        
        # Initialize components
        self.classifier = ThreatClassifier(self.settings)
        self.input_sanitizer = InputSanitizer(self.settings)
        self.output_sanitizer = OutputSanitizer(self.settings)
        self.llm_gateway = get_llm_gateway(self.settings)
        
        logger.info("Security pipeline initialized")
    
    async def process(self, prompt: str, user_id: Optional[str] = None) -> PipelineResult:
        """
        Process a user prompt through the security pipeline.
        
        Args:
            prompt: User's input prompt
            user_id: Optional user identifier for logging
            
        Returns:
            PipelineResult with action taken and response
        """
        logger.info(f"Processing prompt from user: {user_id or 'anonymous'}")
        
        # Step 1: Classify the prompt
        classification = self.classifier.classify(prompt)
        logger.debug(f"Classification result: {classification}")
        
        # Step 2: Decide action based on classification
        action = self._decide_action(classification)
        logger.info(f"Decision: {action.value} (Severity: {classification.severity})")
        
        # Step 3: Handle based on action
        if action == Action.BLOCK:
            return PipelineResult(
                success=False,
                action=Action.BLOCK,
                original_prompt=prompt,
                threats_detected=classification.threats,
                severity=Severity(classification.severity),
                message="Your request was blocked due to security policy"
            )
        
        # Step 4: Sanitize if needed
        processed_prompt = prompt
        if action == Action.SANITIZE:
            processed_prompt = self.input_sanitizer.sanitize(prompt)
            logger.debug(f"Sanitized prompt: {processed_prompt[:100]}...")
        
        # Step 5: Send to LLM
        llm_response = await self.llm_gateway.generate(processed_prompt)
        
        # Step 6: Analyze and sanitize response
        safe_response = self.output_sanitizer.sanitize(llm_response)
        
        return PipelineResult(
            success=True,
            action=action,
            response=safe_response,
            original_prompt=prompt,
            sanitized_prompt=processed_prompt if action == Action.SANITIZE else None,
            threats_detected=classification.threats,
            severity=Severity(classification.severity),
            message="Request processed successfully"
        )
    
    def _decide_action(self, classification: ClassificationResult) -> Action:
        """Decide what action to take based on classification"""
        
        severity = classification.severity
        
        # Check if should block
        if severity in self.settings.security.block_severity:
            return Action.BLOCK
        
        # Check if should sanitize
        if severity in self.settings.security.sanitize_severity:
            return Action.SANITIZE
        
        # Check if has any threats but low confidence
        if classification.threats and classification.confidence < self.settings.security.classifier.confidence_threshold:
            return Action.SANITIZE
        
        # Default: pass through
        return Action.PASS