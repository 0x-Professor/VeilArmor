"""
Data models for Veil Armor
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import uuid


class ThreatLevel(Enum):
    """Threat level classification"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScannerType(Enum):
    """Available scanner types"""
    VECTORDB = "vectordb"
    YARA = "yara"
    TRANSFORMER = "transformer"
    SIMILARITY = "similarity"
    SENTIMENT = "sentiment"
    CANARY = "canary"
    RELEVANCE = "relevance"


@dataclass
class ScanResult:
    """
    Result from scanning a prompt/response.
    
    Attributes:
        is_threat: Whether a threat was detected
        risk_score: Aggregated risk score (0.0-1.0)
        threat_level: Classification of threat severity
        prompt: Original input prompt
        response: LLM response (if scanned)
        messages: List of detection messages
        detections: Details from each scanner
        metadata: Additional metadata
        uuid: Unique identifier for this scan
        timestamp: When the scan occurred
    """
    is_threat: bool
    risk_score: float
    threat_level: ThreatLevel
    prompt: str
    response: Optional[str] = None
    messages: List[str] = field(default_factory=list)
    detections: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'uuid': self.uuid,
            'timestamp': self.timestamp,
            'is_threat': self.is_threat,
            'risk_score': self.risk_score,
            'threat_level': self.threat_level.value,
            'prompt': self.prompt,
            'response': self.response,
            'messages': self.messages,
            'detections': self.detections,
            'metadata': self.metadata
        }
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        import json
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class CanaryResult:
    """
    Result from canary token check.
    
    Attributes:
        detected: Whether canary token was found
        tokens: List of detected canary tokens
        positions: Positions where tokens were found
        count: Number of canaries detected
    """
    detected: bool
    tokens: List[str] = field(default_factory=list)
    positions: List[int] = field(default_factory=list)
    count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'detected': self.detected,
            'tokens': self.tokens,
            'positions': self.positions,
            'count': self.count
        }


@dataclass
class ScannerResult:
    """
    Result from an individual scanner.
    
    Attributes:
        scanner_type: Type of scanner
        detected: Whether threat was detected
        score: Confidence score (0.0-1.0)
        message: Description of detection
        details: Additional details
    """
    scanner_type: ScannerType
    detected: bool
    score: float = 0.0
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'scanner_type': self.scanner_type.value,
            'detected': self.detected,
            'score': self.score,
            'message': self.message,
            'details': self.details
        }


@dataclass
class AnalyzeRequest:
    """Request model for analysis endpoint"""
    prompt: str
    response: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AnalyzeResponse:
    """Response model for analysis endpoint"""
    status: str
    result: ScanResult
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'status': self.status,
            'result': self.result.to_dict()
        }


@dataclass
class CanaryAddRequest:
    """Request model for adding canary token"""
    prompt: str
    always: bool = False
    length: int = 16
    header: Optional[str] = None


@dataclass
class CanaryAddResponse:
    """Response model for canary addition"""
    status: str
    prompt: str
    canary_token: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'status': self.status,
            'prompt': self.prompt,
            'canary_token': self.canary_token
        }


@dataclass
class CanaryCheckRequest:
    """Request model for checking canary token"""
    text: str


@dataclass
class CanaryCheckResponse:
    """Response model for canary check"""
    status: str
    result: CanaryResult
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'status': self.status,
            'result': self.result.to_dict()
        }
