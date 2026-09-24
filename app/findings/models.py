from enum import Enum
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
from datetime import datetime
import uuid

class Severity(str, Enum):
    """
    Severity represents the potential impact or risk of a finding.
    It does not measure how certain the tool is that the issue exists.
    """
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Confidence(str, Enum):
    """
    Confidence represents the strength of evidence for a finding.
    It indicates how certain the tool is that the finding is valid.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    category: str
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    severity: Severity
    confidence: Confidence
    evidence: str
    description: str
    remediation: str
    scanner_source: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
