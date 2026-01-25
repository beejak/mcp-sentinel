"""
Remediation models for automated vulnerability fixing.
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class RemediationType(str, Enum):
    """Type of remediation action."""
    CODE_CHANGE = "code_change"
    CONFIG_CHANGE = "config_change"
    MANUAL_ACTION = "manual_action"


class CodeChange(BaseModel):
    """Represents a specific code modification."""
    file_path: str
    original_code: str
    new_code: str
    start_line: int
    end_line: int
    diff: Optional[str] = None  # Unified diff format


class RemediationSuggestion(BaseModel):
    """
    Represents a suggested fix for a vulnerability.
    """
    id: str = Field(..., description="Unique ID for this remediation")
    vulnerability_id: str = Field(..., description="ID of the vulnerability being fixed")
    type: RemediationType
    title: str = Field(..., description="Short title of the fix")
    description: str = Field(..., description="Detailed description of what this fix does")
    code_changes: List[CodeChange] = Field(default_factory=list)
    explanation: str = Field(..., description="Why this fix resolves the vulnerability")
    steps: List[str] = Field(default_factory=list, description="Step-by-step instructions to apply the fix")
    safety_notes: Optional[str] = Field(None, description="Potential side effects or required manual checks")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the correctness of the fix")
