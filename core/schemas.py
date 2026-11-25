"""Strict Pydantic data contracts for the Code Review & Decision Engine."""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field

DefectCategory = Literal["Security", "Logic", "Requirement", "Code Quality", "Syntax"]
DefectSeverity = Literal["Critical", "High", "Medium", "Low"]
DefectSource = Literal["static", "llm"]
RequirementStatus = Literal["Met", "Partial", "Missing"]
VerdictType = Literal["ACCEPT", "REWORK", "REJECT"]


class DefectItem(BaseModel):
    """Represents a single bug, vulnerability, or code quality issue."""

    category: DefectCategory
    severity: DefectSeverity
    line_number: Optional[int] = Field(default=None, ge=1)
    description: str = Field(..., min_length=1)
    suggested_fix: str = Field(..., min_length=1)
    source: DefectSource = "static"


class RequirementCheck(BaseModel):
    """Represents the verification result for one user requirement."""

    requirement_text: str = Field(..., min_length=1)
    status: RequirementStatus
    explanation: str = Field(..., min_length=1)


class LLMReviewOutput(BaseModel):
    """Structured response returned by Layer 2 (LLM or offline fallback)."""

    requirement_checks: list[RequirementCheck] = Field(default_factory=list)
    defects: list[DefectItem] = Field(default_factory=list)
    summary: str = ""
    provider_used: str = "offline"


class ReviewResult(BaseModel):
    """Complete review output produced by the Decision Engine."""

    verdict: VerdictType
    score: int = Field(..., ge=0, le=100)
    summary: str
    requirement_checks: list[RequirementCheck] = Field(default_factory=list)
    defects: list[DefectItem] = Field(default_factory=list)
    decision_reasons: list[str] = Field(default_factory=list)
    pr_comment: str = ""
    provider_used: str = "offline"