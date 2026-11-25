"""Layer 2: AI Requirement & Edge-Case Verifier (Groq LPU with Offline Fallback)."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from dotenv import load_dotenv

from core.schemas import (
    DefectCategory,
    DefectItem,
    DefectSeverity,
    LLMReviewOutput,
    RequirementCheck,
    RequirementStatus,
)

load_dotenv(override=True)

SYSTEM_PROMPT = """You are a senior software engineer performing a pre-merge code review on AI-generated Python code.
Your job is to:
1. Break the user's written requirements into individual, atomic requirements and verify whether the code implements each one:
   - "Met": Fully implemented and working.
   - "Partial": Attempted or works in normal cases, but misses an edge case or detail.
   - "Missing": Completely absent or ignored.

2. Identify bugs and edge cases with accurate severity:
   - "Critical": ONLY for security vulnerabilities (SQL injection, hardcoded secrets, eval/exec), remote exploits, or total failure to provide working code.
   - "High": Runtime crashes on edge cases (ZeroDivisionError, IndexError, NoneType, unhandled empty input) or missing validation guards.
   - "Medium": Bad practices, mutable default arguments (def fn(x=[])), swallowed exceptions (except: pass), or logic imperfections.
   - "Low": Minor code style, naming, or dead code.

3. Do NOT duplicate issues already reported by Layer 1 static analysis unless linking them to a requirement.

Return ONLY valid JSON matching this exact structure:
{
  "summary": "2-3 sentence concise engineering review summary.",
  "requirement_checks": [
    {
      "requirement_text": "Single requirement bullet extracted from the prompt",
      "status": "Met | Partial | Missing",
      "explanation": "Concrete evidence from the code explaining this status"
    }
  ],
  "defects": [
    {
      "category": "Security | Logic | Requirement | Code Quality",
      "severity": "Critical | High | Medium | Low",
      "line_number": 1,
      "description": "Clear explanation of the bug or unhandled edge case",
      "suggested_fix": "Specific, actionable code fix"
    }
  ]
}
"""

VALID_CATEGORIES: dict[str, DefectCategory] = {
    "security": "Security",
    "logic": "Logic",
    "requirement": "Requirement",
    "code quality": "Code Quality",
    "syntax": "Syntax",
}

VALID_SEVERITIES: dict[str, DefectSeverity] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

VALID_STATUSES: dict[str, RequirementStatus] = {
    "met": "Met",
    "partial": "Partial",
    "partially met": "Partial",
    "missing": "Missing",
    "not met": "Missing",
}

STOPWORDS = {
    "the", "and", "for", "that", "with", "from", "this", "must", "should",
    "have", "into", "when", "then", "also", "will", "write", "python",
    "function", "code", "returns", "return", "using", "user", "users",
}


def _add_line_numbers(code: str) -> str:
    return "\n".join(
        f"{idx}: {line}" for idx, line in enumerate(code.splitlines(), start=1)
    )


def _build_user_prompt(
    requirements_text: str, code: str, static_defects: list[DefectItem]
) -> str:
    req_block = requirements_text.strip() or "No explicit requirements provided."
    if static_defects:
        static_lines = "\n".join(
            f"- [{d.severity}] ({d.category}) Line {d.line_number or '?'}: {d.description}"
            for d in static_defects
        )
    else:
        static_lines = "None."

    return (
        f"### Written Requirements\n{req_block}\n\n"
        f"### Layer 1 Static Analysis Findings\n{static_lines}\n\n"
        f"### Submitted Python Code (with line numbers)\n```python\n"
        f"{_add_line_numbers(code)}\n```\n\n"
        "Respond strictly with the requested JSON object."
    )


def _strip_json_fences(raw_text: str) -> str:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def _normalize_line_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 1:
        return value
    if isinstance(value, str) and value.isdigit() and int(value) >= 1:
        return int(value)
    return None


def _parse_llm_json(raw_text: str, provider: str) -> LLMReviewOutput:
    data = json.loads(_strip_json_fences(raw_text))
    if not isinstance(data, dict):
        raise ValueError("LLM response JSON root must be an object.")

    checks: list[RequirementCheck] = []
    for item in data.get("requirement_checks", []) or []:
        if not isinstance(item, dict):
            continue
        req_text = str(item.get("requirement_text", "")).strip()
        explanation = str(item.get("explanation", "")).strip() or "No explanation provided."
        raw_status = str(item.get("status", "Partial")).strip().lower()
        status: RequirementStatus = VALID_STATUSES.get(raw_status, "Partial")
        if req_text:
            checks.append(
                RequirementCheck(
                    requirement_text=req_text,
                    status=status,
                    explanation=explanation,
                )
            )

    defects: list[DefectItem] = []
    for item in data.get("defects", []) or []:
        if not isinstance(item, dict):
            continue
        description = str(item.get("description", "")).strip()
        if not description:
            continue
        suggested_fix = (
            str(item.get("suggested_fix", "")).strip()
            or "Review and fix this logic or requirement issue."
        )
        raw_cat = str(item.get("category", "Logic")).strip().lower()
        raw_sev = str(item.get("severity", "Medium")).strip().lower()
        category: DefectCategory = VALID_CATEGORIES.get(raw_cat, "Logic")
        severity: DefectSeverity = VALID_SEVERITIES.get(raw_sev, "Medium")
        defects.append(
            DefectItem(
                category=category,
                severity=severity,
                line_number=_normalize_line_number(item.get("line_number")),
                description=description,
                suggested_fix=suggested_fix,
                source="llm",
            )
        )

    summary = str(data.get("summary", "")).strip()
    return LLMReviewOutput(
        requirement_checks=checks,
        defects=defects,
        summary=summary,
        provider_used=provider,
    )

DEFAULT_GROQ_MODELS = [
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
]

def _call_groq(user_prompt: str) -> LLMReviewOutput:
    load_dotenv(override=True)
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key or api_key.startswith("your_"):
        raise RuntimeError("GROQ_API_KEY is not configured.")

    from groq import Groq

    client = Groq(api_key=api_key)

    candidate_models: list[str] = []
    env_model = os.getenv("GROQ_MODEL", "").strip()
    if env_model:
        candidate_models.append(env_model)
    for m in DEFAULT_GROQ_MODELS:
        if m not in candidate_models:
            candidate_models.append(m)

    last_error: Exception | None = None
    for model_name in candidate_models:
        try:
            completion = client.chat.completions.create(
                model=model_name,
                temperature=0.1,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            raw_text = completion.choices[0].message.content or ""
            return _parse_llm_json(raw_text, provider=f"groq ({model_name})")
        except Exception as exc:
            last_error = exc
            continue

    if last_error:
        raise last_error
    raise RuntimeError("No Groq models could be reached.")


def _split_requirements(requirements_text: str) -> list[str]:
    lines = [
        re.sub(r"^(\s*[-*•]|\s*\d+[.)])\s*", "", line).strip()
        for line in requirements_text.splitlines()
        if line.strip()
    ]
    if len(lines) > 1:
        return lines
    if not lines:
        return []
    parts = [p.strip() for p in re.split(r";|\.(?:\s+|$)", lines[0]) if p.strip()]
    return parts if parts else lines


def _offline_heuristic_review(
    requirements_text: str, code: str, static_defects: list[DefectItem]
) -> LLMReviewOutput:
    req_items = _split_requirements(requirements_text)
    has_syntax_error = any(d.category == "Syntax" for d in static_defects)
    code_lower = code.lower()
    checks: list[RequirementCheck] = []
    defects: list[DefectItem] = []

    for req in req_items:
        req_lower = req.lower()

        if has_syntax_error:
            checks.append(
                RequirementCheck(
                    requirement_text=req,
                    status="Missing",
                    explanation="Code has syntax errors and cannot execute to satisfy this requirement.",
                )
            )
            continue

        if "valueerror" in req_lower:
            if "valueerror" in code_lower and "raise" in code_lower:
                checks.append(
                    RequirementCheck(
                        requirement_text=req,
                        status="Met",
                        explanation="Code explicitly raises ValueError for invalid input.",
                    )
                )
            else:
                checks.append(
                    RequirementCheck(
                        requirement_text=req,
                        status="Missing",
                        explanation="No 'raise ValueError' guard was detected in the code.",
                    )
                )
                defects.append(
                    DefectItem(
                        category="Requirement",
                        severity="High",
                        line_number=None,
                        description=f"Missing required ValueError validation for: {req}",
                        suggested_fix="Validate the input at the start of the function and raise ValueError.",
                        source="llm",
                    )
                )
            continue

        if "negative" in req_lower:
            has_guard = bool(re.search(r"(>=?\s*0|<\s*0|>\s*0|<=\s*0)", code))
            if has_guard:
                checks.append(
                    RequirementCheck(
                        requirement_text=req,
                        status="Met",
                        explanation="Numeric boundary comparison for negative values was detected.",
                    )
                )
            else:
                checks.append(
                    RequirementCheck(
                        requirement_text=req,
                        status="Missing",
                        explanation="No filter or check for negative numbers was detected.",
                    )
                )
                defects.append(
                    DefectItem(
                        category="Logic",
                        severity="Medium",
                        line_number=None,
                        description="Code does not appear to filter or reject negative values.",
                        suggested_fix="Add an explicit check (e.g., amount >= 0 or SQL 'AND amount >= 0').",
                        source="llm",
                    )
                )
            continue

        if "zero" in req_lower or "empty" in req_lower:
            has_guard = bool(
                re.search(r"(==\s*0|!=\s*0|not\s+\w+|len\(|is\s+none|is\s+not\s+none)", code_lower)
            )
            if has_guard:
                checks.append(
                    RequirementCheck(
                        requirement_text=req,
                        status="Met",
                        explanation="Empty/zero input validation guard was detected.",
                    )
                )
            else:
                checks.append(
                    RequirementCheck(
                        requirement_text=req,
                        status="Partial",
                        explanation="Could not verify an explicit empty/zero edge-case guard offline.",
                    )
                )
            continue

        tokens = [tok for tok in re.findall(r"[a-z_]{3,}", req_lower) if tok not in STOPWORDS]
        matched = sum(1 for tok in tokens if tok in code_lower)
        ratio = matched / len(tokens) if tokens else 1.0

        if ratio >= 0.4:
            checks.append(
                RequirementCheck(
                    requirement_text=req,
                    status="Met",
                    explanation="Offline heuristic matched relevant implementation tokens in the code.",
                )
            )
        elif ratio >= 0.2:
            checks.append(
                RequirementCheck(
                    requirement_text=req,
                    status="Partial",
                    explanation="Only partial keyword evidence was found offline.",
                )
            )
        else:
            checks.append(
                RequirementCheck(
                    requirement_text=req,
                    status="Missing",
                    explanation="No clear implementation evidence for this requirement was detected offline.",
                )
            )

    summary = (
        "Offline heuristic review completed. "
        "Add a valid GROQ_API_KEY in .env for deep semantic LLM analysis."
    )
    return LLMReviewOutput(
        requirement_checks=checks,
        defects=defects,
        summary=summary,
        provider_used="offline",
    )


def run_llm_review(
    requirements_text: str,
    code: str,
    static_defects: list[DefectItem],
    *,
    force_offline: bool = False,
) -> LLMReviewOutput:
    """Run Layer 2 review with Groq primary and offline heuristic fallback."""
    if force_offline:
        return _offline_heuristic_review(requirements_text, code, static_defects)

    user_prompt = _build_user_prompt(requirements_text, code, static_defects)

    try:
        return _call_groq(user_prompt)
    except Exception:
        return _offline_heuristic_review(requirements_text, code, static_defects)