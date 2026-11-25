"""Deterministic Decision Engine: balanced scoring, ACCEPT/REWORK/REJECT gates, and PR report formatting."""

from __future__ import annotations

from core.llm_reviewer import run_llm_review
from core.schemas import (
    DefectItem,
    LLMReviewOutput,
    RequirementCheck,
    ReviewResult,
    VerdictType,
)
from core.static_analyzer import analyze_code

# Calibrated, fair penalty deductions (reserves < 40 for real blockers)
SEVERITY_PENALTIES: dict[str, int] = {
    "Critical": 25,  # Reserved for security exploits & fatal crashes
    "High": 10,      # Edge-case crashes (ZeroDivision, unhandled None/empty)
    "Medium": 5,     # Code smells (mutable defaults, swallowed errors)
    "Low": 2,        # Minor style or unused variables
}

REQUIREMENT_PENALTIES: dict[str, int] = {
    "Met": 0,
    "Partial": 3,    # Works in normal cases, minor detail missed
    "Missing": 10,   # Feature completely omitted
}

SEVERITY_RANK: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}

VERDICT_BADGES: dict[VerdictType, str] = {
    "ACCEPT": "🟢 ACCEPT",
    "REWORK": "🟠 REWORK",
    "REJECT": "🔴 REJECT",
}


def _merge_and_sort_defects(
    static_defects: list[DefectItem], llm_defects: list[DefectItem]
) -> list[DefectItem]:
    seen: set[tuple[str, int | None, str]] = set()
    merged: list[DefectItem] = []

    for defect in [*static_defects, *llm_defects]:
        key = (defect.category, defect.line_number, defect.description.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        merged.append(defect)

    merged.sort(
        key=lambda d: (
            SEVERITY_RANK.get(d.severity, 99),
            d.line_number if d.line_number is not None else 10**9,
            0 if d.source == "static" else 1,
            d.description,
        )
    )
    return merged


def _calculate_score(
    defects: list[DefectItem], requirement_checks: list[RequirementCheck]
) -> int:
    """Compute a graded 0-100 quality score."""
    score = 100
    for defect in defects:
        score -= SEVERITY_PENALTIES.get(defect.severity, 0)
    for req in requirement_checks:
        score -= REQUIREMENT_PENALTIES.get(req.status, 0)
    return max(0, min(100, score))


def _decide_verdict(
    score: int,
    defects: list[DefectItem],
    requirement_checks: list[RequirementCheck],
) -> tuple[VerdictType, list[str]]:
    """Apply balanced quality gates: REJECT (blockers), REWORK (needs fixes), ACCEPT (clean)."""
    reject_reasons: list[str] = []
    rework_reasons: list[str] = []

    syntax_count = sum(1 for d in defects if d.category == "Syntax")
    critical_security = sum(
        1 for d in defects if d.severity == "Critical" and d.category == "Security"
    )
    critical_total = sum(1 for d in defects if d.severity == "Critical")
    high_count = sum(1 for d in defects if d.severity == "High")
    medium_count = sum(1 for d in defects if d.severity == "Medium")

    missing_reqs = sum(1 for r in requirement_checks if r.status == "Missing")
    partial_reqs = sum(1 for r in requirement_checks if r.status == "Partial")
    total_reqs = len(requirement_checks)

    # 1. Hard REJECT Gates (Only for true blockers)
    if syntax_count > 0:
        reject_reasons.append(f"{syntax_count} syntax error(s) prevent code from running.")
    if critical_security > 0:
        reject_reasons.append(f"{critical_security} critical security vulnerability detected (e.g. SQL injection, secrets, eval).")
    if total_reqs > 0 and missing_reqs >= max(1, total_reqs // 2 + 1):
        reject_reasons.append(f"Majority of required features ({missing_reqs}/{total_reqs}) are completely missing.")
    if score < 40:
        reject_reasons.append(f"Overall quality score ({score}/100) is below the rejection threshold (40).")
    if reject_reasons:
        return "REJECT", reject_reasons

    # 2. REWORK Gates (Code works, but has bugs or unhandled edge cases)
    if critical_total > 0:
        rework_reasons.append(f"{critical_total} critical defect(s) must be resolved.")
    if missing_reqs > 0:
        rework_reasons.append(f"{missing_reqs} requirement(s) are missing.")
    if high_count > 0:
        rework_reasons.append(f"{high_count} high-severity edge case(s) need attention.")
    if medium_count > 0:
        rework_reasons.append(f"{medium_count} code quality/logic issue(s) detected.")
    if partial_reqs > 0:
        rework_reasons.append(f"{partial_reqs} requirement(s) are only partially satisfied.")
    if score < 85:
        rework_reasons.append(f"Quality score ({score}/100) requires fixes before merging (target: 85+).")

    if rework_reasons:
        return "REWORK", rework_reasons

    return "ACCEPT", [
        f"All quality gates passed with score {score}/100 and no blocking defects."
    ]


def _build_default_summary(
    verdict: VerdictType,
    score: int,
    defects: list[DefectItem],
    requirement_checks: list[RequirementCheck],
) -> str:
    met_count = sum(1 for r in requirement_checks if r.status == "Met")
    total_reqs = len(requirement_checks)
    return (
        f"Verdict: {verdict} (Score: {score}/100). "
        f"Found {len(defects)} defect(s); "
        f"{met_count}/{total_reqs} requirement(s) fully met."
    )


def format_pr_comment(result: ReviewResult) -> str:
    badge = VERDICT_BADGES[result.verdict]
    lines: list[str] = [
        f"## CodeGate AI Review — {badge} ({result.score}/100)",
        "",
        f"**Summary:** {result.summary}",
        "",
        "### Decision Gate Reasons",
    ]
    for reason in result.decision_reasons:
        lines.append(f"- {reason}")

    if result.requirement_checks:
        lines.extend(
            [
                "",
                "### Requirement Checklist",
                "| Status | Requirement | Notes |",
                "| :--- | :--- | :--- |",
            ]
        )
        status_icon = {"Met": "✅ Met", "Partial": "⚠️ Partial", "Missing": "❌ Missing"}
        for req in result.requirement_checks:
            req_clean = req.requirement_text.replace("|", "\\|")
            exp_clean = req.explanation.replace("|", "\\|")
            lines.append(f"| {status_icon[req.status]} | {req_clean} | {exp_clean} |")

    if result.defects:
        lines.extend(
            [
                "",
                "### Defects Found",
                "| Severity | Category | Line | Issue | Suggested Fix |",
                "| :--- | :--- | :---: | :--- | :--- |",
            ]
        )
        for d in result.defects:
            line_str = f"L{d.line_number}" if d.line_number else "—"
            desc_clean = d.description.replace("|", "\\|")
            fix_clean = d.suggested_fix.replace("|", "\\|")
            lines.append(
                f"| **{d.severity}** | {d.category} | {line_str} | {desc_clean} | {fix_clean} |"
            )
    else:
        lines.extend(["", "### Defects Found", "No defects detected. Clean code!"])

    lines.extend(
        [
            "",
            f"_Generated by CodeGate AI • Layer 1 AST Scanner + Layer 2 ({result.provider_used})_",
        ]
    )
    return "\n".join(lines)


def evaluate_review(
    static_defects: list[DefectItem],
    llm_output: LLMReviewOutput,
) -> ReviewResult:
    merged_defects = _merge_and_sort_defects(static_defects, llm_output.defects)
    req_checks = llm_output.requirement_checks

    score = _calculate_score(merged_defects, req_checks)
    verdict, reasons = _decide_verdict(score, merged_defects, req_checks)

    summary = llm_output.summary.strip() or _build_default_summary(
        verdict, score, merged_defects, req_checks
    )

    result = ReviewResult(
        verdict=verdict,
        score=score,
        summary=summary,
        requirement_checks=req_checks,
        defects=merged_defects,
        decision_reasons=reasons,
        provider_used=llm_output.provider_used,
    )
    result.pr_comment = format_pr_comment(result)
    return result


def run_full_review(
    requirements_text: str,
    code: str,
    *,
    force_offline: bool = False,
) -> ReviewResult:
    static_defects = analyze_code(code)
    llm_output = run_llm_review(
        requirements_text=requirements_text,
        code=code,
        static_defects=static_defects,
        force_offline=force_offline,
    )
    return evaluate_review(static_defects, llm_output)