"""Automated offline pytest suite for static analysis, decision engine, schemas, and SQLite DB."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from core.database import ReviewDatabase
from core.decision_engine import evaluate_review, run_full_review
from core.llm_reviewer import _parse_llm_json
from core.sample_cases import SAMPLE_CASES, get_sample_case_by_id
from core.schemas import DefectItem, LLMReviewOutput, RequirementCheck
from core.static_analyzer import analyze_code


# ---------------------------------------------------------------------------
# Layer 1: Static Analyzer Tests
# ---------------------------------------------------------------------------


def test_static_empty_code_flagged() -> None:
    defects = analyze_code("   \n\t ")
    assert len(defects) == 1
    assert defects[0].category == "Syntax"
    assert defects[0].severity == "Critical"


def test_static_syntax_error_with_line_number() -> None:
    broken_code = "def greet(name):\n    if name\n        return name\n"
    defects = analyze_code(broken_code)
    assert len(defects) == 1
    assert defects[0].category == "Syntax"
    assert defects[0].severity == "Critical"
    assert defects[0].line_number == 2


def test_static_detects_fstring_sql_injection_inline() -> None:
    code = (
        "def fetch(cursor, uid):\n"
        "    cursor.execute(f'SELECT * FROM orders WHERE user_id = {uid}')\n"
    )
    defects = analyze_code(code)
    assert any(
        d.category == "Security"
        and d.severity == "Critical"
        and "sql injection" in d.description.lower()
        and d.line_number == 2
        for d in defects
    )


def test_static_detects_tainted_variable_sql_injection() -> None:
    code = (
        "def fetch(cursor, uid):\n"
        "    sql = 'SELECT * FROM orders WHERE user_id = ' + uid\n"
        "    cursor.execute(sql)\n"
    )
    defects = analyze_code(code)
    assert any(
        d.category == "Security"
        and d.severity == "Critical"
        and "sql injection" in d.description.lower()
        and d.line_number == 3
        for d in defects
    )


def test_static_allows_parameterized_sql_query() -> None:
    code = (
        "def fetch(cursor, uid):\n"
        "    cursor.execute('SELECT * FROM orders WHERE user_id = ?', (uid,))\n"
        "    return cursor.fetchall()\n"
    )
    defects = analyze_code(code)
    assert defects == []


def test_static_detects_hardcoded_api_key_and_password() -> None:
    code = (
        'API_KEY = "gsk_supersecretkey123456"\n'
        'db_password = "MyProdPassword!99"\n'
    )
    defects = analyze_code(code)
    security_defects = [d for d in defects if d.category == "Security"]
    assert len(security_defects) == 2
    assert all(d.severity == "Critical" for d in security_defects)


def test_static_ignores_placeholder_secret_values() -> None:
    code = (
        'API_KEY = "your_api_key_here"\n'
        'SECRET_TOKEN = ""\n'
    )
    defects = analyze_code(code)
    assert defects == []


def test_static_detects_eval_and_exec() -> None:
    code = (
        "def run_expr(expr):\n"
        "    exec('x = 1')\n"
        "    return eval(expr)\n"
    )
    defects = analyze_code(code)
    critical_sec = [
        d for d in defects if d.category == "Security" and d.severity == "Critical"
    ]
    assert len(critical_sec) == 2


def test_static_detects_bare_except_pass_and_typed_except_pass() -> None:
    code = (
        "def a():\n"
        "    try:\n"
        "        return 1 / 0\n"
        "    except:\n"
        "        pass\n\n"
        "def b():\n"
        "    try:\n"
        "        return int('x')\n"
        "    except ValueError:\n"
        "        pass\n"
    )
    defects = analyze_code(code)
    assert any(d.severity == "High" and "except: pass" in d.description for d in defects)
    assert any(
        d.severity == "Medium" and "silently swallows" in d.description for d in defects
    )


def test_static_detects_mutable_default_argument() -> None:
    code = (
        "def add_item(item, items=[]):\n"
        "    items.append(item)\n"
        "    return items\n"
    )
    defects = analyze_code(code)
    assert len(defects) == 1
    assert defects[0].category == "Code Quality"
    assert defects[0].severity == "Medium"
    assert defects[0].line_number == 1


def test_static_detects_literal_division_by_zero() -> None:
    code = "def broken():\n    return 42 / 0\n"
    defects = analyze_code(code)
    assert any(d.category == "Logic" and d.severity == "High" for d in defects)


def test_static_clean_code_returns_zero_defects() -> None:
    code = (
        "def safe_divide(a: float, b: float) -> float:\n"
        "    if b == 0:\n"
        "        raise ValueError('Divider cannot be zero.')\n"
        "    return a / b\n"
    )
    assert analyze_code(code) == []


# ---------------------------------------------------------------------------
# Decision Engine & PR Comment Tests
# ---------------------------------------------------------------------------


def test_decision_accepts_clean_code_with_100_score() -> None:
    llm_out = LLMReviewOutput(
        requirement_checks=[
            RequirementCheck(
                requirement_text="Handle empty user_id",
                status="Met",
                explanation="Raises ValueError on empty user_id.",
            )
        ],
        defects=[],
        summary="Clean implementation.",
        provider_used="offline",
    )
    result = evaluate_review([], llm_out)
    assert result.verdict == "ACCEPT"
    assert result.score == 100
    assert "ACCEPT" in result.pr_comment


def test_decision_rejects_on_critical_security_defect() -> None:
    static = [
        DefectItem(
            category="Security",
            severity="Critical",
            line_number=4,
            description="SQL injection detected.",
            suggested_fix="Use parameterized queries.",
        )
    ]
    llm_out = LLMReviewOutput(
        requirement_checks=[
            RequirementCheck(
                requirement_text="Query active orders",
                status="Met",
                explanation="Query present.",
            )
        ]
    )
    result = evaluate_review(static, llm_out)
    assert result.verdict == "REJECT"
    assert result.score == 75  # 100 - 25 (Critical) = 75


def test_decision_rejects_on_syntax_error() -> None:
    static = [
        DefectItem(
            category="Syntax",
            severity="Critical",
            line_number=1,
            description="Syntax error.",
            suggested_fix="Fix syntax.",
        )
    ]
    result = evaluate_review(static, LLMReviewOutput())
    assert result.verdict == "REJECT"
    assert any("syntax" in r.lower() for r in result.decision_reasons)


def test_decision_rejects_on_missing_requirement() -> None:
    llm_out = LLMReviewOutput(
        requirement_checks=[
            RequirementCheck(
                requirement_text="Raise ValueError on empty input",
                status="Missing",
                explanation="No validation present.",
            )
        ]
    )
    result = evaluate_review([], llm_out)
    assert result.verdict == "REJECT"
    assert result.score == 90  # 100 - 10 (Missing) = 90


def test_decision_rework_on_medium_defect_even_if_score_above_85() -> None:
    static = [
        DefectItem(
            category="Code Quality",
            severity="Medium",
            line_number=1,
            description="Mutable default argument.",
            suggested_fix="Use None as default.",
        )
    ]
    result = evaluate_review(static, LLMReviewOutput())
    assert result.score == 95  # 100 - 5 (Medium) = 95
    assert result.verdict == "REWORK"


def test_decision_rework_on_partial_requirement() -> None:
    llm_out = LLMReviewOutput(
        requirement_checks=[
            RequirementCheck(
                requirement_text="Handle negative values",
                status="Partial",
                explanation="Handles zero but not negative floats.",
            )
        ]
    )
    result = evaluate_review([], llm_out)
    assert result.score == 97  # 100 - 3 (Partial) = 97
    assert result.verdict == "REWORK"


def test_decision_score_clamped_at_zero_and_pr_comment_generated() -> None:
    static = [
        DefectItem(
            category="Security",
            severity="Critical",
            line_number=i,
            description=f"Critical issue {i}",
            suggested_fix="Fix immediately.",
        )
        for i in range(1, 6)
    ]
    result = evaluate_review(static, LLMReviewOutput())
    assert result.score == 0
    assert result.verdict == "REJECT"
    assert "### Defects Found" in result.pr_comment
    assert "Critical issue 1" in result.pr_comment


# ---------------------------------------------------------------------------
# LLM JSON Parsing & Sample Cases End-to-End Tests
# ---------------------------------------------------------------------------


def test_llm_json_parser_handles_fenced_json_and_normalization() -> None:
    raw = """```json
    {
      "summary": "Found an edge-case issue.",
      "requirement_checks": [
        {
          "requirement_text": "Handle empty list",
          "status": "partially met",
          "explanation": "Does not guard len(items) == 0."
        }
      ],
      "defects": [
        {
          "category": "logic",
          "severity": "high",
          "line_number": "10",
          "description": "ZeroDivisionError on empty list.",
          "suggested_fix": "Return 0.0 when list is empty."
        }
      ]
    }
    ```"""
    parsed = _parse_llm_json(raw, provider="groq (test)")
    assert parsed.provider_used == "groq (test)"
    assert parsed.requirement_checks[0].status == "Partial"
    assert parsed.defects[0].category == "Logic"
    assert parsed.defects[0].severity == "High"
    assert parsed.defects[0].line_number == 10
    assert parsed.defects[0].source == "llm"


def test_sample_cases_offline_end_to_end_match_expected_verdicts() -> None:
    assert len(SAMPLE_CASES) == 5
    for case in SAMPLE_CASES:
        result = run_full_review(
            requirements_text=case.requirements_text,
            code=case.code,
            force_offline=True,
        )
        assert result.verdict == case.expected_verdict, (
            f"Sample '{case.case_id}' expected {case.expected_verdict} "
            f"but got {result.verdict} (score={result.score}, reasons={result.decision_reasons})"
        )


def test_sample_case_lookup_by_id() -> None:
    case = get_sample_case_by_id("clean_orders")
    assert case is not None
    assert case.expected_verdict == "ACCEPT"
    assert get_sample_case_by_id("nonexistent_id") is None


# ---------------------------------------------------------------------------
# SQLite Database Layer Tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def temp_db(tmp_path: Path) -> ReviewDatabase:
    return ReviewDatabase(tmp_path / "test_reviews.db")


def test_db_save_and_fetch_review_with_children(temp_db: ReviewDatabase) -> None:
    case = get_sample_case_by_id("sqli_orders")
    assert case is not None
    result = run_full_review(case.requirements_text, case.code, force_offline=True)

    review_id = temp_db.save_review(
        title=case.title,
        requirements_text=case.requirements_text,
        submitted_code=case.code,
        result=result,
    )
    fetched = temp_db.get_review_by_id(review_id)
    assert fetched is not None
    assert fetched["title"] == case.title
    assert fetched["verdict"] == "REJECT"
    assert len(fetched["defects"]) == len(result.defects)
    assert len(fetched["requirement_checks"]) == len(result.requirement_checks)


def test_db_list_reviews_and_filter_by_verdict(temp_db: ReviewDatabase) -> None:
    for case_id in ("sqli_orders", "billing_rework", "clean_orders"):
        case = get_sample_case_by_id(case_id)
        assert case is not None
        res = run_full_review(case.requirements_text, case.code, force_offline=True)
        temp_db.save_review(
            title=case.title,
            requirements_text=case.requirements_text,
            submitted_code=case.code,
            result=res,
        )

    assert len(temp_db.list_reviews()) == 3
    assert len(temp_db.list_reviews(verdict="ACCEPT")) == 1
    assert len(temp_db.list_reviews(verdict="REWORK")) == 1
    assert len(temp_db.list_reviews(verdict="REJECT")) == 1


def test_db_cascade_delete_removes_children(temp_db: ReviewDatabase) -> None:
    case = get_sample_case_by_id("sqli_orders")
    assert case is not None
    result = run_full_review(case.requirements_text, case.code, force_offline=True)
    review_id = temp_db.save_review(
        title=case.title,
        requirements_text=case.requirements_text,
        submitted_code=case.code,
        result=result,
    )

    assert temp_db.delete_review(review_id) is True
    assert temp_db.get_review_by_id(review_id) is None

    conn = sqlite3.connect(temp_db.db_path)
    try:
        defect_count = conn.execute(
            "SELECT COUNT(*) FROM defects WHERE review_id = ?", (review_id,)
        ).fetchone()[0]
        req_count = conn.execute(
            "SELECT COUNT(*) FROM requirement_checks WHERE review_id = ?", (review_id,)
        ).fetchone()[0]
    finally:
        conn.close()

    assert defect_count == 0
    assert req_count == 0


def test_db_enforces_check_constraints_and_foreign_keys(temp_db: ReviewDatabase) -> None:
    conn = sqlite3.connect(temp_db.db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO reviews (title, requirements_text, submitted_code, verdict, score, summary)
                VALUES ('t', 'r', 'c', 'MAYBE', 80, 's')
                """
            )

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO reviews (title, requirements_text, submitted_code, verdict, score, summary)
                VALUES ('t', 'r', 'c', 'ACCEPT', 150, 's')
                """
            )

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO defects (review_id, category, severity, line_number, description, suggested_fix)
                VALUES (9999, 'Security', 'Critical', 1, 'd', 'f')
                """
            )
    finally:
        conn.close()


def test_db_analytics_aggregation(temp_db: ReviewDatabase) -> None:
    for case in SAMPLE_CASES:
        res = run_full_review(case.requirements_text, case.code, force_offline=True)
        temp_db.save_review(
            title=case.title,
            requirements_text=case.requirements_text,
            submitted_code=case.code,
            result=res,
        )

    stats = temp_db.get_analytics()
    assert stats["total_reviews"] == 5
    assert stats["verdict_counts"] == {"ACCEPT": 1, "REWORK": 2, "REJECT": 2}
    assert stats["verdict_percentages"]["REJECT"] == 40.0
    assert stats["total_defects"] > 0
    assert "Security" in stats["defects_by_category"]