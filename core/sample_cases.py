"""Built-in demo scenarios showcasing realistic AI-generated code bugs, edge cases, and clean code."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SampleCase:
    """A pre-loaded code review scenario for quick testing and live demos."""

    case_id: str
    title: str
    expected_verdict: str
    description: str
    requirements_text: str
    code: str


SAMPLE_CASES: list[SampleCase] = [
    SampleCase(
        case_id="cart_rework",
        title="Cart Discount Calculator (Edge-Case Gaps)",
        expected_verdict="REWORK",
        description="Works great for standard carts, but misses boundary checks for negative discounts and negative item prices.",
        requirements_text=(
            "- Calculate total cart price given a list of item prices and a discount percentage.\n"
            "- Round the final total to 2 decimal places.\n"
            "- Reject or clamp negative prices and invalid discount percentages (< 0 or > 100)."
        ),
        code='''def calculate_cart_total(prices: list[float], discount_pct: float = 0.0) -> float:
    """Calculate discounted total for a shopping cart."""
    subtotal = sum(prices)
    discount = subtotal * (discount_pct / 100.0)
    total = subtotal - discount
    return round(total, 2)
''',
    ),
    SampleCase(
        case_id="sqli_orders",
        title="Active Orders Query (SQL Injection & Secret Leak)",
        expected_verdict="REJECT",
        description="AI-generated SQLite query with raw f-string SQL injection, hardcoded API key, and missing validation.",
        requirements_text=(
            "- Query a SQLite database for a user's active orders using a parameterized query.\n"
            "- Filter out orders with negative amounts.\n"
            "- Raise a ValueError if user_id is empty."
        ),
        code='''import sqlite3

DB_API_KEY = "sk-live-9876543210abcdef"


def get_active_orders(conn: sqlite3.Connection, user_id: str) -> list[tuple]:
    cursor = conn.cursor()
    query = f"SELECT id, amount FROM orders WHERE user_id = '{user_id}' AND status = 'active'"
    cursor.execute(query)
    return cursor.fetchall()
''',
    ),
    SampleCase(
        case_id="billing_rework",
        title="Billing Average Calculator (ZeroDivision & Mutable Default)",
        expected_verdict="REWORK",
        description="Works on normal inputs, but crashes on empty lists, uses a mutable default, and swallows exceptions.",
        requirements_text=(
            "- Calculate the discounted average order amount from a list of amounts.\n"
            "- Validate that discount_pct is between 0 and 100.\n"
            "- Handle empty order lists safely without zero division errors."
        ),
        code='''def calculate_average_bill(
    amounts: list[float],
    discount_pct: float = 0.0,
    audit_log: list[str] = [],
) -> float:
    if discount_pct < 0 or discount_pct > 100:
        return 0.0

    total = sum(amounts)
    average = total / len(amounts)
    discounted = average * (1 - discount_pct / 100)

    try:
        audit_log.append(f"Calculated: {discounted:.2f}")
    except Exception:
        pass

    return round(discounted, 2)
''',
    ),
    SampleCase(
        case_id="clean_orders",
        title="Active Orders Service (Clean Implementation)",
        expected_verdict="ACCEPT",
        description="Well-validated, parameterized SQLite query that satisfies every requirement cleanly.",
        requirements_text=(
            "- Query a SQLite database for a user's active orders using parameterized SQL.\n"
            "- Filter out orders with negative amounts (amount >= 0).\n"
            "- Raise a ValueError if user_id is empty or whitespace."
        ),
        code='''import sqlite3


def get_active_orders(conn: sqlite3.Connection, user_id: str) -> list[dict[str, float | int]]:
    """Return active, non-negative orders for a validated user_id."""
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("user_id must be a non-empty string.")

    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, amount
        FROM orders
        WHERE user_id = ? AND status = 'active' AND amount >= 0
        ORDER BY id ASC
        """,
        (user_id.strip(),),
    )
    rows = cursor.fetchall()
    return [{"id": int(row[0]), "amount": float(row[1])} for row in rows]
''',
    ),
    SampleCase(
        case_id="dangerous_eval",
        title="Dynamic Pricing Calculator (Dangerous eval() & Bare Except)",
        expected_verdict="REJECT",
        description="AI shortcut using eval() for arithmetic expressions and bare except: pass error swallowing.",
        requirements_text=(
            "- Safely evaluate basic arithmetic operations (add, sub, mul, div).\n"
            "- Guard against division by zero by raising a ValueError.\n"
            "- Reject unsupported operators without executing arbitrary code."
        ),
        code='''def evaluate_price(a: float, b: float, operator: str) -> float:
    result = 0.0
    try:
        result = eval(f"{a} {operator} {b}")
    except:
        pass
    return result
''',
    ),
]


def get_sample_case_by_id(case_id: str) -> Optional[SampleCase]:
    """Look up a built-in sample case by its identifier."""
    for case in SAMPLE_CASES:
        if case.case_id == case_id:
            return case
    return None