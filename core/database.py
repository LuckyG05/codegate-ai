"""Normalized 3-table SQLite storage and analytics layer for review audit history."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Optional

from core.schemas import ReviewResult, VerdictType

DEFAULT_DB_PATH = Path("reviews.db")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    requirements_text TEXT NOT NULL,
    submitted_code TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('ACCEPT', 'REWORK', 'REJECT')),
    score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    summary TEXT NOT NULL,
    pr_comment TEXT NOT NULL DEFAULT '',
    provider_used TEXT NOT NULL DEFAULT 'offline',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS requirement_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id INTEGER NOT NULL,
    requirement_text TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Met', 'Partial', 'Missing')),
    explanation TEXT NOT NULL,
    FOREIGN KEY (review_id) REFERENCES reviews(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS defects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id INTEGER NOT NULL,
    category TEXT NOT NULL CHECK (
        category IN ('Security', 'Logic', 'Requirement', 'Code Quality', 'Syntax')
    ),
    severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    line_number INTEGER CHECK (line_number IS NULL OR line_number >= 1),
    description TEXT NOT NULL,
    suggested_fix TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'static' CHECK (source IN ('static', 'llm')),
    FOREIGN KEY (review_id) REFERENCES reviews(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_req_checks_review_id ON requirement_checks(review_id);
CREATE INDEX IF NOT EXISTS idx_defects_review_id ON defects(review_id);
"""


class ReviewDatabase:
    """SQLite persistence layer with foreign-key enforcement and SQL analytics."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create normalized tables and indexes if they do not exist."""
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def save_review(
        self,
        *,
        title: str,
        requirements_text: str,
        submitted_code: str,
        result: ReviewResult,
    ) -> int:
        """Persist a ReviewResult and its child checks/defects in a single transaction."""
        clean_title = title.strip() or "Untitled Code Review"
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO reviews (
                    title, requirements_text, submitted_code,
                    verdict, score, summary, pr_comment, provider_used
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    clean_title,
                    requirements_text,
                    submitted_code,
                    result.verdict,
                    result.score,
                    result.summary,
                    result.pr_comment,
                    result.provider_used,
                ),
            )
            review_id = int(cursor.lastrowid)

            if result.requirement_checks:
                conn.executemany(
                    """
                    INSERT INTO requirement_checks (
                        review_id, requirement_text, status, explanation
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (review_id, r.requirement_text, r.status, r.explanation)
                        for r in result.requirement_checks
                    ],
                )

            if result.defects:
                conn.executemany(
                    """
                    INSERT INTO defects (
                        review_id, category, severity, line_number,
                        description, suggested_fix, source
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            review_id,
                            d.category,
                            d.severity,
                            d.line_number,
                            d.description,
                            d.suggested_fix,
                            d.source,
                        )
                        for d in result.defects
                    ],
                )

        return review_id

    def get_review_by_id(self, review_id: int) -> Optional[dict[str, Any]]:
        """Fetch a single review along with its requirement checks and defects."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM reviews WHERE id = ?", (review_id,)
            ).fetchone()
            if row is None:
                return None

            req_rows = conn.execute(
                """
                SELECT id, requirement_text, status, explanation
                FROM requirement_checks
                WHERE review_id = ?
                ORDER BY id ASC
                """,
                (review_id,),
            ).fetchall()

            defect_rows = conn.execute(
                """
                SELECT id, category, severity, line_number, description, suggested_fix, source
                FROM defects
                WHERE review_id = ?
                ORDER BY id ASC
                """,
                (review_id,),
            ).fetchall()

        review = dict(row)
        review["requirement_checks"] = [dict(r) for r in req_rows]
        review["defects"] = [dict(d) for d in defect_rows]
        return review

    def list_reviews(
        self,
        *,
        verdict: Optional[VerdictType] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List stored reviews (newest first) with aggregated defect/requirement counts."""
        base_query = """
            SELECT
                r.id,
                r.title,
                r.verdict,
                r.score,
                r.summary,
                r.provider_used,
                r.created_at,
                (SELECT COUNT(*) FROM defects d WHERE d.review_id = r.id) AS defect_count,
                (SELECT COUNT(*) FROM requirement_checks rc WHERE rc.review_id = r.id) AS req_count
            FROM reviews r
        """
        params: list[Any] = []
        if verdict is not None:
            base_query += " WHERE r.verdict = ?"
            params.append(verdict)

        base_query += " ORDER BY r.id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(base_query, tuple(params)).fetchall()

        return [dict(row) for row in rows]

    def delete_review(self, review_id: int) -> bool:
        """Delete a review; child requirement_checks and defects cascade automatically."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
            return cursor.rowcount > 0

    def get_analytics(self) -> dict[str, Any]:
        """Compute aggregate review and defect metrics directly in SQL."""
        with self._connect() as conn:
            totals = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_reviews,
                    COALESCE(ROUND(AVG(score), 1), 0.0) AS avg_score
                FROM reviews
                """
            ).fetchone()

            verdict_rows = conn.execute(
                "SELECT verdict, COUNT(*) AS cnt FROM reviews GROUP BY verdict"
            ).fetchall()

            cat_rows = conn.execute(
                """
                SELECT category, COUNT(*) AS cnt
                FROM defects
                GROUP BY category
                ORDER BY cnt DESC, category ASC
                """
            ).fetchall()

            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM defects
                GROUP BY severity
                ORDER BY cnt DESC, severity ASC
                """
            ).fetchall()

            total_defects = conn.execute("SELECT COUNT(*) AS cnt FROM defects").fetchone()["cnt"]

        total_reviews = int(totals["total_reviews"])
        verdict_counts: dict[str, int] = {"ACCEPT": 0, "REWORK": 0, "REJECT": 0}
        for row in verdict_rows:
            verdict_counts[row["verdict"]] = int(row["cnt"])

        verdict_percentages = {
            k: round((v / total_reviews) * 100, 1) if total_reviews > 0 else 0.0
            for k, v in verdict_counts.items()
        }

        return {
            "total_reviews": total_reviews,
            "avg_score": float(totals["avg_score"]),
            "verdict_counts": verdict_counts,
            "verdict_percentages": verdict_percentages,
            "total_defects": int(total_defects),
            "defects_by_category": {row["category"]: int(row["cnt"]) for row in cat_rows},
            "defects_by_severity": {row["severity"]: int(row["cnt"]) for row in sev_rows},
        }