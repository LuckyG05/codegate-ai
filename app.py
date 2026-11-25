"""CodeGate AI — Streamlit Web UI (Review Workspace, Audit History & Analytics, Rules)."""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
import streamlit as st

from core.database import ReviewDatabase
from core.decision_engine import (
    REQUIREMENT_PENALTIES,
    SEVERITY_PENALTIES,
    run_full_review,
)
from core.sample_cases import SAMPLE_CASES, get_sample_case_by_id
from core.schemas import ReviewResult

load_dotenv()

st.set_page_config(
    page_title="CodeGate AI — Code Review & Decision Engine",
    page_icon="🛡️",
    layout="wide",
)

VERDICT_STYLES: dict[str, tuple[str, str]] = {
    "ACCEPT": ("🟢 ACCEPT", "success"),
    "REWORK": ("🟠 REWORK", "warning"),
    "REJECT": ("🔴 REJECT", "error"),
}

SEVERITY_ICONS: dict[str, str] = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
}

REQ_STATUS_ICONS: dict[str, str] = {
    "Met": "✅ Met",
    "Partial": "⚠️ Partial",
    "Missing": "❌ Missing",
}


@st.cache_resource
def get_db() -> ReviewDatabase:
    return ReviewDatabase()


def _init_session_state() -> None:
    defaults: dict[str, Any] = {
        "review_title": "",
        "requirements_input": "",
        "code_input": "",
        "selected_sample_id": SAMPLE_CASES[0].case_id,
        "last_result": None,
        "last_review_id": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _load_selected_sample() -> None:
    case = get_sample_case_by_id(st.session_state["selected_sample_id"])
    if case is not None:
        st.session_state["review_title"] = case.title
        st.session_state["requirements_input"] = case.requirements_text
        st.session_state["code_input"] = case.code
        st.session_state["last_result"] = None
        st.session_state["last_review_id"] = None


def _clear_workspace() -> None:
    st.session_state["review_title"] = ""
    st.session_state["requirements_input"] = ""
    st.session_state["code_input"] = ""
    st.session_state["last_result"] = None
    st.session_state["last_review_id"] = None


def _is_key_configured(env_var: str) -> bool:
    val = os.getenv(env_var, "").strip()
    return bool(val) and not val.startswith("your_")


def _render_defect_card(defect: dict[str, Any]) -> None:
    icon = SEVERITY_ICONS.get(defect["severity"], "⚪")
    line_label = f"Line {defect['line_number']}" if defect.get("line_number") else "General"
    source_label = "Layer 1 (AST)" if defect.get("source") == "static" else "Layer 2 (AI)"

    with st.container(border=True):
        st.markdown(
            f"**{icon} {defect['severity']}** · `{defect['category']}` · "
            f"`{line_label}` · _{source_label}_"
        )
        st.write(defect["description"])
        st.caption(f"Suggested fix: {defect['suggested_fix']}")


def _render_review_result(result: ReviewResult, review_id: int | None) -> None:
    badge, box_type = VERDICT_STYLES[result.verdict]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Verdict", badge)
    c2.metric("Quality Score", f"{result.score} / 100")
    c3.metric("Defects Found", len(result.defects))
    c4.metric("Layer 2 Engine", result.provider_used)

    banner = getattr(st, box_type)
    reasons_md = "\n".join(f"- {r}" for r in result.decision_reasons)
    saved_note = f" (Saved to Audit Log as Review #{review_id})" if review_id else ""
    banner(f"**Summary{saved_note}:** {result.summary}\n\n**Decision Gates:**\n{reasons_md}")

    col_left, col_right = st.columns(2, gap="large")

    with col_left:
        st.subheader("Requirement Checklist")
        if result.requirement_checks:
            for req in result.requirement_checks:
                with st.container(border=True):
                    st.markdown(
                        f"**{REQ_STATUS_ICONS[req.status]}** — {req.requirement_text}"
                    )
                    st.caption(req.explanation)
        else:
            st.info("No individual requirements were supplied for this review.")

    with col_right:
        st.subheader(f"Defects ({len(result.defects)})")
        if result.defects:
            for defect in result.defects:
                _render_defect_card(defect.model_dump())
        else:
            st.success("Zero defects found across both analysis layers.")

    st.subheader("Copyable GitHub PR Review Comment")
    st.code(result.pr_comment, language="markdown")


def _render_sidebar() -> bool:
    st.sidebar.title("🛡️ CodeGate AI")
    st.sidebar.caption("Two-Layer Code Review & Deterministic Decision Engine")

    st.sidebar.subheader("Demo Cases")
    case_map = {c.case_id: f"{c.title} [{c.expected_verdict}]" for c in SAMPLE_CASES}
    st.sidebar.selectbox(
        "Choose a sample scenario",
        options=list(case_map.keys()),
        format_func=lambda cid: case_map[cid],
        key="selected_sample_id",
    )
    

    selected_case = get_sample_case_by_id(st.session_state["selected_sample_id"])
    if selected_case is not None:
        st.sidebar.caption(selected_case.description)

    b1, b2 = st.sidebar.columns(2)
    b1.button("Load Sample", on_click=_load_selected_sample, use_container_width=True)
    b2.button("Clear", on_click=_clear_workspace, use_container_width=True)

    st.sidebar.divider()
    st.sidebar.subheader("LLM Provider Status")
    groq_ok = _is_key_configured("GROQ_API_KEY")
    st.sidebar.write(f"Groq Cloud API: {'✅ Configured' if groq_ok else '⚪ Not set'}")

    force_offline = st.sidebar.toggle(
        "Offline-Only Mode",
        value=False,
        help="Skip live LLM calls and run Layer 1 AST + offline heuristic checks only.",
    )
    return force_offline


def _render_review_tab(db: ReviewDatabase, force_offline: bool) -> None:
    st.text_input(
        "Review Title",
        key="review_title",
        placeholder="e.g., User Active Orders SQLite Query",
    )

    in_left, in_right = st.columns(2, gap="large")
    with in_left:
        st.text_area(
            "Written Requirements",
            key="requirements_input",
            height=260,
            placeholder=(
                "- Query SQLite for a user's active orders\n"
                "- Filter out negative amounts\n"
                "- Raise ValueError if user_id is empty"
            ),
        )
    with in_right:
        st.text_area(
            "Submitted Python Code",
            key="code_input",
            height=260,
            placeholder="Paste AI-generated Python code here...",
        )

    if st.button("Run Review", type="primary"):
        code = st.session_state["code_input"]
        requirements = st.session_state["requirements_input"]
        title = st.session_state["review_title"] or "Untitled Code Review"

        with st.spinner("Running Layer 1 AST Scanner + Layer 2 Requirement Verifier..."):
            result = run_full_review(
                requirements_text=requirements,
                code=code,
                force_offline=force_offline,
            )
            review_id = db.save_review(
                title=title,
                requirements_text=requirements,
                submitted_code=code,
                result=result,
            )

        st.session_state["last_result"] = result
        st.session_state["last_review_id"] = review_id

    if st.session_state["last_result"] is not None:
        st.divider()
        _render_review_result(
            st.session_state["last_result"], st.session_state["last_review_id"]
        )


def _render_history_tab(db: ReviewDatabase) -> None:
    stats = db.get_analytics()

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Reviews", stats["total_reviews"])
    m2.metric("Average Score", f"{stats['avg_score']} / 100")
    m3.metric("Accepted", f"{stats['verdict_percentages']['ACCEPT']}%")
    m4.metric("Rejected", f"{stats['verdict_percentages']['REJECT']}%")
    m5.metric("Total Defects", stats["total_defects"])

    if stats["total_reviews"] > 0:
        ch1, ch2 = st.columns(2, gap="large")
        with ch1:
            st.subheader("Verdict Breakdown")
            st.bar_chart(stats["verdict_counts"])
        with ch2:
            st.subheader("Most Common Defect Categories")
            if stats["defects_by_category"]:
                st.bar_chart(stats["defects_by_category"])
            else:
                st.info("No defects logged yet.")

    st.divider()
    st.subheader("Saved Audit Log")
    filter_choice = st.selectbox(
        "Filter by Verdict",
        options=["ALL", "ACCEPT", "REWORK", "REJECT"],
    )
    verdict_filter = None if filter_choice == "ALL" else filter_choice
    reviews = db.list_reviews(verdict=verdict_filter)  # type: ignore[arg-type]

    if not reviews:
        st.info("No reviews recorded yet. Run a review in Tab 1 to populate the audit log.")
        return

    for row in reviews:
        badge = VERDICT_STYLES[row["verdict"]][0]
        header = (
            f"#{row['id']} · {badge} · {row['score']}/100 · "
            f"{row['title']} ({row['defect_count']} defect(s)) — {row['created_at']}"
        )
        with st.expander(header):
            full = db.get_review_by_id(row["id"])
            if full is None:
                continue

            st.write(f"**Summary:** {full['summary']}")
            st.caption(f"Layer 2 Engine: {full['provider_used']}")

            c_req, c_code = st.columns(2)
            with c_req:
                st.markdown("**Requirements**")
                st.text(full["requirements_text"] or "None")
            with c_code:
                st.markdown("**Submitted Code**")
                st.code(full["submitted_code"], language="python")

            if full["requirement_checks"]:
                st.markdown("**Requirement Checks**")
                for rc in full["requirement_checks"]:
                    st.write(
                        f"- **{REQ_STATUS_ICONS[rc['status']]}** {rc['requirement_text']} "
                        f"— _{rc['explanation']}_"
                    )

            if full["defects"]:
                st.markdown("**Defects**")
                for defect in full["defects"]:
                    _render_defect_card(defect)

            if full["pr_comment"]:
                st.markdown("**PR Review Comment**")
                st.code(full["pr_comment"], language="markdown")

            if st.button(f"Delete Review #{row['id']}", key=f"del_{row['id']}"):
                db.delete_review(row["id"])
                st.rerun()


def _render_architecture_tab() -> None:
    st.subheader("Two-Layer Review Pipeline")
    st.markdown(
        """
        1. **Layer 1 — Deterministic Static Scanner (`core/static_analyzer.py`)**
           Parses Python code with `ast` and regex before any LLM call to catch syntax errors,
           SQL injection, hardcoded secrets, dangerous `eval()`/`exec()`, shell injection,
           silent `except: pass`, mutable default arguments, and literal division by zero.
        2. **Layer 2 — AI Requirement & Edge-Case Verifier (`core/llm_reviewer.py`)**
           Sends requirements, line-numbered code, and Layer 1 findings to **Groq** (primary)
           with automatic failover to **Google Gemini** and a safe **offline heuristic fallback**.
        3. **Deterministic Decision Engine (`core/decision_engine.py`)**
           Computes a transparent `0–100` score and enforces strict merge gates instead of
           letting an LLM guess the verdict.
        """
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Defect Penalties**")
        st.table(
            [{"Severity": k, "Point Deduction": f"-{v}"} for k, v in SEVERITY_PENALTIES.items()]
        )
    with col2:
        st.markdown("**Requirement Penalties**")
        st.table(
            [
                {"Requirement Status": k, "Point Deduction": f"-{v}"}
                for k, v in REQUIREMENT_PENALTIES.items()
            ]
        )

    st.markdown(
        """
        **Merge Decision Gates**
        - 🔴 **REJECT**: Any syntax error, any `Critical` defect, any `Missing` requirement, or score `< 50`.
        - 🟠 **REWORK**: Any `High` or `Medium` defect, any `Partial` requirement, or score `< 85`.
        - 🟢 **ACCEPT**: Score `>= 85`, all requirements `Met`, and zero blocking defects.
        """
    )


def main() -> None:
    _init_session_state()
    db = get_db()
    force_offline = _render_sidebar()

    st.title("CodeGate AI — Code Review & Decision Engine")
    st.caption(
        "Automated pre-merge gatekeeper combining Python AST static analysis, "
        "LLM requirement verification, deterministic scoring, and SQLite audit logging."
    )

    tab1, tab2, tab3 = st.tabs(
        ["Inspect", "Audit Insights", "Architecture"]
    )

    with tab1:
        _render_review_tab(db, force_offline)
    with tab2:
        _render_history_tab(db)
    with tab3:
        _render_architecture_tab()


if __name__ == "__main__":
    main()