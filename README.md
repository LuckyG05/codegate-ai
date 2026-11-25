# 🛡️ CodeGate AI — Code Review & Decision Engine

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://github.com/LuckyG05/codegate-ai)
![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue?logo=python)
![Tests](https://img.shields.io/badge/Tests-27%20Passed%20(pytest)-success?logo=pytest)
![Engine](https://img.shields.io/badge/Layer%202-Groq%20LPU-orange)
![License](https://img.shields.io/badge/License-MIT-green)

> An automated pre-merge gatekeeper that inspects AI-generated Python code for hidden security flaws, edge-case crashes, and missed requirements before it reaches production.

**GitHub Repository:** [https://github.com/LuckyG05/codegate-ai](https://github.com/LuckyG05/codegate-ai)  
**Live Web App:** *[Open in Streamlit](https://github.com/LuckyG05/codegate-ai)* 

---

## 1. The Problem

Today, developers rely heavily on AI coding assistants (ChatGPT, Claude, Copilot, Cursor) to write code at lightning speed. However, AI-generated code frequently introduces subtle, high-risk issues:
- **Quiet Security Flaws:** SQL queries built with raw f-strings (`f"SELECT * WHERE id = {user_id}"`), hardcoded API keys, or dangerous `eval()` shortcuts.
- **Silent Failures & Bad Practices:** Bare `except: pass` error swallowing that hides crashes, or mutable default arguments (`def fn(x=[])`) that leak memory across requests.
- **Missed Edge Cases:** Code that works for standard inputs but crashes on empty lists (`ZeroDivisionError`), `None` values, or negative numbers.
- **Incomplete Requirements:** Code that looks syntactically plausible but ignores crucial prompt constraints.

Allowing AI-written code to bypass human review directly into production leads to database leaks, production outages, and technical debt.

---

## 2. What I Built (CodeGate AI)

**CodeGate AI** acts like an automated senior software engineer guarding the pull-request boundary. 

Instead of trusting an LLM to blindly guess a verdict, CodeGate AI uses a **Two-Layer Hybrid Architecture** paired with a **deterministic mathematical scoring engine**:

```text
[ Requirements + Submitted Python Code ]
                   │
                   ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Layer 1: Deterministic Static AST Scanner                  │
  │  (Pure Python `ast` + Regex — 100% deterministic, zero AI)  │
  │  • Syntax errors with exact line numbers                    │
  │  • SQL injection (raw string interpolation in cursor.exec)  │
  │  • Hardcoded secrets & API keys                             │
  │  • Dangerous built-ins (`eval()`, `exec()`)                 │
  │  • Silent exception swallowing (`except: pass`)             │
  │  • Mutable default arguments (`def fn(x=[])`)               │
  │  • Literal division by zero (`42 / 0`)                      │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Layer 2: AI Requirement & Logic Verifier                   │
  │  (Groq Cloud LPU — Sub-second semantic verification)        │
  │  • Decomposes prompts into atomic requirement checklists   │
  │  • Evaluates requirement fulfillment: Met | Partial | Miss  │
  │  • Catches runtime edge-case logic bugs (empty inputs, 0)   │
  │  • Safe offline heuristic fallback mode (zero downtime)     │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Deterministic Decision Engine (No AI Guesswork)            │
  │  • Linear penalty math: Score = max(0, 100 - Penalties)     │
  │  • Strict Gate Rules:                                       │
  │    🔴 REJECT : Security vulnerabilities, syntax crashes     │
  │    🟠 REWORK : Functional code with edge cases or smells   │
  │    🟢 ACCEPT : Score ≥ 85, all requirements Met, clean code│
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  SQLite Persistence & GitHub PR Export                      │
  │  • Saves every review, checklist item, and defect card      │
  │  • Formats a ready-to-paste GitHub PR Markdown comment      │
  └─────────────────────────────────────────────────────────────┘
```

---

## 3. Key Features

- **Two-Layer Inspection Pipeline:** Combines the speed and zero-hallucination guarantees of Python Abstract Syntax Trees (`ast`) with the semantic comprehension of Groq LPUs (`openai/gpt-oss-120b` / `qwen/qwen3.8-27b`).
- **Deterministic Quality Scoring (0–100):** Transparent, graded scoring model prevents subjective LLM decisions:
  - **Critical ($-25$):** Security exploits (SQLi, secrets, eval).
  - **High ($-10$):** Runtime edge-case crashes (ZeroDivision, unhandled empty input).
  - **Medium ($-5$):** Code smells (mutable defaults, swallowed exceptions).
  - **Low ($-2$):** Style / unused variables.
- **Clear Decision Gates:**
  - **🟢 ACCEPT (85–100):** Ready to merge.
  - **🟠 REWORK (40–84):** Works on standard inputs; needs fixes for edge cases or code smells.
  - **🔴 REJECT (<40 or Blockers):** Security vulnerabilities, syntax errors, or major requirement gaps.
- **Ready-to-Paste GitHub PR Comment:** Generates clean, professional Markdown reports with severity badges, line numbers, and actionable suggestions.
- **1-Click Interactive Demo Cases:** 5 built-in scenarios (SQL injection, dangerous `eval()`, edge-case gaps, cart calculations, and clean implementations) for instant testing.
- **SQLite Audit History & Analytics:** Tracks review history, acceptance rates, and defect distribution charts directly in SQL with foreign-key cascade constraints.
- **27 Automated Offline Unit Tests:** Comprehensive `pytest` suite testing AST visitors, scoring gates, and database constraints without needing live API calls.

---

## 4. Built-in Demo Scenarios

| Scenario | Code Characteristics | Verdict | Score |
| :--- | :--- | :---: | :---: |
| **Active Orders Query** | Raw f-string SQL injection + hardcoded API key | **🔴 REJECT** | ~10–25 / 100 |
| **Dynamic Pricing Calculator** | Arbitrary execution via `eval()` + bare `except: pass` | **🔴 REJECT** | ~35–45 / 100 |
| **Cart Discount Calculator** | Works for standard carts; misses negative price/discount validation | **🟠 REWORK** | ~75–80 / 100 |
| **Billing Average Calculator** | Crashes on empty lists (`ZeroDivisionError`) + mutable default | **🟠 REWORK** | ~60–65 / 100 |
| **Clean Orders Service** | Parameterized SQL query `?`, validated `user_id`, boundary checks | **🟢 ACCEPT** | **100 / 100** |

---

## 5. Tech Stack

- **Frontend / UI:** [Streamlit](https://streamlit.io/)
- **Core Analysis:** Python 3.11+, `ast` (Abstract Syntax Trees), `re`
- **Data Validation:** [Pydantic v2](https://docs.pydantic.dev/)
- **LLM Engine:** [Groq Cloud API](https://groq.com/) (LPU inference via `openai/gpt-oss-120b`, `qwen/qwen3.8-27b`)
- **Database:** SQLite 3 (Foreign Keys enabled, `ON DELETE CASCADE`)
- **Testing:** [pytest](https://docs.pytest.org/) (27 unit tests)

---

## 6. Local Setup & Installation

### Prerequisites
- Python 3.11 or higher
- Git

### 1. Clone the repository
```bash
git clone https://github.com/LuckyG05/codegate-ai.git
cd codegate-ai
```

### 2. Create a virtual environment & install dependencies
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy the `.env.example` file to `.env`:
```bash
copy .env.example .env    # Windows
cp .env.example .env      # macOS/Linux
```
Add your free [Groq API Key](https://console.groq.com/keys) inside `.env`:
```env
GROQ_API_KEY=gsk_your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
```
*(Note: CodeGate AI also includes an offline heuristic scanner, so it works even without an API key!)*

### 4. Run Automated Tests
Verify all 27 unit tests pass:
```bash
pytest
```

### 5. Launch the Streamlit App
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 7. Project Structure

```text
codegate-ai/
├── core/
│   ├── __init__.py
│   ├── schemas.py           # Strict Pydantic models (Defects, Checks, ReviewResult)
│   ├── static_analyzer.py   # Layer 1: AST visitor & deterministic security scanner
│   ├── llm_reviewer.py      # Layer 2: Groq LPU requirement verifier + offline fallback
│   ├── decision_engine.py   # Mathematical scoring & ACCEPT / REWORK / REJECT gates
│   ├── sample_cases.py      # 5 built-in 1-click test scenarios
│   └── database.py          # Normalized 3-table SQLite audit log & analytics
├── tests/
│   └── test_reviewer.py     # 27 automated offline pytest unit tests
├── app.py                   # Streamlit 3-tab Web Application
├── .env.example             # Environment variable template
├── .gitignore               # Ignores .env, *.db, and __pycache__
├── pytest.ini               # Pytest configuration
├── requirements.txt         # Project dependencies
└── README.md                # Project documentation
```

---

## 8. License

Distributed under the MIT License. See `LICENSE` for more information.

---

### Author
Developed by **[LuckyG05](https://github.com/LuckyG05)** — feel free to connect or open an issue!
