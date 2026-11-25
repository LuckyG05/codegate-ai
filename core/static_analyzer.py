"""Layer 1: Pure-Python deterministic AST and regex static code analyzer."""

from __future__ import annotations

import ast
import re
from typing import Optional

from core.schemas import DefectItem

SQL_KEYWORD_RE = re.compile(
    r"\b(SELECT\b.+\bFROM|INSERT\s+INTO|UPDATE\b.+\bSET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)\b",
    re.IGNORECASE | re.DOTALL,
)

SECRET_VAR_RE = re.compile(
    r"(api[_-]?key|secret|password|passwd|pwd|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)

SECRET_VALUE_PREFIX_RE = re.compile(
    r"^(sk-[A-Za-z0-9_-]{8,}|gsk_[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{10,}|ghp_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{12,})$"
)

PLACEHOLDER_VALUES = {
    "",
    "none",
    "null",
    "changeme",
    "replace_me",
    "placeholder",
    "example",
    "your_api_key_here",
    "your_secret_here",
}

SQL_EXEC_METHODS = {"execute", "executemany", "executescript"}
DANGEROUS_BUILTINS = {"eval", "exec", "__import__"}

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _extract_string_fragments(node: ast.AST) -> str:
    """Recursively collect constant string fragments from an expression."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            for part in node.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _extract_string_fragments(node.left) + _extract_string_fragments(node.right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return _extract_string_fragments(node.func.value)
    return ""


def _is_dynamic_string_expr(node: ast.AST) -> bool:
    """Return True if the AST node builds a string dynamically at runtime."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left_is_const = isinstance(node.left, ast.Constant)
        right_is_const = isinstance(node.right, ast.Constant)
        return not (left_is_const and right_is_const)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def _is_dynamic_sql(node: ast.AST) -> bool:
    """Return True if node dynamically interpolates values into a SQL query."""
    if not _is_dynamic_string_expr(node):
        return False
    fragments = _extract_string_fragments(node)
    return bool(SQL_KEYWORD_RE.search(fragments))


def _is_placeholder_secret(value: str) -> bool:
    """Ignore empty or obvious template placeholder values."""
    cleaned = value.strip().lower()
    if cleaned in PLACEHOLDER_VALUES:
        return True
    if cleaned.startswith("your_") or (cleaned.startswith("<") and cleaned.endswith(">")):
        return True
    return False


def _is_pass_only_body(body: list[ast.stmt]) -> bool:
    """Return True if a block only contains pass or ellipsis statements."""
    if not body:
        return True
    for stmt in body:
        if isinstance(stmt, ast.Pass):
            continue
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is Ellipsis
        ):
            continue
        return False
    return True


def _get_target_name(target: ast.AST) -> Optional[str]:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


class _StaticCodeVisitor(ast.NodeVisitor):
    """AST visitor collecting deterministic security and quality defects."""

    def __init__(self) -> None:
        self.defects: list[DefectItem] = []
        self._dynamic_sql_vars: set[str] = set()
        self._reported_secret_lines: set[int] = set()

    def _add_defect(
        self,
        *,
        category: str,
        severity: str,
        line_number: Optional[int],
        description: str,
        suggested_fix: str,
    ) -> None:
        self.defects.append(
            DefectItem(
                category=category,  # type: ignore[arg-type]
                severity=severity,  # type: ignore[arg-type]
                line_number=line_number,
                description=description,
                suggested_fix=suggested_fix,
                source="static",
            )
        )

    def _check_secret_assignment(
        self, target_name: Optional[str], value: Optional[ast.AST], lineno: int
    ) -> None:
        if value is None or lineno in self._reported_secret_lines:
            return
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            return

        secret_val = value.value.strip()
        if _is_placeholder_secret(secret_val):
            return

        name_matches = bool(target_name and SECRET_VAR_RE.search(target_name))
        prefix_matches = bool(SECRET_VALUE_PREFIX_RE.match(secret_val))

        if name_matches or prefix_matches:
            self._reported_secret_lines.add(lineno)
            label = f"'{target_name}'" if target_name else "string literal"
            self._add_defect(
                category="Security",
                severity="Critical",
                line_number=lineno,
                description=f"Hardcoded secret or credential detected in {label}.",
                suggested_fix=(
                    "Load secrets from environment variables (e.g., os.getenv(...)) "
                    "instead of hardcoding them in source code."
                ),
            )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = _get_target_name(target)
            if name and _is_dynamic_sql(node.value):
                self._dynamic_sql_vars.add(name)
            self._check_secret_assignment(name, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        name = _get_target_name(node.target)
        if name and node.value and _is_dynamic_sql(node.value):
            self._dynamic_sql_vars.add(name)
        self._check_secret_assignment(name, node.value, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # 1. Dangerous built-ins: eval(), exec(), __import__()
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_BUILTINS:
            self._add_defect(
                category="Security",
                severity="Critical",
                line_number=node.lineno,
                description=f"Dangerous built-in '{node.func.id}()' enables arbitrary code execution.",
                suggested_fix=(
                    f"Remove '{node.func.id}()' and use safe alternatives "
                    "(such as ast.literal_eval or explicit dispatch tables)."
                ),
            )

        # 2. SQL Injection via cursor.execute(...) / executemany(...) / executescript(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr in SQL_EXEC_METHODS:
            if node.args:
                query_arg = node.args[0]
                is_tainted_var = (
                    isinstance(query_arg, ast.Name)
                    and query_arg.id in self._dynamic_sql_vars
                )
                if _is_dynamic_sql(query_arg) or is_tainted_var:
                    self._add_defect(
                        category="Security",
                        severity="Critical",
                        line_number=node.lineno,
                        description=(
                            f"Potential SQL injection in '{node.func.attr}()': "
                            "SQL query is built with string interpolation/concatenation."
                        ),
                        suggested_fix=(
                            "Use parameterized queries with placeholders "
                            '(e.g., cursor.execute("SELECT ... WHERE user_id = ?", (user_id,))).'
                        ),
                    )

        # 3. Shell command injection: os.system(...) or subprocess.*(..., shell=True)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "system"
        ):
            self._add_defect(
                category="Security",
                severity="High",
                line_number=node.lineno,
                description="Use of 'os.system()' risks shell command injection.",
                suggested_fix="Use 'subprocess.run([...], shell=False, check=True)' with a list of arguments.",
            )

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ):
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self._add_defect(
                        category="Security",
                        severity="High",
                        line_number=node.lineno,
                        description=(
                            f"'subprocess.{node.func.attr}(..., shell=True)' "
                            "exposes the code to shell injection."
                        ),
                        suggested_fix="Pass arguments as a list and set shell=False.",
                    )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        is_bare = node.type is None
        swallows_silently = _is_pass_only_body(node.body)

        if is_bare and swallows_silently:
            self._add_defect(
                category="Code Quality",
                severity="High",
                line_number=node.lineno,
                description="Bare 'except: pass' silently swallows all errors, including KeyboardInterrupt.",
                suggested_fix="Catch a specific exception type and log, handle, or re-raise it.",
            )
        elif swallows_silently:
            self._add_defect(
                category="Code Quality",
                severity="Medium",
                line_number=node.lineno,
                description="Exception handler silently swallows errors with 'pass'.",
                suggested_fix="Log the exception, return a clear error state, or re-raise it.",
            )
        elif is_bare:
            self._add_defect(
                category="Code Quality",
                severity="Medium",
                line_number=node.lineno,
                description="Bare 'except:' catches system-exiting exceptions like KeyboardInterrupt.",
                suggested_fix="Replace bare 'except:' with a specific exception type (e.g., ValueError).",
            )

        self.generic_visit(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # 1. Mutable default arguments
        all_defaults = list(node.args.defaults) + [
            d for d in node.args.kw_defaults if d is not None
        ]
        for default in all_defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._add_defect(
                    category="Code Quality",
                    severity="Medium",
                    line_number=node.lineno,
                    description=(
                        f"Function '{node.name}' uses a mutable default argument "
                        f"({type(default).__name__.lower()}), which is shared across calls."
                    ),
                    suggested_fix=(
                        "Use None as the default value and initialize a fresh "
                        "list/dict/set inside the function body."
                    ),
                )
                break

        # 2. Empty placeholder function body (ignoring optional docstring)
        effective_body = node.body
        if (
            effective_body
            and isinstance(effective_body[0], ast.Expr)
            and isinstance(effective_body[0].value, ast.Constant)
            and isinstance(effective_body[0].value.value, str)
        ):
            effective_body = effective_body[1:]

        if _is_pass_only_body(effective_body):
            self._add_defect(
                category="Code Quality",
                severity="Medium",
                line_number=node.lineno,
                description=f"Function '{node.name}' has an empty placeholder body.",
                suggested_fix="Implement the required logic or remove the unused stub function.",
            )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if (
            isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod))
            and isinstance(node.right, ast.Constant)
            and isinstance(node.right.value, (int, float))
            and not isinstance(node.right.value, bool)
            and node.right.value == 0
        ):
            self._add_defect(
                category="Logic",
                severity="High",
                line_number=node.lineno,
                description="Literal division or modulo by zero will always raise ZeroDivisionError.",
                suggested_fix="Guard against zero denominators or fix the constant divisor.",
            )
        self.generic_visit(node)


def analyze_code(code: str) -> list[DefectItem]:
    """Run deterministic AST and regex checks on submitted Python code."""
    if not code or not code.strip():
        return [
            DefectItem(
                category="Syntax",
                severity="Critical",
                line_number=1,
                description="No Python code was provided for review.",
                suggested_fix="Paste valid Python code before running the review.",
                source="static",
            )
        ]

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return [
            DefectItem(
                category="Syntax",
                severity="Critical",
                line_number=exc.lineno or 1,
                description=f"Python syntax error: {exc.msg}.",
                suggested_fix="Fix the syntax error so the code can be parsed and executed.",
                source="static",
            )
        ]

    visitor = _StaticCodeVisitor()
    visitor.visit(tree)

    # Sort deterministically by severity then line number
    visitor.defects.sort(
        key=lambda d: (SEVERITY_RANK.get(d.severity, 99), d.line_number or 0, d.description)
    )
    return visitor.defects