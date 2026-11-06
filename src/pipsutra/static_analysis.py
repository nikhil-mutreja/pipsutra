from __future__ import annotations

import ast
from pathlib import Path
from typing import Literal

from pipsutra.models import StaticFinding

_EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "site-packages",
    "node_modules",
    ".tox",
}


class _RuleVisitor(ast.NodeVisitor):
    source: str
    syntax_error: str | None = None

    def __init__(self, relative_path: str) -> None:
        self.relative_path = relative_path
        self.findings: list[StaticFinding] = []
        self.os_modules: set[str] = set()
        self.os_system_names: set[str] = set()
        self.subprocess_modules: set[str] = set()
        self.subprocess_methods = {
            "Popen",
            "run",
            "call",
            "check_call",
            "check_output",
        }
        self.subprocess_names: set[str] = set()
        self.pickle_modules: set[str] = set()
        self.pickle_loads_names: set[str] = set()

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        title: str,
        severity: Literal["LOW", "MEDIUM", "HIGH"],
        confidence: Literal["LOW", "MEDIUM", "HIGH"],
        message: str,
        recommendation: str,
    ) -> None:
        segment = ast.get_source_segment(self.source, node) or node.__class__.__name__
        line_number = getattr(node, "lineno", 1)  # noqa: B009
        self.findings.append(
            StaticFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                confidence=confidence,
                message=message,
                file=self.relative_path,
                line=line_number,
                evidence=segment[:240],
                recommendation=recommendation,
            )
        )

    def scan(self, source: str) -> list[StaticFinding]:
        self.source = source
        try:
            tree = ast.parse(source, filename=self.relative_path)
        except SyntaxError as exc:
            self.syntax_error = f"SyntaxError at line {exc.lineno or 1}: {exc.msg}"
            return []
        self._collect_import_aliases(tree)
        self.visit(tree)
        return self.findings

    def _collect_import_aliases(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "os":
                        self.os_modules.add(alias.asname or "os")
                    elif alias.name == "subprocess":
                        self.subprocess_modules.add(alias.asname or "subprocess")
                    elif alias.name == "pickle":
                        self.pickle_modules.add(alias.asname or "pickle")
            elif isinstance(node, ast.ImportFrom):
                if node.module == "os":
                    for alias in node.names:
                        if alias.name == "system":
                            self.os_system_names.add(alias.asname or alias.name)
                elif node.module == "subprocess":
                    for alias in node.names:
                        if alias.name in self.subprocess_methods:
                            self.subprocess_names.add(alias.asname or alias.name)
                elif node.module == "pickle":
                    for alias in node.names:
                        if alias.name == "loads":
                            self.pickle_loads_names.add(alias.asname or alias.name)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else ""
        )
        if name in {"eval", "exec"}:
            self._add(
                node,
                "DG-PY-001",
                "Dynamic code execution",
                "HIGH",
                "HIGH",
                f"Use of {name}() executes dynamically supplied code.",
                "Avoid dynamic execution; use a constrained parser "
                "or explicit dispatch.",
            )
        is_os_system = (
            isinstance(func, ast.Attribute)
            and func.attr == "system"
            and isinstance(func.value, ast.Name)
            and func.value.id in self.os_modules
        ) or (isinstance(func, ast.Name) and func.id in self.os_system_names)
        if is_os_system:
            self._add(
                node,
                "DG-PY-002",
                "OS command execution",
                "MEDIUM",
                "MEDIUM",
                "os.system() invokes a command through a shell.",
                "Prefer subprocess.run with an argument list and shell=False.",
            )
        is_subprocess_call = (
            isinstance(func, ast.Attribute)
            and func.attr in self.subprocess_methods
            and isinstance(func.value, ast.Name)
            and func.value.id in self.subprocess_modules
        ) or (isinstance(func, ast.Name) and func.id in self.subprocess_names)
        if is_subprocess_call:
            shell_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if shell_true:
                self._add(
                    node,
                    "DG-PY-003",
                    "Subprocess with shell=True",
                    "HIGH",
                    "HIGH",
                    "A subprocess call enables shell interpretation.",
                    "Pass an argument list and set shell=False; "
                    "validate untrusted input.",
                )
        is_pickle_load = (
            isinstance(func, ast.Attribute)
            and func.attr == "loads"
            and isinstance(func.value, ast.Name)
            and func.value.id in self.pickle_modules
        ) or (isinstance(func, ast.Name) and func.id in self.pickle_loads_names)
        if is_pickle_load:
            self._add(
                node,
                "DG-PY-004",
                "Unsafe pickle deserialization",
                "HIGH",
                "HIGH",
                "pickle.loads() can execute code while deserializing untrusted data.",
                "Never unpickle untrusted data; use a non-executable data format.",
            )
        self.generic_visit(node)


def scan_python_source(
    project_path: str | Path,
) -> tuple[list[StaticFinding], list[str]]:
    root = Path(project_path).expanduser().resolve()
    findings: list[StaticFinding] = []
    warnings: list[str] = []
    files = 0
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if any(part in _EXCLUDED for part in relative.parts):
            continue
        files += 1
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            warnings.append(f"Could not read {relative}: {type(exc).__name__}")
            continue
        visitor = _RuleVisitor(relative.as_posix())
        findings.extend(visitor.scan(source))
        if visitor.syntax_error:
            warnings.append(f"Could not parse {relative}: {visitor.syntax_error}")
    if files == 0:
        warnings.append("No Python source files found for static analysis.")
    return (
        sorted(findings, key=lambda item: (item.file, item.line, item.rule_id)),
        warnings,
    )
