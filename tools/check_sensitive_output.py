#!/usr/bin/env python3
"""Guard against accidental credential output in CLI and audit paths."""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET_FILES = [
    REPO_ROOT / "src/secure_string_cipher/cli.py",
    REPO_ROOT / "src/secure_string_cipher/cli_args.py",
    REPO_ROOT / "src/secure_string_cipher/audit_log.py",
]

SINK_FUNCTION_NAMES = {
    "print",
    "_print_error",
    "_print_warning",
    "_print_info",
    "_exit_error",
    "_audit_encryption",
    "_audit_vault",
    "audit_event",
    "audit_auth_failure",
    "audit_rate_limit",
}
SINK_METHOD_NAMES = {
    "write",
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    "exception",
    "log",
    "log_encryption",
    "log_vault_operation",
    "log_auth_failure",
    "log_rate_limit",
}
SENSITIVE_EXACT_NAMES = {
    "pw",
    "confirm_pw",
    "master",
    "master_pw",
    "password",
    "password2",
    "passphrase",
    "secret",
    "token",
    "credential",
    "credentials",
}
SENSITIVE_SUFFIXES = (
    "_pw",
    "_password",
    "_passphrase",
    "_secret",
    "_token",
    "_credential",
    "_credentials",
    "_key",
)
SANITIZER_FUNCTION_NAMES = {
    "_key_file_error_message",
}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    message: str

    def render(self) -> str:
        rel_path = self.path.relative_to(REPO_ROOT)
        return f"{rel_path}:{self.line}: {self.message}"


class SensitiveExpressionVisitor(ast.NodeVisitor):
    """Detect sensitive names and raw exception references inside an expression."""

    def __init__(self, exception_names: set[str]) -> None:
        self.exception_names = exception_names
        self.sensitive_names: set[str] = set()
        self.exception_refs: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        name = node.id
        if is_sensitive_name(name):
            self.sensitive_names.add(name)
        if name in self.exception_names:
            self.exception_refs.add(name)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in SANITIZER_FUNCTION_NAMES:
            return
        self.generic_visit(node)


class SensitiveOutputVisitor(ast.NodeVisitor):
    """Scan a module for sensitive values flowing into output/log sinks."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.exception_stack: list[set[str]] = []
        self.findings: list[Finding] = []

    @property
    def exception_names(self) -> set[str]:
        names: set[str] = set()
        for frame in self.exception_stack:
            names.update(frame)
        return names

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        frame = {node.name} if node.name else set()
        self.exception_stack.append(frame)
        self.generic_visit(node)
        self.exception_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        sink_name = call_sink_name(node.func)
        if sink_name is not None:
            for expr in [*node.args, *(kw.value for kw in node.keywords)]:
                self._check_sink_argument(node, expr)

        self.generic_visit(node)

    def _check_sink_argument(self, call_node: ast.Call, expr: ast.expr) -> None:
        visitor = SensitiveExpressionVisitor(self.exception_names)
        visitor.visit(expr)

        if visitor.sensitive_names:
            names = ", ".join(sorted(visitor.sensitive_names))
            self.findings.append(
                Finding(
                    self.path,
                    call_node.lineno,
                    f"sensitive value sent to output/log sink: {names}",
                )
            )

        if visitor.exception_refs:
            names = ", ".join(sorted(visitor.exception_refs))
            self.findings.append(
                Finding(
                    self.path,
                    call_node.lineno,
                    f"raw exception detail sent to output/log sink: {names}",
                )
            )


def is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in SENSITIVE_EXACT_NAMES:
        return True
    return lowered.endswith(SENSITIVE_SUFFIXES)


def call_sink_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name) and node.id in SINK_FUNCTION_NAMES:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in SINK_METHOD_NAMES:
        return node.attr
    return None


def scan_file(path: Path) -> list[Finding]:
    tree = ast.parse(path.read_text(), filename=str(path))
    visitor = SensitiveOutputVisitor(path)
    visitor.visit(tree)
    return visitor.findings


def scan(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(scan_file(path))
    return findings


def main() -> int:
    findings = scan(TARGET_FILES)
    if findings:
        print("Sensitive output guard failed:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding.render()}", file=sys.stderr)
        return 1

    print("Sensitive output guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
