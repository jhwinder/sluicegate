from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional

Severity = Literal["error", "warning"]


@dataclass
class ValidationIssue:
    severity: Severity
    path: str
    message: str
    line: Optional[int] = None


@dataclass
class ValidationResult:
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def add_error(self, path: str, message: str, *, line: Optional[int] = None) -> None:
        self.issues.append(ValidationIssue(severity="error", path=path, message=message, line=line))

    def add_warning(self, path: str, message: str, *, line: Optional[int] = None) -> None:
        self.issues.append(ValidationIssue(severity="warning", path=path, message=message, line=line))

    def render(self) -> str:
        if not self.issues:
            return "Policy is valid."
        rows = []
        for issue in self.issues:
            location = issue.path or "<root>"
            if issue.line is not None:
                location = f"{location}:line {issue.line}"
            rows.append(f"{issue.severity.upper()}: {location}: {issue.message}")
        return "\n".join(rows)
