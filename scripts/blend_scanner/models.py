"""Data models for blend_scanner package."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""

    ERROR = "error"  # Dangerous: immediate action required
    WARNING = "warning"  # Warning: review recommended
    INFO = "info"  # Information: reference only


@dataclass
class Finding:
    """A security finding from a scanner."""

    scanner: str  # Scanner name
    severity: Severity  # Severity level
    message: str  # Description message
    location: str  # File/block name:line number
    matched_text: str  # Matched text


@dataclass
class ExtractedData:
    """Data extracted from a Blender file."""

    text_blocks: dict[str, str] = field(default_factory=dict)  # {name: content}
    driver_expressions: list[str] = field(default_factory=list)  # Driver expressions
    node_scripts: list[str] = field(default_factory=list)  # Node scripts
    metadata: dict[str, str] = field(default_factory=dict)  # Metadata
    external_refs: list[str] = field(default_factory=list)  # External reference paths


@dataclass
class ScanResult:
    """Result of scanning a Blender file."""

    extracted_data: ExtractedData
    findings: list[Finding] = field(default_factory=list)
    bandit_output: str | None = None

    @property
    def has_errors(self) -> bool:
        """Check if any error-level findings exist."""
        return any(f.severity == Severity.ERROR for f in self.findings)

    @property
    def has_warnings(self) -> bool:
        """Check if any warning-level findings exist."""
        return any(f.severity == Severity.WARNING for f in self.findings)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def findings_by_scanner(self, scanner_name: str) -> list[Finding]:
        """Get findings filtered by scanner name."""
        return [f for f in self.findings if f.scanner == scanner_name]
