"""Base scanner class for security scanning."""

from abc import ABC, abstractmethod

from blend_scanner.models import Finding


class BaseScanner(ABC):
    """Abstract base class for security scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the scanner name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a brief description of what this scanner detects."""
        pass

    @abstractmethod
    def scan(self, content: str, source: str) -> list[Finding]:
        """
        Scan content for security issues.

        Args:
            content: The text content to scan
            source: The source identifier (e.g., text block name)

        Returns:
            List of findings
        """
        pass

    def scan_multiple(self, contents: dict[str, str]) -> list[Finding]:
        """
        Scan multiple content blocks.

        Args:
            contents: Dictionary of {source: content}

        Returns:
            Combined list of findings from all content blocks
        """
        findings = []
        for source, content in contents.items():
            findings.extend(self.scan(content, source))
        return findings
