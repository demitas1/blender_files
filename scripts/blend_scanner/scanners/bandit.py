"""Bandit integration scanner for Python security analysis."""

import shutil
import subprocess
import tempfile
from pathlib import Path

from blend_scanner.models import Finding, Severity
from blend_scanner.scanners.base import BaseScanner


class BanditScanner(BaseScanner):
    """Scanner that integrates with the bandit security tool."""

    @property
    def name(self) -> str:
        return "bandit"

    @property
    def description(self) -> str:
        return "Python security analysis using bandit"

    @classmethod
    def is_available(cls) -> bool:
        """Check if bandit is installed."""
        return shutil.which("bandit") is not None

    def scan(self, content: str, source: str) -> list[Finding]:
        """
        Scan content using bandit.

        Note: This scanner works differently - it writes content to temp files
        and runs bandit on them. For single content, use scan_with_temp_dir.
        """
        # For single content, use scan_multiple which handles temp dir
        return self.scan_multiple({source: content})

    def scan_multiple(self, contents: dict[str, str]) -> list[Finding]:
        """Scan multiple content blocks using bandit."""
        if not self.is_available():
            return []

        findings = []

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Write each content block to a file
            for name, content in contents.items():
                safe_name = name.replace("/", "__").replace(":", "__")
                if not safe_name.endswith(".py"):
                    safe_name += ".py"
                file_path = temp_path / safe_name
                file_path.write_text(f"# Source: {name}\n{content}")

            # Run bandit
            result = subprocess.run(
                ["bandit", "-r", "-f", "json", str(temp_path)],
                capture_output=True,
                text=True,
            )

            # Parse bandit JSON output
            findings.extend(self._parse_bandit_output(result.stdout, contents))

        return findings

    def _parse_bandit_output(
        self, output: str, contents: dict[str, str]
    ) -> list[Finding]:
        """Parse bandit JSON output into findings."""
        import json

        findings = []

        if not output.strip():
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            severity = self._map_severity(result.get("issue_severity", "LOW"))
            findings.append(
                Finding(
                    scanner=self.name,
                    severity=severity,
                    message=f"[{result.get('test_id', 'B000')}] {result.get('issue_text', 'Unknown issue')}",
                    location=f"{result.get('filename', 'unknown')}:{result.get('line_number', 0)}",
                    matched_text=result.get("code", "").strip(),
                )
            )

        return findings

    def _map_severity(self, bandit_severity: str) -> Severity:
        """Map bandit severity to our severity levels."""
        mapping = {
            "HIGH": Severity.ERROR,
            "MEDIUM": Severity.WARNING,
            "LOW": Severity.INFO,
        }
        return mapping.get(bandit_severity.upper(), Severity.INFO)

    def get_raw_output(self, contents: dict[str, str]) -> str | None:
        """Get raw bandit output for display."""
        if not self.is_available():
            return None

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Write each content block to a file
            for name, content in contents.items():
                safe_name = name.replace("/", "__").replace(":", "__")
                if not safe_name.endswith(".py"):
                    safe_name += ".py"
                file_path = temp_path / safe_name
                file_path.write_text(f"# Source: {name}\n{content}")

            # Run bandit with text output
            result = subprocess.run(
                ["bandit", "-r", str(temp_path)],
                capture_output=True,
                text=True,
            )

            return result.stdout + result.stderr
