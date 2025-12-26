"""Privacy scanner for detecting personal information and secrets."""

import re

from blend_scanner.models import Finding, Severity
from blend_scanner.scanners.base import BaseScanner


class PrivacyScanner(BaseScanner):
    """Scanner for detecting privacy issues and leaked secrets."""

    # Error level patterns (high risk secrets)
    ERROR_PATTERNS = [
        # API Keys
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key detected"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token detected"),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token detected"),
        (r"ghu_[a-zA-Z0-9]{36}", "GitHub User-to-Server Token detected"),
        (r"ghs_[a-zA-Z0-9]{36}", "GitHub Server-to-Server Token detected"),
        (r"ghr_[a-zA-Z0-9]{36}", "GitHub Refresh Token detected"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID detected"),
        (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token detected"),
        # Password variables
        (
            r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']+[\"']",
            "Hardcoded password detected",
        ),
        # Connection strings
        (
            r"(mysql|postgres|postgresql|mongodb|redis)://[^\s\"']+",
            "Database connection string detected",
        ),
        # Private keys
        (
            r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
            "Private key detected",
        ),
    ]

    # Warning level patterns (need review)
    WARNING_PATTERNS = [
        # User paths
        (r"/home/[a-zA-Z][a-zA-Z0-9_-]+/", "Linux user home path detected"),
        (r"C:\\\\Users\\\\[^\\\\]+\\\\", "Windows user path detected"),
        (r'C:\\Users\\[^\\]+\\', "Windows user path detected"),
        # Email addresses
        (
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Email address detected",
        ),
        # Generic tokens/secrets
        (
            r"(?i)(api_key|apikey|api-key)\s*=\s*[\"'][^\"']+[\"']",
            "API key variable detected",
        ),
        (
            r"(?i)(secret|token)\s*=\s*[\"'][^\"']+[\"']",
            "Secret/token variable detected",
        ),
        (
            r"(?i)(auth|authorization)\s*=\s*[\"'][^\"']+[\"']",
            "Authorization header detected",
        ),
    ]

    # Info level patterns (reference only)
    INFO_PATTERNS = [
        # Public IP addresses (excluding private ranges)
        (
            r"\b(?!192\.168\.)(?!10\.)(?!172\.(1[6-9]|2[0-9]|3[01])\.)(?!127\.)"
            r"(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "Public IP address detected",
        ),
    ]

    @property
    def name(self) -> str:
        return "privacy"

    @property
    def description(self) -> str:
        return "Detects personal information and leaked secrets"

    def scan(self, content: str, source: str) -> list[Finding]:
        """Scan content for privacy issues."""
        findings = []

        for line_no, line in enumerate(content.split("\n"), 1):
            # Check error patterns
            for pattern, message in self.ERROR_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            scanner=self.name,
                            severity=Severity.ERROR,
                            message=message,
                            location=f"{source}:{line_no}",
                            matched_text=self._mask_sensitive(line.strip()),
                        )
                    )

            # Check warning patterns
            for pattern, message in self.WARNING_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            scanner=self.name,
                            severity=Severity.WARNING,
                            message=message,
                            location=f"{source}:{line_no}",
                            matched_text=line.strip(),
                        )
                    )

            # Check info patterns
            for pattern, message in self.INFO_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            scanner=self.name,
                            severity=Severity.INFO,
                            message=message,
                            location=f"{source}:{line_no}",
                            matched_text=line.strip(),
                        )
                    )

        return findings

    def _mask_sensitive(self, text: str) -> str:
        """Mask sensitive data in text for safe display."""
        # Mask API keys and tokens
        text = re.sub(r"(sk-)[a-zA-Z0-9]+", r"\1****", text)
        text = re.sub(r"(ghp_)[a-zA-Z0-9]+", r"\1****", text)
        text = re.sub(r"(AKIA)[0-9A-Z]+", r"\1****", text)
        text = re.sub(r"(xox[baprs]-)[0-9a-zA-Z-]+", r"\1****", text)
        # Mask passwords
        text = re.sub(
            r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
            r"\1=****",
            text,
        )
        return text
