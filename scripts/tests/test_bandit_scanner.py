"""Tests for blend_scanner.scanners.bandit module."""

import json
import pytest
from unittest.mock import patch, MagicMock

from blend_scanner.models import Severity
from blend_scanner.scanners.bandit import BanditScanner


class TestBanditScannerProperties:
    """Tests for BanditScanner properties."""

    def test_scanner_name(self, bandit_scanner):
        """Test scanner name property."""
        assert bandit_scanner.name == "bandit"

    def test_scanner_description(self, bandit_scanner):
        """Test scanner description property."""
        assert "bandit" in bandit_scanner.description.lower()
        assert "security" in bandit_scanner.description.lower()


class TestBanditScannerAvailability:
    """Tests for bandit availability check."""

    def test_is_available_when_installed(self):
        """Test is_available returns True when bandit is installed."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/bandit"
            assert BanditScanner.is_available() is True
            mock_which.assert_called_once_with("bandit")

    def test_is_available_when_not_installed(self):
        """Test is_available returns False when bandit is not installed."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = None
            assert BanditScanner.is_available() is False


class TestBanditScannerSeverityMapping:
    """Tests for severity mapping."""

    def test_map_severity_high(self, bandit_scanner):
        """Test HIGH severity maps to ERROR."""
        assert bandit_scanner._map_severity("HIGH") == Severity.ERROR

    def test_map_severity_medium(self, bandit_scanner):
        """Test MEDIUM severity maps to WARNING."""
        assert bandit_scanner._map_severity("MEDIUM") == Severity.WARNING

    def test_map_severity_low(self, bandit_scanner):
        """Test LOW severity maps to INFO."""
        assert bandit_scanner._map_severity("LOW") == Severity.INFO

    def test_map_severity_case_insensitive(self, bandit_scanner):
        """Test severity mapping is case insensitive."""
        assert bandit_scanner._map_severity("high") == Severity.ERROR
        assert bandit_scanner._map_severity("Medium") == Severity.WARNING
        assert bandit_scanner._map_severity("low") == Severity.INFO

    def test_map_severity_unknown(self, bandit_scanner):
        """Test unknown severity defaults to INFO."""
        assert bandit_scanner._map_severity("UNKNOWN") == Severity.INFO
        assert bandit_scanner._map_severity("") == Severity.INFO


class TestBanditScannerParsing:
    """Tests for bandit output parsing."""

    def test_parse_empty_output(self, bandit_scanner):
        """Test parsing empty output."""
        findings = bandit_scanner._parse_bandit_output("", {})
        assert len(findings) == 0

    def test_parse_invalid_json(self, bandit_scanner):
        """Test parsing invalid JSON."""
        findings = bandit_scanner._parse_bandit_output("not valid json", {})
        assert len(findings) == 0

    def test_parse_valid_output(self, bandit_scanner):
        """Test parsing valid bandit output."""
        bandit_output = json.dumps(
            {
                "results": [
                    {
                        "test_id": "B101",
                        "issue_text": "Use of assert detected.",
                        "issue_severity": "LOW",
                        "filename": "/tmp/test.py",
                        "line_number": 5,
                        "code": "assert x == 1",
                    },
                    {
                        "test_id": "B105",
                        "issue_text": "Possible hardcoded password.",
                        "issue_severity": "HIGH",
                        "filename": "/tmp/config.py",
                        "line_number": 10,
                        "code": 'password = "secret"',
                    },
                ]
            }
        )

        findings = bandit_scanner._parse_bandit_output(bandit_output, {})

        assert len(findings) == 2

        # Check first finding (LOW -> INFO)
        assert findings[0].scanner == "bandit"
        assert findings[0].severity == Severity.INFO
        assert "B101" in findings[0].message
        assert "assert" in findings[0].message
        assert "/tmp/test.py:5" in findings[0].location

        # Check second finding (HIGH -> ERROR)
        assert findings[1].severity == Severity.ERROR
        assert "B105" in findings[1].message
        assert "/tmp/config.py:10" in findings[1].location

    def test_parse_output_with_empty_results(self, bandit_scanner):
        """Test parsing output with empty results array."""
        bandit_output = json.dumps({"results": []})
        findings = bandit_scanner._parse_bandit_output(bandit_output, {})
        assert len(findings) == 0

    def test_parse_output_missing_fields(self, bandit_scanner):
        """Test parsing output with missing optional fields."""
        bandit_output = json.dumps(
            {
                "results": [
                    {
                        "issue_severity": "MEDIUM",
                    }
                ]
            }
        )
        findings = bandit_scanner._parse_bandit_output(bandit_output, {})
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARNING
        assert "B000" in findings[0].message  # Default test_id
        assert "unknown:0" in findings[0].location


class TestBanditScannerScanMultiple:
    """Tests for scan_multiple method."""

    def test_scan_multiple_when_unavailable(self, bandit_scanner):
        """Test scan_multiple returns empty when bandit unavailable."""
        with patch.object(BanditScanner, "is_available", return_value=False):
            findings = bandit_scanner.scan_multiple({"test.py": "code"})
            assert len(findings) == 0

    def test_scan_multiple_runs_bandit(self, bandit_scanner):
        """Test scan_multiple runs bandit command."""
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"results": []})

        with patch.object(BanditScanner, "is_available", return_value=True):
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                bandit_scanner.scan_multiple({"test.py": "print('hello')"})

                # Verify bandit was called
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert args[0] == "bandit"
                assert "-r" in args
                assert "-f" in args
                assert "json" in args

    def test_scan_multiple_with_findings(self, bandit_scanner):
        """Test scan_multiple returns findings."""
        bandit_output = json.dumps(
            {
                "results": [
                    {
                        "test_id": "B102",
                        "issue_text": "exec detected",
                        "issue_severity": "HIGH",
                        "filename": "/tmp/test.py",
                        "line_number": 1,
                        "code": "exec(code)",
                    }
                ]
            }
        )
        mock_result = MagicMock()
        mock_result.stdout = bandit_output

        with patch.object(BanditScanner, "is_available", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                findings = bandit_scanner.scan_multiple({"test.py": "exec(code)"})

                assert len(findings) == 1
                assert findings[0].severity == Severity.ERROR

    def test_scan_multiple_sanitizes_filenames(self, bandit_scanner):
        """Test that filenames with special characters are sanitized."""
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"results": []})

        with patch.object(BanditScanner, "is_available", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                # Should not raise an error
                bandit_scanner.scan_multiple(
                    {
                        "path/to/script.py": "code",
                        "block:name": "more code",
                    }
                )


class TestBanditScannerScan:
    """Tests for single content scan method."""

    def test_scan_delegates_to_scan_multiple(self, bandit_scanner):
        """Test scan method delegates to scan_multiple."""
        with patch.object(
            bandit_scanner, "scan_multiple", return_value=[]
        ) as mock_scan_multiple:
            bandit_scanner.scan("test code", "test.py")
            mock_scan_multiple.assert_called_once_with({"test.py": "test code"})


class TestBanditScannerRawOutput:
    """Tests for raw output retrieval."""

    def test_get_raw_output_when_unavailable(self, bandit_scanner):
        """Test get_raw_output returns None when bandit unavailable."""
        with patch.object(BanditScanner, "is_available", return_value=False):
            result = bandit_scanner.get_raw_output({"test.py": "code"})
            assert result is None

    def test_get_raw_output_returns_text(self, bandit_scanner):
        """Test get_raw_output returns bandit text output."""
        mock_result = MagicMock()
        mock_result.stdout = "Run started..."
        mock_result.stderr = ""

        with patch.object(BanditScanner, "is_available", return_value=True):
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                result = bandit_scanner.get_raw_output({"test.py": "code"})

                assert result == "Run started..."

                # Verify bandit was called without -f json
                args = mock_run.call_args[0][0]
                assert "-f" not in args
                assert "json" not in args


class TestBanditScannerIntegration:
    """Integration tests (run only if bandit is available)."""

    @pytest.fixture
    def skip_if_bandit_unavailable(self):
        """Skip test if bandit is not installed."""
        if not BanditScanner.is_available():
            pytest.skip("Bandit is not installed")

    def test_real_scan_with_issues(self, bandit_scanner, skip_if_bandit_unavailable):
        """Test real bandit scan with code that has issues."""
        code_with_issues = """
import subprocess
subprocess.call(shell=True)
exec("print('hello')")
"""
        findings = bandit_scanner.scan_multiple({"test.py": code_with_issues})

        # Should find at least subprocess issue
        assert len(findings) >= 1

    def test_real_scan_safe_code(self, bandit_scanner, skip_if_bandit_unavailable):
        """Test real bandit scan with safe code."""
        safe_code = """
def add(a, b):
    return a + b

if __name__ == "__main__":
    print(add(1, 2))
"""
        findings = bandit_scanner.scan_multiple({"test.py": safe_code})

        # Should not find any high severity issues
        error_findings = [f for f in findings if f.severity == Severity.ERROR]
        assert len(error_findings) == 0

    def test_real_raw_output(self, bandit_scanner, skip_if_bandit_unavailable):
        """Test real bandit raw output."""
        code = "exec('code')"
        output = bandit_scanner.get_raw_output({"test.py": code})

        assert output is not None
        assert isinstance(output, str)
