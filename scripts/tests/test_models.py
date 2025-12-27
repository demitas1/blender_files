"""Tests for blend_scanner.models module."""

import pytest

from blend_scanner.models import Severity, Finding, ExtractedData, ScanResult


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.ERROR.value == "error"
        assert Severity.WARNING.value == "warning"
        assert Severity.INFO.value == "info"

    def test_severity_comparison(self):
        """Test severity enum comparison."""
        assert Severity.ERROR != Severity.WARNING
        assert Severity.ERROR == Severity.ERROR


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a Finding."""
        finding = Finding(
            scanner="malware",
            severity=Severity.ERROR,
            message="Test message",
            location="test.py:10",
            matched_text="os.system('rm -rf /')",
        )
        assert finding.scanner == "malware"
        assert finding.severity == Severity.ERROR
        assert finding.message == "Test message"
        assert finding.location == "test.py:10"
        assert finding.matched_text == "os.system('rm -rf /')"

    def test_finding_equality(self):
        """Test Finding equality."""
        finding1 = Finding(
            scanner="test",
            severity=Severity.ERROR,
            message="msg",
            location="file:1",
            matched_text="code",
        )
        finding2 = Finding(
            scanner="test",
            severity=Severity.ERROR,
            message="msg",
            location="file:1",
            matched_text="code",
        )
        assert finding1 == finding2


class TestExtractedData:
    """Tests for ExtractedData dataclass."""

    def test_extracted_data_defaults(self):
        """Test ExtractedData default values."""
        data = ExtractedData()
        assert data.text_blocks == {}
        assert data.driver_expressions == []
        assert data.node_scripts == []
        assert data.metadata == {}
        assert data.external_refs == []

    def test_extracted_data_with_values(self, sample_extracted_data):
        """Test ExtractedData with values."""
        assert len(sample_extracted_data.text_blocks) == 2
        assert "script.py" in sample_extracted_data.text_blocks
        assert len(sample_extracted_data.driver_expressions) == 2
        assert sample_extracted_data.metadata["Blender Version"] == "4.2.0"


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_defaults(self, empty_extracted_data):
        """Test ScanResult default values."""
        result = ScanResult(extracted_data=empty_extracted_data)
        assert result.findings == []
        assert result.bandit_output is None
        assert result.has_errors is False
        assert result.has_warnings is False

    def test_has_errors(self, sample_extracted_data):
        """Test has_errors property."""
        findings = [
            Finding(
                scanner="test",
                severity=Severity.ERROR,
                message="Error",
                location="test:1",
                matched_text="code",
            )
        ]
        result = ScanResult(
            extracted_data=sample_extracted_data,
            findings=findings,
        )
        assert result.has_errors is True
        assert result.has_warnings is False

    def test_has_warnings(self, sample_extracted_data):
        """Test has_warnings property."""
        findings = [
            Finding(
                scanner="test",
                severity=Severity.WARNING,
                message="Warning",
                location="test:1",
                matched_text="code",
            )
        ]
        result = ScanResult(
            extracted_data=sample_extracted_data,
            findings=findings,
        )
        assert result.has_errors is False
        assert result.has_warnings is True

    def test_has_both_errors_and_warnings(self, sample_extracted_data):
        """Test when both errors and warnings exist."""
        findings = [
            Finding(
                scanner="test",
                severity=Severity.ERROR,
                message="Error",
                location="test:1",
                matched_text="code",
            ),
            Finding(
                scanner="test",
                severity=Severity.WARNING,
                message="Warning",
                location="test:2",
                matched_text="code2",
            ),
        ]
        result = ScanResult(
            extracted_data=sample_extracted_data,
            findings=findings,
        )
        assert result.has_errors is True
        assert result.has_warnings is True

    def test_findings_by_severity(self, sample_extracted_data):
        """Test findings_by_severity method."""
        findings = [
            Finding(
                scanner="test",
                severity=Severity.ERROR,
                message="Error 1",
                location="test:1",
                matched_text="code1",
            ),
            Finding(
                scanner="test",
                severity=Severity.WARNING,
                message="Warning 1",
                location="test:2",
                matched_text="code2",
            ),
            Finding(
                scanner="test",
                severity=Severity.ERROR,
                message="Error 2",
                location="test:3",
                matched_text="code3",
            ),
            Finding(
                scanner="test",
                severity=Severity.INFO,
                message="Info 1",
                location="test:4",
                matched_text="code4",
            ),
        ]
        result = ScanResult(
            extracted_data=sample_extracted_data,
            findings=findings,
        )

        errors = result.findings_by_severity(Severity.ERROR)
        assert len(errors) == 2

        warnings = result.findings_by_severity(Severity.WARNING)
        assert len(warnings) == 1

        infos = result.findings_by_severity(Severity.INFO)
        assert len(infos) == 1

    def test_findings_by_scanner(self, sample_extracted_data):
        """Test findings_by_scanner method."""
        findings = [
            Finding(
                scanner="malware",
                severity=Severity.ERROR,
                message="Malware 1",
                location="test:1",
                matched_text="code1",
            ),
            Finding(
                scanner="privacy",
                severity=Severity.WARNING,
                message="Privacy 1",
                location="test:2",
                matched_text="code2",
            ),
            Finding(
                scanner="malware",
                severity=Severity.ERROR,
                message="Malware 2",
                location="test:3",
                matched_text="code3",
            ),
        ]
        result = ScanResult(
            extracted_data=sample_extracted_data,
            findings=findings,
        )

        malware_findings = result.findings_by_scanner("malware")
        assert len(malware_findings) == 2

        privacy_findings = result.findings_by_scanner("privacy")
        assert len(privacy_findings) == 1

        bandit_findings = result.findings_by_scanner("bandit")
        assert len(bandit_findings) == 0

    def test_scan_result_with_bandit_output(self, sample_extracted_data):
        """Test ScanResult with bandit output."""
        result = ScanResult(
            extracted_data=sample_extracted_data,
            findings=[],
            bandit_output="Bandit output here",
        )
        assert result.bandit_output == "Bandit output here"
