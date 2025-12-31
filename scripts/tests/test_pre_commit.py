"""Tests for pre_commit_scan module."""

import os
import pytest
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch, MagicMock

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(scripts_dir))

from pre_commit_scan import main, get_scanners, print_file_result
from blend_scanner.config import ScannerConfig, BlenderConfig, BlenderConfigError, PreCommitConfig
from blend_scanner.blender_detector import BlenderInfo
from blend_scanner.models import ScanResult, ExtractedData, Finding, Severity


class TestGetScanners:
    """Tests for get_scanners function."""

    def test_get_malware_scanner(self):
        """Test getting malware scanner."""
        scanners = get_scanners(["malware"])
        assert len(scanners) == 1
        assert scanners[0].__class__.__name__ == "MalwareScanner"

    def test_get_privacy_scanner(self):
        """Test getting privacy scanner."""
        scanners = get_scanners(["privacy"])
        assert len(scanners) == 1
        assert scanners[0].__class__.__name__ == "PrivacyScanner"

    def test_get_multiple_scanners(self):
        """Test getting multiple scanners."""
        scanners = get_scanners(["malware", "privacy"])
        assert len(scanners) == 2

    def test_get_unknown_scanner(self):
        """Test that unknown scanners are ignored."""
        scanners = get_scanners(["malware", "unknown"])
        assert len(scanners) == 1

    def test_get_empty_list(self):
        """Test with empty scanner list."""
        scanners = get_scanners([])
        assert len(scanners) == 0


class TestPrintFileResult:
    """Tests for print_file_result function."""

    def test_result_with_errors(self, capsys):
        """Test printing result with errors."""
        result = ScanResult(
            extracted_data=ExtractedData(),
            findings=[
                Finding(
                    scanner="malware",
                    severity=Severity.ERROR,
                    message="Dangerous pattern detected",
                    location="script.py:5",
                    matched_text="os.system('rm -rf')",
                )
            ],
        )

        has_errors = print_file_result(Path("test.blend"), result)

        assert has_errors is True
        captured = capsys.readouterr()
        assert "test.blend" in captured.out
        assert "ERROR" in captured.out

    def test_result_with_warnings(self, capsys):
        """Test printing result with warnings only."""
        result = ScanResult(
            extracted_data=ExtractedData(),
            findings=[
                Finding(
                    scanner="privacy",
                    severity=Severity.WARNING,
                    message="User path detected",
                    location="script.py:10",
                    matched_text="/home/user/",
                )
            ],
        )

        has_errors = print_file_result(Path("test.blend"), result)

        assert has_errors is False
        captured = capsys.readouterr()
        assert "test.blend" in captured.out
        assert "WARNING" in captured.out

    def test_result_clean(self, capsys):
        """Test printing clean result."""
        result = ScanResult(
            extracted_data=ExtractedData(),
            findings=[],
        )

        has_errors = print_file_result(Path("test.blend"), result)

        assert has_errors is False
        captured = capsys.readouterr()
        assert "OK" in captured.out


class TestMain:
    """Tests for main function."""

    def test_no_blend_files(self):
        """Test with no .blend files in args."""
        exit_code = main(["file.py", "file.txt"])
        assert exit_code == 0

    def test_empty_args(self):
        """Test with empty args."""
        exit_code = main([])
        assert exit_code == 0

    def test_blender_config_error(self, capsys):
        """Test behavior when Blender base_dir is not configured."""
        config = ScannerConfig(
            blender=BlenderConfig(base_dir=None),
        )

        with patch("pre_commit_scan.ScannerConfig.load", return_value=config):
            exit_code = main(["test.blend"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "configuration error" in captured.out.lower()
        assert "base_dir" in captured.out

    def test_no_blender_warn_mode(self, capsys):
        """Test behavior when Blender not found with warn mode."""
        config = ScannerConfig(
            blender=BlenderConfig(base_dir="/nonexistent"),
            pre_commit=PreCommitConfig(no_blender="warn"),
        )

        with patch("pre_commit_scan.ScannerConfig.load", return_value=config):
            with patch("pre_commit_scan.BlenderDetector") as mock_detector_class:
                mock_detector = MagicMock()
                mock_detector.detect.return_value = None
                mock_detector_class.return_value = mock_detector

                exit_code = main(["test.blend"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "Blender not found" in captured.out

    def test_no_blender_error_mode(self, capsys):
        """Test behavior when Blender not found with error mode."""
        config = ScannerConfig(
            blender=BlenderConfig(base_dir="/nonexistent"),
            pre_commit=PreCommitConfig(no_blender="error"),
        )

        with patch("pre_commit_scan.ScannerConfig.load", return_value=config):
            with patch("pre_commit_scan.BlenderDetector") as mock_detector_class:
                mock_detector = MagicMock()
                mock_detector.detect.return_value = None
                mock_detector_class.return_value = mock_detector

                exit_code = main(["test.blend"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "ERROR" in captured.out
        assert "SKIP_BLEND_SCAN=1" in captured.out

    def test_no_blender_error_mode_with_skip_env(self, capsys):
        """Test behavior when Blender not found with error mode but SKIP_BLEND_SCAN=1."""
        config = ScannerConfig(
            blender=BlenderConfig(base_dir="/nonexistent"),
            pre_commit=PreCommitConfig(no_blender="error"),
        )

        with patch("pre_commit_scan.ScannerConfig.load", return_value=config):
            with patch("pre_commit_scan.BlenderDetector") as mock_detector_class:
                mock_detector = MagicMock()
                mock_detector.detect.return_value = None
                mock_detector_class.return_value = mock_detector

                with patch.dict(os.environ, {"SKIP_BLEND_SCAN": "1"}):
                    exit_code = main(["test.blend"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "scan skipped" in captured.out

    def test_no_blender_skip_mode(self, capsys):
        """Test behavior when Blender not found with skip mode."""
        config = ScannerConfig(
            blender=BlenderConfig(base_dir="/nonexistent"),
            pre_commit=PreCommitConfig(no_blender="skip"),
        )

        with patch("pre_commit_scan.ScannerConfig.load", return_value=config):
            with patch("pre_commit_scan.BlenderDetector") as mock_detector_class:
                mock_detector = MagicMock()
                mock_detector.detect.return_value = None
                mock_detector_class.return_value = mock_detector

                exit_code = main(["test.blend"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "skipping" in captured.out.lower()

    def test_file_not_found(self, capsys):
        """Test with non-existent .blend file."""
        config = ScannerConfig()
        blender_info = BlenderInfo(
            path=Path("/opt/blender"),
            version_name="blender-4-LTS",
            version_number="4.5.0",
        )

        with patch("pre_commit_scan.ScannerConfig.load", return_value=config):
            with patch("pre_commit_scan.BlenderDetector") as mock_detector_class:
                mock_detector = MagicMock()
                mock_detector.detect.return_value = blender_info
                mock_detector_class.return_value = mock_detector

                with patch("pre_commit_scan.BlendScanner"):
                    exit_code = main(["/nonexistent/test.blend"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "skipped" in captured.out.lower()

    def test_scan_with_errors(self):
        """Test scan that finds errors."""
        config = ScannerConfig()
        blender_info = BlenderInfo(
            path=Path("/opt/blender"),
            version_name="blender-4-LTS",
            version_number="4.5.0",
        )

        error_result = ScanResult(
            extracted_data=ExtractedData(),
            findings=[
                Finding(
                    scanner="malware",
                    severity=Severity.ERROR,
                    message="Dangerous",
                    location="test:1",
                    matched_text="os.system",
                )
            ],
        )

        with TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.blend"
            test_file.touch()

            with patch("pre_commit_scan.ScannerConfig.load", return_value=config):
                with patch("pre_commit_scan.BlenderDetector") as mock_detector_class:
                    mock_detector = MagicMock()
                    mock_detector.detect.return_value = blender_info
                    mock_detector_class.return_value = mock_detector

                    with patch("pre_commit_scan.BlendScanner") as mock_scanner_class:
                        mock_scanner = MagicMock()
                        mock_scanner.scan.return_value = error_result
                        mock_scanner_class.return_value = mock_scanner

                        exit_code = main([str(test_file)])

            assert exit_code == 1

    def test_scan_clean(self):
        """Test scan with no issues."""
        config = ScannerConfig()
        blender_info = BlenderInfo(
            path=Path("/opt/blender"),
            version_name="blender-4-LTS",
            version_number="4.5.0",
        )

        clean_result = ScanResult(
            extracted_data=ExtractedData(),
            findings=[],
        )

        with TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.blend"
            test_file.touch()

            with patch("pre_commit_scan.ScannerConfig.load", return_value=config):
                with patch("pre_commit_scan.BlenderDetector") as mock_detector_class:
                    mock_detector = MagicMock()
                    mock_detector.detect.return_value = blender_info
                    mock_detector_class.return_value = mock_detector

                    with patch("pre_commit_scan.BlendScanner") as mock_scanner_class:
                        mock_scanner = MagicMock()
                        mock_scanner.scan.return_value = clean_result
                        mock_scanner_class.return_value = mock_scanner

                        exit_code = main([str(test_file)])

            assert exit_code == 0
