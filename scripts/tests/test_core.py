"""Tests for blend_scanner.core module."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from blend_scanner.core import BlendScanner
from blend_scanner.models import ExtractedData, Severity
from blend_scanner.scanners.malware import MalwareScanner
from blend_scanner.scanners.privacy import PrivacyScanner


class TestBlendScannerInit:
    """Tests for BlendScanner initialization."""

    def test_default_scanners(self):
        """Test that default scanners are MalwareScanner and PrivacyScanner."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            scanner = BlendScanner()

            assert len(scanner.scanners) == 2
            assert isinstance(scanner.scanners[0], MalwareScanner)
            assert isinstance(scanner.scanners[1], PrivacyScanner)

    def test_custom_scanners(self):
        """Test using custom scanners."""
        custom_scanner = MalwareScanner()
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            scanner = BlendScanner(scanners=[custom_scanner])

            assert len(scanner.scanners) == 1
            assert scanner.scanners[0] is custom_scanner

    def test_blender_version(self):
        """Test blender version setting."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/path/to/blender-4-LTS")
            scanner = BlendScanner(blender_version="blender-4-LTS")

            assert scanner.blender_version == "blender-4-LTS"

    def test_custom_blender_path(self):
        """Test custom blender path."""
        custom_path = Path("/custom/blender")
        scanner = BlendScanner(blender_path=custom_path)

        assert scanner.blender_path == custom_path

    def test_disable_addons_default(self):
        """Test disable_addons default is True."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            scanner = BlendScanner()

            assert scanner.disable_addons is True

    def test_enable_addons(self):
        """Test enabling addons."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            scanner = BlendScanner(disable_addons=False)

            assert scanner.disable_addons is False


class TestBlendScannerGetBlenderPath:
    """Tests for _get_blender_path method."""

    def test_path_from_env(self, tmp_path):
        """Test getting path from BLENDER_BASE_DIR env variable."""
        blender_dir = tmp_path / "blender-5"
        blender_dir.mkdir()

        with patch.dict(os.environ, {"BLENDER_BASE_DIR": str(tmp_path)}):
            scanner = BlendScanner(blender_version="blender-5")
            assert scanner.blender_path == blender_dir

    def test_path_not_found(self):
        """Test FileNotFoundError when blender not found."""
        with patch.dict(os.environ, {"BLENDER_BASE_DIR": "/nonexistent"}):
            with pytest.raises(FileNotFoundError) as exc_info:
                BlendScanner(blender_version="blender-5")
            assert "Blender not found" in str(exc_info.value)


class TestBlendScannerListVersions:
    """Tests for list_blender_versions static method."""

    def test_list_versions(self, tmp_path):
        """Test listing available Blender versions."""
        # Create fake blender directories
        (tmp_path / "blender-3-LTS").mkdir()
        (tmp_path / "blender-4").mkdir()
        (tmp_path / "blender-5").mkdir()
        (tmp_path / "other-folder").mkdir()  # Should be ignored

        with patch.dict(os.environ, {"BLENDER_BASE_DIR": str(tmp_path)}):
            versions = BlendScanner.list_blender_versions()

            assert "blender-3-LTS" in versions
            assert "blender-4" in versions
            assert "blender-5" in versions
            assert "other-folder" not in versions
            assert versions == sorted(versions)

    def test_list_versions_empty(self, tmp_path):
        """Test listing versions when no blender installed."""
        with patch.dict(os.environ, {"BLENDER_BASE_DIR": str(tmp_path)}):
            versions = BlendScanner.list_blender_versions()
            assert versions == []

    def test_list_versions_nonexistent_dir(self):
        """Test listing versions when base dir doesn't exist."""
        with patch.dict(os.environ, {"BLENDER_BASE_DIR": "/nonexistent/path"}):
            versions = BlendScanner.list_blender_versions()
            assert versions == []


class TestBlendScannerParseOutput:
    """Tests for _parse_extracted_output method."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner with mocked blender path."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            return BlendScanner()

    def test_parse_text_blocks(self, scanner):
        """Test parsing text blocks from output."""
        output = """
=== Text Block: script.py ===
import os
print('hello')
=== Text Block: init.py ===
# init
value = 42
=== End ===
"""
        data = scanner._parse_extracted_output(output)

        assert len(data.text_blocks) == 2
        assert "script.py" in data.text_blocks
        assert "init.py" in data.text_blocks
        assert "import os" in data.text_blocks["script.py"]
        assert "value = 42" in data.text_blocks["init.py"]

    def test_parse_driver_expressions(self, scanner):
        """Test parsing driver expressions."""
        output = """
=== Driver Expressions ===
Object: Cube, Property: location, Expression: frame * 0.1
Object: Sphere, Property: rotation, Expression: sin(frame)
=== End ===
"""
        data = scanner._parse_extracted_output(output)

        assert len(data.driver_expressions) == 2
        assert any("frame * 0.1" in expr for expr in data.driver_expressions)
        assert any("sin(frame)" in expr for expr in data.driver_expressions)

    def test_parse_node_scripts(self, scanner):
        """Test parsing node scripts."""
        output = """
=== Node Scripts ===
node_script_1.py
node_script_2.py
=== End ===
"""
        data = scanner._parse_extracted_output(output)

        assert len(data.node_scripts) == 2
        assert "node_script_1.py" in data.node_scripts
        assert "node_script_2.py" in data.node_scripts

    def test_parse_metadata(self, scanner):
        """Test parsing metadata."""
        output = """
=== Metadata ===
Blender Version: 4.2.0
File Path: /home/user/test.blend
Scene: Main
=== End ===
"""
        data = scanner._parse_extracted_output(output)

        assert data.metadata["Blender Version"] == "4.2.0"
        assert data.metadata["File Path"] == "/home/user/test.blend"
        assert data.metadata["Scene"] == "Main"

    def test_parse_external_refs(self, scanner):
        """Test parsing external references."""
        output = """
=== External References ===
/home/user/textures/image.png
/home/user/models/ref.blend
=== End ===
"""
        data = scanner._parse_extracted_output(output)

        assert len(data.external_refs) == 2
        assert "/home/user/textures/image.png" in data.external_refs
        assert "/home/user/models/ref.blend" in data.external_refs

    def test_parse_complete_output(self, scanner):
        """Test parsing complete output with all sections."""
        output = """
Some blender startup output...
=== Text Block: main.py ===
print('main')
=== Driver Expressions ===
Object: Cube, Expression: frame
=== Node Scripts ===
script.py
=== Metadata ===
Version: 4.2.0
=== External References ===
/path/to/file.png
=== End ===
More output...
"""
        data = scanner._parse_extracted_output(output)

        assert len(data.text_blocks) == 1
        assert len(data.driver_expressions) == 1
        assert len(data.node_scripts) == 1
        assert len(data.metadata) == 1
        assert len(data.external_refs) == 1

    def test_parse_empty_output(self, scanner):
        """Test parsing empty output."""
        data = scanner._parse_extracted_output("")

        assert data.text_blocks == {}
        assert data.driver_expressions == []
        assert data.node_scripts == []
        assert data.metadata == {}
        assert data.external_refs == []


class TestBlendScannerRunScanners:
    """Tests for _run_scanners method."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner with mocked blender path."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            return BlendScanner()

    def test_run_scanners_on_text_blocks(self, scanner):
        """Test running scanners on text blocks."""
        data = ExtractedData(
            text_blocks={
                "malicious.py": "os.system('rm -rf /')",
                "safe.py": "print('hello')",
            }
        )

        findings = scanner._run_scanners(data)

        assert len(findings) >= 1
        assert any(f.scanner == "malware" for f in findings)

    def test_run_scanners_on_drivers(self, scanner):
        """Test running scanners on driver expressions."""
        data = ExtractedData(
            driver_expressions=[
                "frame * 2",  # Safe
                "os.system('cmd')",  # Malicious
            ]
        )

        findings = scanner._run_scanners(data)

        malware_findings = [f for f in findings if f.scanner == "malware"]
        assert len(malware_findings) >= 1

    def test_privacy_scanner_on_external_refs(self, scanner):
        """Test privacy scanner checks external refs."""
        data = ExtractedData(
            external_refs=[
                "/home/username/secret/file.png",
            ]
        )

        findings = scanner._run_scanners(data)

        privacy_findings = [f for f in findings if f.scanner == "privacy"]
        assert len(privacy_findings) >= 1
        assert any("home path" in f.message.lower() for f in privacy_findings)

    def test_privacy_scanner_on_metadata(self, scanner):
        """Test privacy scanner checks metadata."""
        data = ExtractedData(
            metadata={
                "Author Email": "user@example.com",
            }
        )

        findings = scanner._run_scanners(data)

        privacy_findings = [f for f in findings if f.scanner == "privacy"]
        assert len(privacy_findings) >= 1
        assert any("email" in f.message.lower() for f in privacy_findings)


class TestBlendScannerScan:
    """Tests for scan method."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner with mocked blender path."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            return BlendScanner()

    def test_scan_returns_scan_result(self, scanner, tmp_path):
        """Test scan method returns ScanResult."""
        blend_file = tmp_path / "test.blend"
        blend_file.touch()

        mock_output = """
=== Text Block: script.py ===
print('hello')
=== End ===
"""
        mock_result = MagicMock()
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                scanner, "_get_blender_path", return_value=Path("/usr/bin/blender")
            ):
                result = scanner.scan(blend_file)

                assert result is not None
                assert hasattr(result, "extracted_data")
                assert hasattr(result, "findings")

    def test_scan_with_malicious_content(self, scanner, tmp_path):
        """Test scan detects malicious content."""
        blend_file = tmp_path / "test.blend"
        blend_file.touch()

        mock_output = """
=== Text Block: evil.py ===
import os
os.system('rm -rf /')
=== End ===
"""
        mock_result = MagicMock()
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch(
                "blend_scanner.scanners.bandit.BanditScanner.is_available",
                return_value=False,
            ):
                result = scanner.scan(blend_file)

                assert result.has_errors is True
                assert any(f.scanner == "malware" for f in result.findings)

    def test_scan_includes_bandit(self, scanner, tmp_path):
        """Test scan includes bandit when available."""
        blend_file = tmp_path / "test.blend"
        blend_file.touch()

        mock_output = """
=== Text Block: script.py ===
print('hello')
=== End ===
"""
        mock_result = MagicMock()
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        mock_bandit_result = MagicMock()
        mock_bandit_result.stdout = '{"results": []}'

        with patch("subprocess.run", side_effect=[mock_result, mock_bandit_result, mock_bandit_result]):
            with patch(
                "blend_scanner.scanners.bandit.BanditScanner.is_available",
                return_value=True,
            ):
                result = scanner.scan(blend_file)

                assert result is not None


class TestBlendScannerExtractData:
    """Tests for _extract_data method."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner with mocked blender path."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            return BlendScanner()

    def test_extract_data_calls_blender(self, scanner, tmp_path):
        """Test _extract_data calls blender with correct arguments."""
        blend_file = tmp_path / "test.blend"
        blend_file.touch()

        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            scanner._extract_data(blend_file)

            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]

            assert "--background" in args
            assert "--factory-startup" in args  # disable_addons=True
            assert str(blend_file) in args
            assert "--python" in args

    def test_extract_data_without_factory_startup(self, tmp_path):
        """Test _extract_data without --factory-startup when addons enabled."""
        with patch.object(BlendScanner, "_get_blender_path") as mock_path:
            mock_path.return_value = Path("/usr/bin/blender")
            scanner = BlendScanner(disable_addons=False)

        blend_file = tmp_path / "test.blend"
        blend_file.touch()

        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            scanner._extract_data(blend_file)

            args = mock_run.call_args[0][0]
            assert "--factory-startup" not in args
