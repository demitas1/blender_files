"""Tests for blend_scanner.blender_detector module."""

import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch, MagicMock

from blend_scanner.blender_detector import BlenderDetector, BlenderInfo
from blend_scanner.config import ScannerConfig, BlenderConfig, PreCommitConfig


class TestBlenderInfo:
    """Tests for BlenderInfo dataclass."""

    def test_basic_info(self):
        """Test BlenderInfo creation."""
        info = BlenderInfo(
            path=Path("/opt/blender/blender-4-LTS"),
            version_name="blender-4-LTS",
            version_number="4.5.0",
        )
        assert info.path == Path("/opt/blender/blender-4-LTS")
        assert info.version_name == "blender-4-LTS"
        assert info.version_number == "4.5.0"

    def test_without_version_number(self):
        """Test BlenderInfo without version number."""
        info = BlenderInfo(
            path=Path("/opt/blender/blender-5"),
            version_name="blender-5",
        )
        assert info.version_number is None


class TestBlenderDetector:
    """Tests for BlenderDetector class."""

    def test_detect_no_blender_dir(self):
        """Test detection when base directory doesn't exist."""
        with TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                blender=BlenderConfig(
                    versions=["blender-4-LTS"],
                    base_dir=f"{tmpdir}/nonexistent",
                )
            )
            detector = BlenderDetector(config)
            result = detector.detect()
            assert result is None

    def test_detect_finds_first_available(self):
        """Test that detector finds the first available version."""
        with TemporaryDirectory() as tmpdir:
            # Create blender-5 directory (second in priority)
            blender_5_path = Path(tmpdir) / "blender-5"
            blender_5_path.mkdir()

            config = ScannerConfig(
                blender=BlenderConfig(
                    versions=["blender-4-LTS", "blender-5"],
                    base_dir=tmpdir,
                )
            )
            detector = BlenderDetector(config)

            # Mock _get_version_number to avoid running blender
            with patch.object(detector, "_get_version_number", return_value="5.0.0"):
                result = detector.detect()

            assert result is not None
            assert result.version_name == "blender-5"
            assert result.path == blender_5_path

    def test_detect_respects_priority(self):
        """Test that detector respects version priority order."""
        with TemporaryDirectory() as tmpdir:
            # Create both directories
            blender_4_path = Path(tmpdir) / "blender-4-LTS"
            blender_5_path = Path(tmpdir) / "blender-5"
            blender_4_path.mkdir()
            blender_5_path.mkdir()

            config = ScannerConfig(
                blender=BlenderConfig(
                    versions=["blender-4-LTS", "blender-5"],
                    base_dir=tmpdir,
                )
            )
            detector = BlenderDetector(config)

            with patch.object(detector, "_get_version_number", return_value="4.5.0"):
                result = detector.detect()

            # Should find blender-4-LTS first
            assert result is not None
            assert result.version_name == "blender-4-LTS"

    def test_detect_all(self):
        """Test detecting all available versions."""
        with TemporaryDirectory() as tmpdir:
            # Create multiple blender directories
            blender_3_path = Path(tmpdir) / "blender-3-LTS"
            blender_4_path = Path(tmpdir) / "blender-4-LTS"
            blender_3_path.mkdir()
            blender_4_path.mkdir()

            config = ScannerConfig(
                blender=BlenderConfig(
                    versions=["blender-4-LTS", "blender-3-LTS", "blender-5"],
                    base_dir=tmpdir,
                )
            )
            detector = BlenderDetector(config)

            with patch.object(detector, "_get_version_number", return_value="4.0.0"):
                results = detector.detect_all()

            assert len(results) == 2
            names = [r.version_name for r in results]
            assert "blender-4-LTS" in names
            assert "blender-3-LTS" in names
            assert "blender-5" not in names

    def test_detect_all_empty(self):
        """Test detect_all when no versions are found."""
        with TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                blender=BlenderConfig(
                    versions=["blender-4-LTS"],
                    base_dir=tmpdir,
                )
            )
            detector = BlenderDetector(config)
            results = detector.detect_all()
            assert results == []

    def test_get_version_number_success(self):
        """Test version number extraction from blender output."""
        detector = BlenderDetector()

        mock_result = MagicMock()
        mock_result.stdout = "Blender 4.5.0\nSome other output"

        with patch("subprocess.run", return_value=mock_result):
            version = detector._get_version_number(Path("/opt/blender"))

        assert version == "4.5.0"

    def test_get_version_number_failure(self):
        """Test version number extraction when blender fails."""
        detector = BlenderDetector()

        with patch("subprocess.run", side_effect=OSError("Not found")):
            version = detector._get_version_number(Path("/opt/blender"))

        assert version is None

    def test_get_version_number_timeout(self):
        """Test version number extraction when blender times out."""
        import subprocess

        detector = BlenderDetector()

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("blender", 10)):
            version = detector._get_version_number(Path("/opt/blender"))

        assert version is None

    def test_get_blender_from_path_found(self):
        """Test finding blender in PATH."""
        with patch("shutil.which", return_value="/usr/bin/blender"):
            result = BlenderDetector.get_blender_from_path()
            assert result == Path("/usr/bin/blender")

    def test_get_blender_from_path_not_found(self):
        """Test when blender is not in PATH."""
        with patch("shutil.which", return_value=None):
            result = BlenderDetector.get_blender_from_path()
            assert result is None

    def test_uses_default_config(self):
        """Test that detector loads default config when none provided."""
        with patch.object(ScannerConfig, "load") as mock_load:
            mock_load.return_value = ScannerConfig()
            detector = BlenderDetector()
            mock_load.assert_called_once()
