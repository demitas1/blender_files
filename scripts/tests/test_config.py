"""Tests for blend_scanner.config module."""

import pytest
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

from blend_scanner.config import (
    BlenderConfig,
    PreCommitConfig,
    ScannerConfig,
)


class TestBlenderConfig:
    """Tests for BlenderConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = BlenderConfig()
        assert config.versions == ["blender-4-LTS", "blender-3-LTS", "blender-5"]
        assert config.base_dir == "~/Application/blender"

    def test_custom_values(self):
        """Test custom configuration values."""
        config = BlenderConfig(
            versions=["blender-5", "blender-4"],
            base_dir="/opt/blender",
        )
        assert config.versions == ["blender-5", "blender-4"]
        assert config.base_dir == "/opt/blender"

    def test_base_path_expansion(self):
        """Test that base_path expands ~ correctly."""
        config = BlenderConfig(base_dir="~/Application/blender")
        assert "~" not in str(config.base_path)
        assert config.base_path.is_absolute()


class TestPreCommitConfig:
    """Tests for PreCommitConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = PreCommitConfig()
        assert config.no_blender == "warn"
        assert config.scanners == ["malware", "privacy"]

    def test_custom_values(self):
        """Test custom configuration values."""
        config = PreCommitConfig(
            no_blender="error",
            scanners=["malware"],
        )
        assert config.no_blender == "error"
        assert config.scanners == ["malware"]


class TestScannerConfig:
    """Tests for ScannerConfig dataclass."""

    def test_default_config(self):
        """Test default configuration."""
        config = ScannerConfig()
        assert isinstance(config.blender, BlenderConfig)
        assert isinstance(config.pre_commit, PreCommitConfig)

    def test_load_default_when_no_file(self):
        """Test that default config is returned when no file exists."""
        with TemporaryDirectory() as tmpdir:
            # Change to temp directory with no config file
            import os
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                config = ScannerConfig.load()
                assert config.blender.versions == BlenderConfig().versions
            finally:
                os.chdir(original_cwd)

    def test_load_from_file(self):
        """Test loading configuration from file."""
        yaml_content = """
blender:
  versions:
    - blender-5
    - blender-4-LTS
  base_dir: /custom/path

pre_commit:
  no_blender: error
  scanners:
    - malware
"""
        with NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config_path = Path(f.name)

        try:
            config = ScannerConfig.load(config_path)
            assert config.blender.versions == ["blender-5", "blender-4-LTS"]
            assert config.blender.base_dir == "/custom/path"
            assert config.pre_commit.no_blender == "error"
            assert config.pre_commit.scanners == ["malware"]
        finally:
            config_path.unlink()

    def test_load_partial_config(self):
        """Test loading partial configuration (missing sections use defaults)."""
        yaml_content = """
blender:
  versions:
    - blender-5
"""
        with NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config_path = Path(f.name)

        try:
            config = ScannerConfig.load(config_path)
            assert config.blender.versions == ["blender-5"]
            # Default values for missing fields
            assert config.blender.base_dir == "~/Application/blender"
            assert config.pre_commit.no_blender == "warn"
            assert config.pre_commit.scanners == ["malware", "privacy"]
        finally:
            config_path.unlink()

    def test_load_empty_file(self):
        """Test loading empty configuration file."""
        yaml_content = ""
        with NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config_path = Path(f.name)

        try:
            config = ScannerConfig.load(config_path)
            # Should use all defaults
            assert config.blender.versions == BlenderConfig().versions
            assert config.pre_commit.no_blender == "warn"
        finally:
            config_path.unlink()

    def test_find_git_root(self):
        """Test _find_git_root method."""
        # The test is running in a git repository
        git_root = ScannerConfig._find_git_root()
        if git_root:
            assert (git_root / ".git").exists()
