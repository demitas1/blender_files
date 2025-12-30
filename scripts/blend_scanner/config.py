"""Configuration management for blend_scanner."""

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class BlenderConfig:
    """Blender-related configuration."""

    versions: list[str] = field(default_factory=lambda: ["blender-4-LTS", "blender-3-LTS", "blender-5"])
    base_dir: str = "~/Application/blender"

    @property
    def base_path(self) -> Path:
        """Get expanded base directory path."""
        return Path(os.path.expanduser(self.base_dir))


@dataclass
class PreCommitConfig:
    """Pre-commit hook configuration."""

    # Behavior when Blender is not found: "warn", "error", "skip"
    no_blender: str = "warn"
    scanners: list[str] = field(default_factory=lambda: ["malware", "privacy"])


@dataclass
class ScannerConfig:
    """Root configuration for blend_scanner."""

    blender: BlenderConfig = field(default_factory=BlenderConfig)
    pre_commit: PreCommitConfig = field(default_factory=PreCommitConfig)

    @classmethod
    def load(cls, config_path: Path | None = None) -> "ScannerConfig":
        """
        Load configuration from file.

        Search order:
        1. Specified config_path
        2. .blend-scanner.yaml in current directory
        3. .blend-scanner.yaml in git root
        4. Default configuration

        Args:
            config_path: Optional path to config file

        Returns:
            Loaded configuration
        """
        if config_path and config_path.exists():
            return cls._load_from_file(config_path)

        # Search for config file
        search_paths = [
            Path.cwd() / ".blend-scanner.yaml",
            cls._find_git_root() / ".blend-scanner.yaml" if cls._find_git_root() else None,
        ]

        for path in search_paths:
            if path and path.exists():
                return cls._load_from_file(path)

        # Return default configuration
        return cls()

    @classmethod
    def _load_from_file(cls, path: Path) -> "ScannerConfig":
        """Load configuration from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        blender_data = data.get("blender", {})
        pre_commit_data = data.get("pre_commit", {})

        blender_config = BlenderConfig(
            versions=blender_data.get("versions", BlenderConfig().versions),
            base_dir=blender_data.get("base_dir", BlenderConfig().base_dir),
        )

        pre_commit_config = PreCommitConfig(
            no_blender=pre_commit_data.get("no_blender", PreCommitConfig().no_blender),
            scanners=pre_commit_data.get("scanners", PreCommitConfig().scanners),
        )

        return cls(blender=blender_config, pre_commit=pre_commit_config)

    @staticmethod
    def _find_git_root() -> Path | None:
        """Find the git repository root directory."""
        current = Path.cwd()
        while current != current.parent:
            if (current / ".git").exists():
                return current
            current = current.parent
        return None
