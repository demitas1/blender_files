"""Blender installation detection."""

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from blend_scanner.config import ScannerConfig


@dataclass
class BlenderInfo:
    """Information about a detected Blender installation."""

    path: Path
    version_name: str  # e.g., "blender-4-LTS"
    version_number: str | None = None  # e.g., "4.5.0"


class BlenderDetector:
    """Detect Blender installations based on configuration."""

    def __init__(self, config: ScannerConfig | None = None):
        """
        Initialize the detector.

        Args:
            config: Scanner configuration. If None, loads from file or uses defaults.
        """
        self.config = config or ScannerConfig.load()

    def detect(self) -> BlenderInfo | None:
        """
        Detect Blender installation based on configuration priority.

        Returns:
            BlenderInfo if found, None otherwise
        """
        base_path = self.config.blender.base_path

        if not base_path.exists():
            return None

        for version_name in self.config.blender.versions:
            blender_path = base_path / version_name
            if blender_path.exists():
                version_number = self._get_version_number(blender_path)
                return BlenderInfo(
                    path=blender_path,
                    version_name=version_name,
                    version_number=version_number,
                )

        return None

    def detect_all(self) -> list[BlenderInfo]:
        """
        Detect all available Blender installations.

        Returns:
            List of BlenderInfo for all found installations
        """
        base_path = self.config.blender.base_path
        found: list[BlenderInfo] = []

        if not base_path.exists():
            return found

        for version_name in self.config.blender.versions:
            blender_path = base_path / version_name
            if blender_path.exists():
                version_number = self._get_version_number(blender_path)
                found.append(
                    BlenderInfo(
                        path=blender_path,
                        version_name=version_name,
                        version_number=version_number,
                    )
                )

        return found

    def _get_version_number(self, blender_path: Path) -> str | None:
        """
        Get Blender version number by running blender --version.

        Args:
            blender_path: Path to Blender directory

        Returns:
            Version string (e.g., "4.5.0") or None if detection fails
        """
        try:
            result = subprocess.run(
                [str(blender_path), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Parse output like "Blender 4.5.0"
            match = re.search(r"Blender (\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return None

    @staticmethod
    def get_blender_from_path() -> Path | None:
        """
        Try to find Blender in system PATH.

        Returns:
            Path to blender executable or None
        """
        import shutil

        blender_path = shutil.which("blender")
        return Path(blender_path) if blender_path else None
