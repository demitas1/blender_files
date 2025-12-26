"""Security scanners for Blender files."""

from blend_scanner.scanners.base import BaseScanner
from blend_scanner.scanners.malware import MalwareScanner
from blend_scanner.scanners.privacy import PrivacyScanner
from blend_scanner.scanners.bandit import BanditScanner

__all__ = [
    "BaseScanner",
    "MalwareScanner",
    "PrivacyScanner",
    "BanditScanner",
]

# Default scanners to use
DEFAULT_SCANNERS: list[type[BaseScanner]] = [
    MalwareScanner,
    PrivacyScanner,
]
