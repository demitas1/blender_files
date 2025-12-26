"""
blend_scanner - Security scanner for Blender files

This package provides tools for scanning Blender files for:
- Malware patterns (dangerous code execution)
- Privacy issues (leaked credentials, personal paths)
"""

from blend_scanner.models import (
    Severity,
    Finding,
    ExtractedData,
    ScanResult,
)
from blend_scanner.colors import Colors

__version__ = "1.0.0"
__all__ = [
    "Severity",
    "Finding",
    "ExtractedData",
    "ScanResult",
    "Colors",
]
