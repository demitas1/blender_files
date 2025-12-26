#!/usr/bin/env python3
"""
Blender Security Scanner

Scan Blender files for security issues including:
- Malware patterns (dangerous code execution)
- Privacy issues (leaked credentials, personal paths)

Usage:
    python scripts/scan_blend.py <blend_file>
    python scripts/scan_blend.py <blend_file> --verbose
    python scripts/scan_blend.py <blend_file> -b blender-4-LTS
    python scripts/scan_blend.py --list-versions
"""

import sys
from pathlib import Path

# Add parent directory to path for package import
sys.path.insert(0, str(Path(__file__).parent))

from blend_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
