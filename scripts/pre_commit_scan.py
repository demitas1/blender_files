#!/usr/bin/env python3
"""
Pre-commit hook for scanning .blend files.

This script is designed to be called by pre-commit framework.
It scans staged .blend files for security issues.

Usage:
    python scripts/pre_commit_scan.py <blend_file1> [blend_file2] ...

Exit codes:
    0 - No errors (warnings may be present)
    1 - Errors detected (commit should be blocked)
"""

import os
import sys
from pathlib import Path

# Add parent directory to path for package import
sys.path.insert(0, str(Path(__file__).parent))

from blend_scanner.blender_detector import BlenderDetector
from blend_scanner.colors import Colors
from blend_scanner.config import BlenderConfigError, ScannerConfig
from blend_scanner.core import BlendScanner
from blend_scanner.models import Severity
from blend_scanner.scanners.malware import MalwareScanner
from blend_scanner.scanners.privacy import PrivacyScanner


def get_scanners(scanner_names: list[str]) -> list:
    """Create scanner instances from names."""
    scanner_map = {
        "malware": MalwareScanner,
        "privacy": PrivacyScanner,
    }
    return [scanner_map[name]() for name in scanner_names if name in scanner_map]


def print_file_result(file_path: Path, result, verbose: bool = False) -> bool:
    """
    Print result for a single file.

    Returns:
        True if errors were found, False otherwise
    """
    errors = result.findings_by_severity(Severity.ERROR)
    warnings = result.findings_by_severity(Severity.WARNING)

    if errors:
        print(Colors.red(f"  ✗ {file_path} - {len(errors)} ERROR(s)"))
        for finding in errors:
            print(f"    [{finding.scanner}] {finding.location}")
            print(f"      {finding.message}")
            if verbose:
                print(f"      {finding.matched_text}")
        return True
    elif warnings:
        print(Colors.yellow(f"  ! {file_path} - {len(warnings)} WARNING(s)"))
        if verbose:
            for finding in warnings:
                print(f"    [{finding.scanner}] {finding.location}")
                print(f"      {finding.message}")
        return False
    else:
        print(Colors.green(f"  ✓ {file_path} - OK"))
        return False


def main(args: list[str] | None = None) -> int:
    """
    Main entry point for pre-commit hook.

    Args:
        args: Command line arguments (file paths)

    Returns:
        Exit code (0 = success, 1 = errors found)
    """
    if args is None:
        args = sys.argv[1:]

    # Filter to only .blend files
    blend_files = [Path(f) for f in args if f.endswith(".blend")]

    if not blend_files:
        return 0

    # Load configuration
    config = ScannerConfig.load()

    print(f"[pre-commit] Scanning {len(blend_files)} .blend file(s)...")

    # Detect Blender
    detector = BlenderDetector(config)
    try:
        blender_info = detector.detect()
    except BlenderConfigError as e:
        print(Colors.red("[pre-commit] ERROR: Blender configuration error"))
        print(f"  {e}")
        return 1

    if not blender_info:
        # Handle based on configuration
        if config.pre_commit.no_blender == "error":
            # Check if SKIP_BLEND_SCAN environment variable is set
            if os.environ.get("SKIP_BLEND_SCAN") == "1":
                print(Colors.yellow("[pre-commit] WARNING: Blender not found, scan skipped"))
                return 0
            print(Colors.red("[pre-commit] ERROR: Blender not found"))
            print("  Install Blender or set SKIP_BLEND_SCAN=1 to skip")
            return 1
        elif config.pre_commit.no_blender == "skip":
            print("[pre-commit] Blender not found, skipping scan")
            return 0
        else:  # "warn"
            print(Colors.yellow("[pre-commit] WARNING: Blender not found"))
            print("  Install Blender locally for pre-commit scanning")
            return 0

    # Print Blender info
    version_str = blender_info.version_name
    if blender_info.version_number:
        version_str += f" ({blender_info.version_number})"
    print(f"[pre-commit] Using Blender: {version_str}")
    print()

    # Create scanner
    scanners = get_scanners(config.pre_commit.scanners)
    scanner = BlendScanner(
        blender_path=blender_info.path,
        scanners=scanners,
        disable_addons=True,
    )

    # Scan files
    total_errors = 0
    total_warnings = 0

    for blend_file in blend_files:
        if not blend_file.exists():
            print(Colors.yellow(f"  ? {blend_file} - File not found (skipped)"))
            continue

        result = scanner.scan(blend_file)
        has_errors = print_file_result(blend_file, result)

        if has_errors:
            total_errors += len(result.findings_by_severity(Severity.ERROR))
        total_warnings += len(result.findings_by_severity(Severity.WARNING))

    # Summary
    print()
    if total_errors > 0:
        print(
            Colors.red(
                f"[pre-commit] Scan failed: {total_errors} error(s), "
                f"{total_warnings} warning(s)"
            )
        )
        return 1
    elif total_warnings > 0:
        print(
            Colors.yellow(
                f"[pre-commit] Scan complete: {total_warnings} warning(s)"
            )
        )
        return 0
    else:
        print(Colors.green("[pre-commit] Scan complete: No issues found"))
        return 0


if __name__ == "__main__":
    sys.exit(main())
