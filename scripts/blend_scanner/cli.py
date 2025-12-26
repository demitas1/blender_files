"""Command-line interface for blend_scanner."""

import argparse
import shutil
import sys
from pathlib import Path

from blend_scanner.colors import Colors
from blend_scanner.core import BlendScanner
from blend_scanner.models import ScanResult, Severity
from blend_scanner.scanners.bandit import BanditScanner


def print_results(result: ScanResult, verbose: bool = False) -> int:
    """Print scan results and return exit code."""
    print("=" * 60)
    print("Blender Security Scanner")
    print("=" * 60)
    print()

    # Summary of extracted data
    print(Colors.cyan("[Extracted Data]"))
    print(f"  Text blocks: {len(result.extracted_data.text_blocks)}")
    if result.extracted_data.text_blocks:
        for name in result.extracted_data.text_blocks.keys():
            print(f"    - {name}")
    print(f"  Driver expressions: {len(result.extracted_data.driver_expressions)}")
    print(f"  External references: {len(result.extracted_data.external_refs)}")
    print()

    if verbose:
        print(Colors.cyan("[Extracted Scripts]"))
        print("-" * 50)
        for name, content in result.extracted_data.text_blocks.items():
            print(f"=== {name} ===")
            print(content)
            print()
        print("-" * 50)
        print()

        if result.extracted_data.external_refs:
            print(Colors.cyan("[External References]"))
            for ref in result.extracted_data.external_refs:
                print(f"  {ref}")
            print()

    # Findings by severity
    errors = result.findings_by_severity(Severity.ERROR)
    warnings = result.findings_by_severity(Severity.WARNING)
    infos = result.findings_by_severity(Severity.INFO)

    if errors:
        print(Colors.red(f"[ERROR] {len(errors)} dangerous pattern(s) detected!"))
        print()
        for finding in errors:
            print(f"  [{finding.scanner}] {finding.location}")
            print(f"    {finding.message}")
            print(f"    {finding.matched_text}")
            print()

    if warnings:
        print(Colors.yellow(f"[WARNING] {len(warnings)} pattern(s) requiring review"))
        print()
        for finding in warnings:
            print(f"  [{finding.scanner}] {finding.location}")
            print(f"    {finding.message}")
            print(f"    {finding.matched_text}")
            print()

    if infos and verbose:
        print(Colors.cyan(f"[INFO] {len(infos)} informational finding(s)"))
        print()
        for finding in infos:
            print(f"  [{finding.scanner}] {finding.location}")
            print(f"    {finding.message}")
            print(f"    {finding.matched_text}")
            print()

    # Bandit output
    if result.bandit_output:
        print(Colors.cyan("[Bandit Security Scan]"))
        print(result.bandit_output)
    elif not BanditScanner.is_available():
        print(Colors.yellow("Note: bandit is not installed"))
        print("Install: pip install bandit")
        print()

    # Result summary
    print("=" * 60)
    if errors:
        print(Colors.red(f"Scan complete: {len(errors)} error(s), {len(warnings)} warning(s)"))
        return 1
    elif warnings:
        print(Colors.yellow(f"Scan complete: {len(warnings)} warning(s)"))
        return 0
    else:
        print(Colors.green("Scan complete: No issues found"))
        return 0


def main(args: list[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Security scanner for Blender files",
        prog="scan_blend",
    )
    parser.add_argument(
        "blend_file",
        type=Path,
        nargs="?",
        help="Target .blend file to scan",
    )
    parser.add_argument(
        "--blender-version",
        "-b",
        default="blender-5",
        help="Blender version to use (default: blender-5)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show extracted script contents",
    )
    parser.add_argument(
        "--with-addons",
        action="store_true",
        help="Run with user addons enabled",
    )
    parser.add_argument(
        "--list-versions",
        action="store_true",
        help="List available Blender versions",
    )
    parser.add_argument(
        "--scanners",
        "-s",
        help="Comma-separated list of scanners to use (default: malware,privacy)",
    )

    parsed_args = parser.parse_args(args)

    # List versions
    if parsed_args.list_versions:
        versions = BlendScanner.list_blender_versions()
        if versions:
            print("Available Blender versions:")
            for v in versions:
                print(f"  {v}")
        else:
            print("Blender not found")
        return 0

    # Check file argument
    if not parsed_args.blend_file:
        parser.print_help()
        return 1

    # Check file exists
    if not parsed_args.blend_file.exists():
        print(Colors.red(f"Error: File not found: {parsed_args.blend_file}"))
        return 1

    # Setup scanners
    scanners = None
    if parsed_args.scanners:
        from blend_scanner.scanners.malware import MalwareScanner
        from blend_scanner.scanners.privacy import PrivacyScanner

        scanner_map = {
            "malware": MalwareScanner,
            "privacy": PrivacyScanner,
            "bandit": BanditScanner,
        }
        scanner_names = [s.strip() for s in parsed_args.scanners.split(",")]
        scanners = []
        for name in scanner_names:
            if name in scanner_map:
                scanners.append(scanner_map[name]())
            else:
                print(Colors.yellow(f"Warning: Unknown scanner '{name}'"))

    # Create scanner
    try:
        scanner = BlendScanner(
            blender_version=parsed_args.blender_version,
            scanners=scanners,
            disable_addons=not parsed_args.with_addons,
        )
    except FileNotFoundError as e:
        print(Colors.red(f"Error: {e}"))
        versions = BlendScanner.list_blender_versions()
        if versions:
            print(f"Available versions: {', '.join(versions)}")
        return 1

    print(f"Target file: {parsed_args.blend_file}")
    print(f"Blender version: {parsed_args.blender_version}")
    if not parsed_args.with_addons:
        print("(Addons disabled)")
    print()

    # Run scan
    print(Colors.yellow("Extracting and scanning..."))
    result = scanner.scan(parsed_args.blend_file)

    if not result.extracted_data.text_blocks and not result.extracted_data.external_refs:
        print(Colors.yellow("Warning: No data extracted. Check Blender output."))

    print("Extraction complete")
    print()

    # Print results
    return print_results(result, verbose=parsed_args.verbose)


if __name__ == "__main__":
    sys.exit(main())
