#!/usr/bin/env python3
"""
Extract scripts from Blender files and run security scans

Usage:
    python scripts/extract_and_scan.py <blend_file>
    python scripts/extract_and_scan.py <blend_file> --blender-version blender-5
    python scripts/extract_and_scan.py <blend_file> --verbose

Environment variables:
    BLENDER_BASE_DIR  - Blender installation directory (default: $HOME/Application/blender)
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


# Colored output
class Colors:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"  # No Color


# Dangerous patterns (error level)
DANGEROUS_PATTERNS = re.compile(
    r"(os\.system|os\.popen|subprocess|exec\(|socket\.|requests\.|urllib\.|shutil\.rmtree|__import__)"
)

# Warning patterns (warning level)
WARNING_PATTERNS = re.compile(r"eval\(")


@dataclass
class ScanResult:
    """Scan result"""

    text_blocks: dict[str, str]  # {name: content}
    driver_expressions: list[str]
    dangerous_matches: list[tuple[str, int, str]]  # (block_name, line_no, line)
    warning_matches: list[tuple[str, int, str]]  # (block_name, line_no, line)
    bandit_output: str | None = None


def get_blender_path(version: str, base_dir: str | None = None) -> Path:
    """Get Blender executable path"""
    if base_dir is None:
        base_dir = os.environ.get(
            "BLENDER_BASE_DIR", os.path.expanduser("~/Application/blender")
        )
    blender_path = Path(base_dir) / version
    if not blender_path.exists():
        raise FileNotFoundError(f"Blender not found: {blender_path}")
    return blender_path


def list_blender_versions(base_dir: str | None = None) -> list[str]:
    """List available Blender versions"""
    if base_dir is None:
        base_dir = os.environ.get(
            "BLENDER_BASE_DIR", os.path.expanduser("~/Application/blender")
        )
    base_path = Path(base_dir)
    if not base_path.exists():
        return []
    return sorted([d.name for d in base_path.iterdir() if d.name.startswith("blender-")])


def extract_scripts(blend_file: Path, blender_path: Path, disable_addons: bool = True) -> str:
    """Extract scripts using Blender"""
    script_dir = Path(__file__).parent
    extract_script = script_dir / "extract_scripts.py"

    cmd = [str(blender_path), "--background"]
    if disable_addons:
        cmd.append("--factory-startup")
    cmd.extend([str(blend_file), "--python", str(extract_script)])

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout + result.stderr


def parse_extracted_output(output: str) -> ScanResult:
    """Parse extracted output"""
    text_blocks: dict[str, str] = {}
    driver_expressions: list[str] = []
    current_block: str | None = None
    current_content: list[str] = []

    for line in output.split("\n"):
        # Text Block start
        match = re.match(r"^=== Text Block: (.+) ===$", line)
        if match:
            if current_block:
                text_blocks[current_block] = "\n".join(current_content)
            current_block = match.group(1)
            current_content = []
            continue

        # Driver Expressions
        if line.startswith("=== Driver Expressions ==="):
            if current_block:
                text_blocks[current_block] = "\n".join(current_content)
                current_block = None
            continue

        # Section end
        if line.startswith("===") and line.endswith("==="):
            if current_block:
                text_blocks[current_block] = "\n".join(current_content)
                current_block = None
            continue

        # Driver expression
        if "Expression:" in line:
            driver_expressions.append(line)
            continue

        # Collect content
        if current_block:
            current_content.append(line)

    # Last block
    if current_block:
        text_blocks[current_block] = "\n".join(current_content)

    # Pattern matching
    dangerous_matches: list[tuple[str, int, str]] = []
    warning_matches: list[tuple[str, int, str]] = []

    for block_name, content in text_blocks.items():
        for line_no, line in enumerate(content.split("\n"), 1):
            if DANGEROUS_PATTERNS.search(line):
                dangerous_matches.append((block_name, line_no, line.strip()))
            if WARNING_PATTERNS.search(line):
                warning_matches.append((block_name, line_no, line.strip()))

    return ScanResult(
        text_blocks=text_blocks,
        driver_expressions=driver_expressions,
        dangerous_matches=dangerous_matches,
        warning_matches=warning_matches,
    )


def run_bandit(text_blocks: dict[str, str], temp_dir: Path) -> str | None:
    """Run bandit"""
    if not shutil.which("bandit"):
        return None

    bandit_dir = temp_dir / "bandit_files"
    bandit_dir.mkdir(exist_ok=True)

    # Save each Text Block to individual files
    for name, content in text_blocks.items():
        safe_name = name.replace("/", "__").replace(":", "__")
        if not safe_name.endswith(".py"):
            safe_name += ".py"
        file_path = bandit_dir / safe_name
        file_path.write_text(f"# Source: {name}\n{content}")

    # Run bandit
    result = subprocess.run(
        ["bandit", "-r", str(bandit_dir)],
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


def print_results(result: ScanResult, verbose: bool = False) -> int:
    """Print results and return exit code"""
    print("=" * 50)
    print("Blender Script Security Scanner")
    print("=" * 50)
    print()

    # Summary of extracted scripts
    print(f"{Colors.CYAN}[Detected Text Blocks]{Colors.NC}")
    for name in result.text_blocks.keys():
        print(f"  - {name}")
    print()

    if verbose:
        print(f"{Colors.CYAN}[Extracted Scripts]{Colors.NC}")
        print("-" * 50)
        for name, content in result.text_blocks.items():
            print(f"=== {name} ===")
            print(content)
            print()
        print("-" * 50)
        print()

    # Dangerous patterns (error level)
    has_danger = len(result.dangerous_matches) > 0
    has_warning = len(result.warning_matches) > 0

    if has_danger:
        print(f"{Colors.RED}[Error] Dangerous patterns detected!{Colors.NC}")
        print()
        for block_name, line_no, line in result.dangerous_matches:
            print(f"  {block_name}:{line_no}: {line}")
        print()

    # Warning patterns
    if has_warning:
        print(f"{Colors.YELLOW}[Warning] Patterns requiring attention detected{Colors.NC}")
        print("(May be used in legitimate scripts like Rigify)")
        print()
        for block_name, line_no, line in result.warning_matches:
            print(f"  {block_name}:{line_no}: {line}")
        print()

    # bandit results
    if result.bandit_output:
        print(f"{Colors.CYAN}[bandit Security Scan]{Colors.NC}")
        print(result.bandit_output)
    elif shutil.which("bandit") is None:
        print(f"{Colors.YELLOW}Note: bandit is not installed{Colors.NC}")
        print("Install: pip install bandit")
        print()

    # Result summary
    print("=" * 50)
    if has_danger:
        print(f"{Colors.RED}Scan complete: Dangerous patterns detected{Colors.NC}")
        return 1
    elif has_warning:
        print(f"{Colors.YELLOW}Scan complete: Warnings found (review recommended){Colors.NC}")
        return 0
    else:
        print(f"{Colors.GREEN}Scan complete: No issues found{Colors.NC}")
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Extract scripts from Blender files and run security scans"
    )
    parser.add_argument("blend_file", type=Path, help="Target .blend file to scan")
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

    args = parser.parse_args()

    # List versions
    if args.list_versions:
        versions = list_blender_versions()
        if versions:
            print("Available Blender versions:")
            for v in versions:
                print(f"  {v}")
        else:
            print("Blender not found")
        return 0

    # Check file exists
    if not args.blend_file.exists():
        print(f"{Colors.RED}Error: File not found: {args.blend_file}{Colors.NC}")
        return 1

    # Get Blender path
    try:
        blender_path = get_blender_path(args.blender_version)
    except FileNotFoundError as e:
        print(f"{Colors.RED}Error: {e}{Colors.NC}")
        versions = list_blender_versions()
        if versions:
            print(f"Available versions: {', '.join(versions)}")
        return 1

    print(f"Target file: {args.blend_file}")
    print(f"Blender version: {args.blender_version}")
    if not args.with_addons:
        print("(Addons disabled)")
    print()

    # Extract scripts
    print(f"{Colors.YELLOW}Extracting scripts...{Colors.NC}")
    output = extract_scripts(
        args.blend_file,
        blender_path,
        disable_addons=not args.with_addons,
    )

    # Check extraction success
    if "Extraction Complete" not in output:
        print(f"{Colors.RED}Error: Script extraction failed{Colors.NC}")
        print(output)
        return 1

    print("Extraction complete")
    print()

    # Parse and scan
    result = parse_extracted_output(output)

    # Run bandit
    with tempfile.TemporaryDirectory() as temp_dir:
        result.bandit_output = run_bandit(result.text_blocks, Path(temp_dir))

    # Print results
    return print_results(result, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
