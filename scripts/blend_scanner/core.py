"""Core scanner orchestration module."""

import os
import re
import subprocess
from pathlib import Path

from blend_scanner.models import ExtractedData, Finding, ScanResult, Severity
from blend_scanner.scanners.base import BaseScanner
from blend_scanner.scanners.malware import MalwareScanner
from blend_scanner.scanners.privacy import PrivacyScanner
from blend_scanner.scanners.bandit import BanditScanner


class BlendScanner:
    """Main scanner orchestrator for Blender files."""

    def __init__(
        self,
        blender_path: Path | None = None,
        blender_version: str = "blender-5",
        scanners: list[BaseScanner] | None = None,
        disable_addons: bool = True,
    ):
        """
        Initialize the scanner.

        Args:
            blender_path: Path to Blender executable
            blender_version: Blender version name (e.g., "blender-5")
            scanners: List of scanners to use (default: MalwareScanner, PrivacyScanner)
            disable_addons: Whether to disable addons when running Blender
        """
        self.blender_version = blender_version
        self.blender_path = blender_path or self._get_blender_path(blender_version)
        self.disable_addons = disable_addons

        if scanners is None:
            self.scanners: list[BaseScanner] = [
                MalwareScanner(),
                PrivacyScanner(),
            ]
        else:
            self.scanners = scanners

    def _get_blender_path(self, version: str) -> Path:
        """Get Blender executable path."""
        base_dir = os.environ.get(
            "BLENDER_BASE_DIR", os.path.expanduser("~/Application/blender")
        )
        blender_path = Path(base_dir) / version
        if not blender_path.exists():
            raise FileNotFoundError(f"Blender not found: {blender_path}")
        return blender_path

    @staticmethod
    def list_blender_versions() -> list[str]:
        """List available Blender versions."""
        base_dir = os.environ.get(
            "BLENDER_BASE_DIR", os.path.expanduser("~/Application/blender")
        )
        base_path = Path(base_dir)
        if not base_path.exists():
            return []
        return sorted(
            [d.name for d in base_path.iterdir() if d.name.startswith("blender-")]
        )

    def scan(self, blend_file: Path) -> ScanResult:
        """
        Scan a Blender file for security issues.

        Args:
            blend_file: Path to the .blend file

        Returns:
            ScanResult containing extracted data and findings
        """
        # Extract data from Blender file
        extracted_data = self._extract_data(blend_file)

        # Run scanners on extracted data
        findings = self._run_scanners(extracted_data)

        # Run bandit if available
        bandit_output = None
        if BanditScanner.is_available() and extracted_data.text_blocks:
            bandit = BanditScanner()
            bandit_findings = bandit.scan_multiple(extracted_data.text_blocks)
            findings.extend(bandit_findings)
            bandit_output = bandit.get_raw_output(extracted_data.text_blocks)

        return ScanResult(
            extracted_data=extracted_data,
            findings=findings,
            bandit_output=bandit_output,
        )

    def _extract_data(self, blend_file: Path) -> ExtractedData:
        """Extract data from a Blender file."""
        script_dir = Path(__file__).parent.parent / "blender"
        extract_script = script_dir / "extract_all.py"

        cmd = [str(self.blender_path), "--background"]
        if self.disable_addons:
            cmd.append("--factory-startup")
        cmd.extend([str(blend_file), "--python", str(extract_script)])

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout + result.stderr

        return self._parse_extracted_output(output)

    def _parse_extracted_output(self, output: str) -> ExtractedData:
        """Parse extracted output from Blender script."""
        text_blocks: dict[str, str] = {}
        driver_expressions: list[str] = []
        node_scripts: list[str] = []
        metadata: dict[str, str] = {}
        external_refs: list[str] = []

        current_section: str | None = None
        current_block: str | None = None
        current_content: list[str] = []

        for line in output.split("\n"):
            # Section markers
            if line.startswith("=== Text Block: "):
                if current_block:
                    text_blocks[current_block] = "\n".join(current_content)
                match = re.match(r"^=== Text Block: (.+) ===$", line)
                if match:
                    current_block = match.group(1)
                    current_content = []
                    current_section = "text_block"
                continue

            if line == "=== Driver Expressions ===":
                if current_block:
                    text_blocks[current_block] = "\n".join(current_content)
                    current_block = None
                current_section = "drivers"
                continue

            if line == "=== Node Scripts ===":
                current_section = "nodes"
                continue

            if line == "=== Metadata ===":
                current_section = "metadata"
                continue

            if line == "=== External References ===":
                current_section = "external_refs"
                continue

            if line.startswith("===") and line.endswith("==="):
                if current_block:
                    text_blocks[current_block] = "\n".join(current_content)
                    current_block = None
                current_section = None
                continue

            # Collect content based on section
            if current_section == "text_block" and current_block:
                current_content.append(line)
            elif current_section == "drivers" and "Expression:" in line:
                driver_expressions.append(line)
            elif current_section == "nodes" and line.strip():
                node_scripts.append(line)
            elif current_section == "metadata" and ":" in line:
                key, _, value = line.partition(":")
                metadata[key.strip()] = value.strip()
            elif current_section == "external_refs" and line.strip():
                external_refs.append(line.strip())

        # Save last block
        if current_block:
            text_blocks[current_block] = "\n".join(current_content)

        return ExtractedData(
            text_blocks=text_blocks,
            driver_expressions=driver_expressions,
            node_scripts=node_scripts,
            metadata=metadata,
            external_refs=external_refs,
        )

    def _run_scanners(self, extracted_data: ExtractedData) -> list[Finding]:
        """Run all scanners on extracted data."""
        findings: list[Finding] = []

        for scanner in self.scanners:
            # Scan text blocks
            for name, content in extracted_data.text_blocks.items():
                findings.extend(scanner.scan(content, name))

            # Scan driver expressions
            for expr in extracted_data.driver_expressions:
                findings.extend(scanner.scan(expr, "driver"))

            # Scan external refs (privacy scanner only)
            if isinstance(scanner, PrivacyScanner):
                for ref in extracted_data.external_refs:
                    findings.extend(scanner.scan(ref, "external_ref"))

                # Scan metadata
                for key, value in extracted_data.metadata.items():
                    findings.extend(scanner.scan(value, f"metadata:{key}"))

        return findings
