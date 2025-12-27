"""Pytest configuration and fixtures for blend_scanner tests."""

import pytest
import sys
from pathlib import Path

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(scripts_dir))

from blend_scanner.models import (
    Severity,
    Finding,
    ExtractedData,
    ScanResult,
)
from blend_scanner.scanners.malware import MalwareScanner
from blend_scanner.scanners.privacy import PrivacyScanner
from blend_scanner.scanners.bandit import BanditScanner


@pytest.fixture
def malware_scanner():
    """Create a MalwareScanner instance."""
    return MalwareScanner()


@pytest.fixture
def privacy_scanner():
    """Create a PrivacyScanner instance."""
    return PrivacyScanner()


@pytest.fixture
def bandit_scanner():
    """Create a BanditScanner instance."""
    return BanditScanner()


@pytest.fixture
def sample_extracted_data():
    """Create sample ExtractedData for testing."""
    return ExtractedData(
        text_blocks={
            "script.py": "import os\nprint('hello')\n",
            "init.py": "# initialization\nvalue = 42\n",
        },
        driver_expressions=["frame * 2", "sin(frame)"],
        node_scripts=["node_script_1"],
        metadata={"Blender Version": "4.2.0", "File Path": "/home/user/test.blend"},
        external_refs=["/home/user/textures/image.png"],
    )


@pytest.fixture
def empty_extracted_data():
    """Create empty ExtractedData for testing."""
    return ExtractedData()


@pytest.fixture
def sample_finding():
    """Create a sample Finding for testing."""
    return Finding(
        scanner="test",
        severity=Severity.ERROR,
        message="Test message",
        location="test.py:1",
        matched_text="test code",
    )


@pytest.fixture
def malicious_code():
    """Sample code with malicious patterns."""
    return """
import os
import subprocess

def run_command(cmd):
    os.system(cmd)
    os.popen("ls -la")
    subprocess.call(["rm", "-rf", "/"])
    exec("print('evil')")
    eval("1+1")
    __import__("socket")
"""


@pytest.fixture
def privacy_leak_code():
    """Sample code with privacy issues."""
    return """
# API Keys
OPENAI_KEY = "sk-abc123def456ghi789jkl012mno345pqr"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SLACK_TOKEN = "xoxb-123456789-abcdefghij"

# Passwords
password = "mysecretpassword123"
db_url = "mysql://user:pass@localhost/db"

# Paths
config_path = "/home/username/config.json"
email = "user@example.com"
"""


@pytest.fixture
def safe_code():
    """Sample code without security issues."""
    return """
import math

def calculate_area(radius):
    return math.pi * radius ** 2

def greet(name):
    return f"Hello, {name}!"

if __name__ == "__main__":
    print(greet("World"))
"""


# =============================================================================
# Blend File Fixtures
# =============================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    """Return the fixtures directory path."""
    return FIXTURES_DIR


@pytest.fixture
def clean_blend():
    """Path to a clean blend file with no scripts."""
    return FIXTURES_DIR / "clean.blend"


@pytest.fixture
def with_safe_script_blend():
    """Path to a blend file with safe scripts."""
    return FIXTURES_DIR / "with_safe_script.blend"


@pytest.fixture
def with_malware_patterns_blend():
    """Path to a blend file with malware patterns."""
    return FIXTURES_DIR / "with_malware_patterns.blend"


@pytest.fixture
def with_privacy_issues_blend():
    """Path to a blend file with privacy issues."""
    return FIXTURES_DIR / "with_privacy_issues.blend"


@pytest.fixture
def with_drivers_blend():
    """Path to a blend file with driver expressions."""
    return FIXTURES_DIR / "with_drivers.blend"


@pytest.fixture
def with_external_refs_blend():
    """Path to a blend file with external references."""
    return FIXTURES_DIR / "with_external_refs.blend"


@pytest.fixture
def blend_scanner_36():
    """Create a BlendScanner instance using Blender 3.6 LTS."""
    from blend_scanner.core import BlendScanner

    try:
        return BlendScanner(blender_version="blender-3-LTS")
    except FileNotFoundError:
        pytest.skip("Blender 3.6 LTS not available")
