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
