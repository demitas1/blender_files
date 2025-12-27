"""Tests for blend_scanner.scanners.privacy module."""

import pytest

from blend_scanner.models import Severity
from blend_scanner.scanners.privacy import PrivacyScanner


class TestPrivacyScannerProperties:
    """Tests for PrivacyScanner properties."""

    def test_scanner_name(self, privacy_scanner):
        """Test scanner name property."""
        assert privacy_scanner.name == "privacy"

    def test_scanner_description(self, privacy_scanner):
        """Test scanner description property."""
        assert "personal information" in privacy_scanner.description.lower()


class TestPrivacyScannerErrorPatterns:
    """Tests for ERROR level pattern detection."""

    @pytest.mark.parametrize(
        "code,description",
        [
            ('OPENAI_KEY = "sk-abc123def456ghi789jkl012mno345pqr"', "OpenAI API key"),
            ('TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"', "GitHub PAT"),
            ('TOKEN = "gho_abcdefghijklmnopqrstuvwxyz1234567890"', "GitHub OAuth"),
            ('TOKEN = "ghu_abcdefghijklmnopqrstuvwxyz1234567890"', "GitHub U2S"),
            ('TOKEN = "ghs_abcdefghijklmnopqrstuvwxyz1234567890"', "GitHub S2S"),
            ('TOKEN = "ghr_abcdefghijklmnopqrstuvwxyz1234567890"', "GitHub Refresh"),
            ('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', "AWS Access Key"),
            ('SLACK = "xoxb-123456789-abcdefghij"', "Slack Token"),
        ],
    )
    def test_api_key_detection(self, privacy_scanner, code, description):
        """Test API key detection."""
        findings = privacy_scanner.scan(code, "test.py")
        assert len(findings) >= 1
        assert any(f.severity == Severity.ERROR for f in findings)

    def test_openai_key_masked(self, privacy_scanner):
        """Test that OpenAI API key is masked in output."""
        code = 'KEY = "sk-abc123def456ghi789jkl012mno345pqr"'
        findings = privacy_scanner.scan(code, "test.py")
        assert len(findings) >= 1
        error_finding = next(f for f in findings if f.severity == Severity.ERROR)
        assert "sk-****" in error_finding.matched_text
        assert "abc123" not in error_finding.matched_text

    def test_github_token_masked(self, privacy_scanner):
        """Test that GitHub token is masked in output."""
        code = 'TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = privacy_scanner.scan(code, "test.py")
        error_findings = [f for f in findings if f.severity == Severity.ERROR]
        assert len(error_findings) >= 1
        assert "ghp_****" in error_findings[0].matched_text

    def test_password_detection(self, privacy_scanner):
        """Test hardcoded password detection."""
        passwords = [
            'password = "secret123"',
            'passwd = "mypass"',
            'pwd = "p@ssw0rd"',
            "PASSWORD = 'admin'",
        ]
        for code in passwords:
            findings = privacy_scanner.scan(code, "test.py")
            assert len(findings) >= 1
            assert any(
                f.severity == Severity.ERROR and "password" in f.message.lower()
                for f in findings
            )

    def test_password_masked(self, privacy_scanner):
        """Test that password is masked in output."""
        code = 'password = "supersecret"'
        findings = privacy_scanner.scan(code, "test.py")
        error_findings = [f for f in findings if f.severity == Severity.ERROR]
        assert len(error_findings) >= 1
        assert "supersecret" not in error_findings[0].matched_text
        assert "****" in error_findings[0].matched_text

    def test_database_connection_string(self, privacy_scanner):
        """Test database connection string detection."""
        conn_strings = [
            'DB_URL = "mysql://user:pass@localhost/db"',
            'DB_URL = "postgres://admin:secret@host:5432/mydb"',
            'DB_URL = "postgresql://user@localhost/test"',
            'MONGO = "mongodb://user:pass@cluster.mongodb.net/db"',
            'REDIS = "redis://default:password@localhost:6379"',
        ]
        for code in conn_strings:
            findings = privacy_scanner.scan(code, "test.py")
            assert len(findings) >= 1
            assert any(
                f.severity == Severity.ERROR and "connection string" in f.message.lower()
                for f in findings
            )

    def test_private_key_detection(self, privacy_scanner):
        """Test private key detection."""
        private_keys = [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ]
        for code in private_keys:
            findings = privacy_scanner.scan(code, "test.py")
            assert len(findings) >= 1
            assert any(
                f.severity == Severity.ERROR and "private key" in f.message.lower()
                for f in findings
            )


class TestPrivacyScannerWarningPatterns:
    """Tests for WARNING level pattern detection."""

    def test_linux_home_path_detection(self, privacy_scanner):
        """Test Linux home path detection."""
        code = 'path = "/home/username/documents/file.txt"'
        findings = privacy_scanner.scan(code, "test.py")
        assert len(findings) >= 1
        warning_findings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warning_findings) >= 1
        assert any("Linux user home path" in f.message for f in warning_findings)

    def test_windows_path_detection(self, privacy_scanner):
        """Test Windows user path detection."""
        windows_paths = [
            r'path = "C:\\Users\\john\\Documents\\file.txt"',
            r"path = 'C:\\Users\\admin\\Desktop'",
        ]
        for code in windows_paths:
            findings = privacy_scanner.scan(code, "test.py")
            warning_findings = [f for f in findings if f.severity == Severity.WARNING]
            assert len(warning_findings) >= 1
            assert any("Windows user path" in f.message for f in warning_findings)

    def test_email_detection(self, privacy_scanner):
        """Test email address detection."""
        code = 'contact = "user@example.com"'
        findings = privacy_scanner.scan(code, "test.py")
        warning_findings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warning_findings) >= 1
        assert any("Email address" in f.message for f in warning_findings)

    def test_api_key_variable_detection(self, privacy_scanner):
        """Test generic API key variable detection."""
        codes = [
            'api_key = "some_value"',
            'apikey = "abc123"',
            'API-KEY = "xyz789"',
        ]
        for code in codes:
            findings = privacy_scanner.scan(code, "test.py")
            warning_findings = [f for f in findings if f.severity == Severity.WARNING]
            assert len(warning_findings) >= 1

    def test_secret_token_variable_detection(self, privacy_scanner):
        """Test secret/token variable detection."""
        codes = [
            'secret = "mysecret"',
            'token = "mytoken"',
            'SECRET = "value"',
            'TOKEN = "value"',
        ]
        for code in codes:
            findings = privacy_scanner.scan(code, "test.py")
            warning_findings = [f for f in findings if f.severity == Severity.WARNING]
            assert len(warning_findings) >= 1

    def test_authorization_header_detection(self, privacy_scanner):
        """Test authorization header detection."""
        codes = [
            'auth = "Bearer token123"',
            'authorization = "Basic base64string"',
            'AUTH = "api-key-here"',
        ]
        for code in codes:
            findings = privacy_scanner.scan(code, "test.py")
            warning_findings = [f for f in findings if f.severity == Severity.WARNING]
            assert len(warning_findings) >= 1


class TestPrivacyScannerInfoPatterns:
    """Tests for INFO level pattern detection."""

    def test_public_ip_detection(self, privacy_scanner):
        """Test public IP address detection."""
        code = 'server = "8.8.8.8"'
        findings = privacy_scanner.scan(code, "test.py")
        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert len(info_findings) >= 1
        assert any("IP address" in f.message for f in info_findings)

    def test_private_ip_not_detected(self, privacy_scanner):
        """Test that private IP addresses are not flagged."""
        private_ips = [
            'server = "192.168.1.1"',
            'server = "10.0.0.1"',
            'server = "172.16.0.1"',
            'server = "127.0.0.1"',
        ]
        for code in private_ips:
            findings = privacy_scanner.scan(code, "test.py")
            ip_findings = [f for f in findings if "IP address" in f.message]
            assert len(ip_findings) == 0


class TestPrivacyScannerSafeCode:
    """Tests for safe code (no findings)."""

    def test_safe_code_no_findings(self, privacy_scanner, safe_code):
        """Test that safe code produces no findings."""
        findings = privacy_scanner.scan(safe_code, "safe.py")
        assert len(findings) == 0

    def test_variable_names_not_flagged(self, privacy_scanner):
        """Test that variable names similar to patterns are not flagged."""
        safe_codes = [
            "password_length = 12",  # Not a password value
            "use_email = True",  # Not an email
            "socket_timeout = 30",  # socket is different from socket.
        ]
        for code in safe_codes:
            findings = privacy_scanner.scan(code, "test.py")
            # Should not have ERROR level findings
            error_findings = [f for f in findings if f.severity == Severity.ERROR]
            assert len(error_findings) == 0


class TestPrivacyScannerMultiline:
    """Tests for multiline code scanning."""

    def test_multiline_code(self, privacy_scanner, privacy_leak_code):
        """Test scanning multiline code with multiple issues."""
        findings = privacy_scanner.scan(privacy_leak_code, "leaky.py")

        error_findings = [f for f in findings if f.severity == Severity.ERROR]
        warning_findings = [f for f in findings if f.severity == Severity.WARNING]

        # Should detect API keys and passwords as errors
        assert len(error_findings) >= 5  # OpenAI, GitHub, AWS, Slack, password, db_url

        # Should detect paths and email as warnings
        assert len(warning_findings) >= 2  # home path, email

    def test_line_numbers_correct(self, privacy_scanner):
        """Test that line numbers are correctly reported."""
        code = """line 1
line 2
password = "secret"
line 4"""
        findings = privacy_scanner.scan(code, "test.py")
        error_findings = [f for f in findings if f.severity == Severity.ERROR]
        assert len(error_findings) >= 1
        assert error_findings[0].location == "test.py:3"


class TestPrivacyScannerMasking:
    """Tests for sensitive data masking."""

    def test_aws_key_masked(self, privacy_scanner):
        """Test AWS key masking."""
        code = 'AWS = "AKIAIOSFODNN7EXAMPLE"'
        findings = privacy_scanner.scan(code, "test.py")
        error_findings = [f for f in findings if f.severity == Severity.ERROR]
        assert len(error_findings) >= 1
        assert "AKIA****" in error_findings[0].matched_text

    def test_slack_token_masked(self, privacy_scanner):
        """Test Slack token masking."""
        code = 'SLACK = "xoxb-123456789-abcdefghij"'
        findings = privacy_scanner.scan(code, "test.py")
        error_findings = [f for f in findings if f.severity == Severity.ERROR]
        assert len(error_findings) >= 1
        assert "xoxb-****" in error_findings[0].matched_text


class TestPrivacyScannerScanMultiple:
    """Tests for scan_multiple method."""

    def test_scan_multiple_contents(self, privacy_scanner):
        """Test scanning multiple content blocks."""
        contents = {
            "config.py": 'API_KEY = "sk-abc123def456ghi789jkl012mno"',
            "safe.py": "x = 42",
            "paths.py": 'path = "/home/user/file"',
        }
        findings = privacy_scanner.scan_multiple(contents)

        config_findings = [f for f in findings if "config.py" in f.location]
        paths_findings = [f for f in findings if "paths.py" in f.location]

        assert len(config_findings) >= 1
        assert len(paths_findings) >= 1

    def test_scan_multiple_empty(self, privacy_scanner):
        """Test scanning empty contents."""
        findings = privacy_scanner.scan_multiple({})
        assert len(findings) == 0
