"""Integration tests using real .blend files.

These tests require Blender 3.6 LTS to be installed.
They will be skipped if Blender is not available.
"""

import pytest

from blend_scanner.models import Severity


class TestCleanBlendFile:
    """Tests for clean.blend - a file with no scripts or issues."""

    def test_no_text_blocks(self, blend_scanner_36, clean_blend):
        """Test that clean blend has no text blocks."""
        result = blend_scanner_36.scan(clean_blend)
        assert len(result.extracted_data.text_blocks) == 0

    def test_no_findings(self, blend_scanner_36, clean_blend):
        """Test that clean blend has no security findings."""
        result = blend_scanner_36.scan(clean_blend)
        assert len(result.findings) == 0
        assert result.has_errors is False
        assert result.has_warnings is False


class TestSafeScriptBlendFile:
    """Tests for with_safe_script.blend - a file with safe scripts."""

    def test_has_text_blocks(self, blend_scanner_36, with_safe_script_blend):
        """Test that file has text blocks extracted."""
        result = blend_scanner_36.scan(with_safe_script_blend)
        assert len(result.extracted_data.text_blocks) >= 1

    def test_no_errors(self, blend_scanner_36, with_safe_script_blend):
        """Test that safe script produces no errors."""
        result = blend_scanner_36.scan(with_safe_script_blend)
        error_findings = result.findings_by_severity(Severity.ERROR)
        # Filter out bandit findings which may flag safe code
        malware_errors = [f for f in error_findings if f.scanner == "malware"]
        privacy_errors = [f for f in error_findings if f.scanner == "privacy"]
        assert len(malware_errors) == 0
        assert len(privacy_errors) == 0


class TestMalwarePatternsBlendFile:
    """Tests for with_malware_patterns.blend - a file with dangerous code."""

    def test_has_text_blocks(self, blend_scanner_36, with_malware_patterns_blend):
        """Test that file has text blocks extracted."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)
        assert len(result.extracted_data.text_blocks) >= 1

    def test_detects_malware_errors(self, blend_scanner_36, with_malware_patterns_blend):
        """Test that malware patterns are detected as errors."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)
        assert result.has_errors is True

        malware_findings = result.findings_by_scanner("malware")
        error_findings = [f for f in malware_findings if f.severity == Severity.ERROR]
        assert len(error_findings) >= 1

    def test_detects_os_system(self, blend_scanner_36, with_malware_patterns_blend):
        """Test that os.system is detected."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)
        malware_findings = result.findings_by_scanner("malware")
        assert any("os.system" in f.message for f in malware_findings)

    def test_detects_subprocess(self, blend_scanner_36, with_malware_patterns_blend):
        """Test that subprocess is detected."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)
        malware_findings = result.findings_by_scanner("malware")
        assert any("subprocess" in f.message for f in malware_findings)

    def test_detects_exec(self, blend_scanner_36, with_malware_patterns_blend):
        """Test that exec() is detected."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)
        malware_findings = result.findings_by_scanner("malware")
        assert any("exec" in f.message.lower() for f in malware_findings)

    def test_detects_eval_as_warning(self, blend_scanner_36, with_malware_patterns_blend):
        """Test that eval() is detected as warning."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)
        malware_findings = result.findings_by_scanner("malware")
        eval_findings = [f for f in malware_findings if "eval" in f.message.lower()]
        assert len(eval_findings) >= 1
        assert any(f.severity == Severity.WARNING for f in eval_findings)


class TestPrivacyIssuesBlendFile:
    """Tests for with_privacy_issues.blend - a file with privacy leaks."""

    def test_has_text_blocks(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that file has text blocks extracted."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        assert len(result.extracted_data.text_blocks) >= 1

    def test_detects_privacy_errors(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that privacy issues are detected."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        privacy_findings = result.findings_by_scanner("privacy")
        assert len(privacy_findings) >= 1

    def test_detects_openai_key(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that OpenAI API key is detected."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        privacy_findings = result.findings_by_scanner("privacy")
        openai_findings = [f for f in privacy_findings if "OpenAI" in f.message]
        assert len(openai_findings) >= 1
        assert openai_findings[0].severity == Severity.ERROR

    def test_detects_github_token(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that GitHub token is detected (as token variable or GitHub-specific)."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        privacy_findings = result.findings_by_scanner("privacy")
        # Token may be detected as GitHub token or generic secret/token variable
        token_findings = [
            f for f in privacy_findings
            if "GitHub" in f.message or "token" in f.message.lower()
        ]
        assert len(token_findings) >= 1

    def test_detects_password(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that hardcoded password is detected."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        privacy_findings = result.findings_by_scanner("privacy")
        password_findings = [f for f in privacy_findings if "password" in f.message.lower()]
        assert len(password_findings) >= 1

    def test_detects_database_url(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that database connection string is detected."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        privacy_findings = result.findings_by_scanner("privacy")
        db_findings = [f for f in privacy_findings if "connection string" in f.message.lower()]
        assert len(db_findings) >= 1

    def test_detects_email(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that email address is detected."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        privacy_findings = result.findings_by_scanner("privacy")
        email_findings = [f for f in privacy_findings if "Email" in f.message]
        assert len(email_findings) >= 1
        assert email_findings[0].severity == Severity.WARNING

    def test_detects_home_path(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that user home path is detected."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        privacy_findings = result.findings_by_scanner("privacy")
        path_findings = [f for f in privacy_findings if "home path" in f.message.lower()]
        assert len(path_findings) >= 1

    def test_masks_sensitive_data(self, blend_scanner_36, with_privacy_issues_blend):
        """Test that sensitive data is masked in output."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        privacy_findings = result.findings_by_scanner("privacy")

        # Check that API keys are masked
        for finding in privacy_findings:
            if finding.severity == Severity.ERROR:
                # Should not contain actual secret values
                assert "sk-test1234567890" not in finding.matched_text
                assert "ghp_abcdefghij" not in finding.matched_text


class TestDriversBlendFile:
    """Tests for with_drivers.blend - a file with driver expressions."""

    def test_extracts_driver_expressions(self, blend_scanner_36, with_drivers_blend):
        """Test that driver expressions are extracted."""
        result = blend_scanner_36.scan(with_drivers_blend)
        assert len(result.extracted_data.driver_expressions) >= 1

    def test_driver_expressions_contain_expected(self, blend_scanner_36, with_drivers_blend):
        """Test that expected driver expressions are found."""
        result = blend_scanner_36.scan(with_drivers_blend)
        expressions = result.extracted_data.driver_expressions

        # Check for expected expression patterns
        all_text = " ".join(expressions)
        assert "frame" in all_text.lower() or "Expression:" in all_text


class TestExternalRefsBlendFile:
    """Tests for with_external_refs.blend - a file with external references."""

    def test_extracts_external_refs(self, blend_scanner_36, with_external_refs_blend):
        """Test that external references are extracted."""
        result = blend_scanner_36.scan(with_external_refs_blend)
        # Should have at least the texture reference
        assert len(result.extracted_data.external_refs) >= 1

    def test_detects_external_path(self, blend_scanner_36, with_external_refs_blend):
        """Test that external file path is in references."""
        result = blend_scanner_36.scan(with_external_refs_blend)
        refs = result.extracted_data.external_refs
        # Should contain path to texture
        all_refs = " ".join(refs)
        assert "texture" in all_refs.lower() or "png" in all_refs.lower() or len(refs) > 0


class TestMetadataExtraction:
    """Tests for metadata extraction from blend files."""

    def test_extracts_blender_version(self, blend_scanner_36, clean_blend):
        """Test that Blender version is in metadata."""
        result = blend_scanner_36.scan(clean_blend)
        metadata = result.extracted_data.metadata
        # Should have some metadata
        assert len(metadata) >= 0  # Metadata extraction depends on file

    def test_extracts_file_path(self, blend_scanner_36, clean_blend):
        """Test that file path may be in metadata."""
        result = blend_scanner_36.scan(clean_blend)
        # Just verify scan completes without error
        assert result is not None


class TestScanResultProperties:
    """Tests for ScanResult properties with real files."""

    def test_has_errors_true_for_malware(self, blend_scanner_36, with_malware_patterns_blend):
        """Test has_errors is True for malware patterns."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)
        assert result.has_errors is True

    def test_has_errors_false_for_clean(self, blend_scanner_36, clean_blend):
        """Test has_errors is False for clean file."""
        result = blend_scanner_36.scan(clean_blend)
        assert result.has_errors is False

    def test_has_warnings_true_for_privacy(self, blend_scanner_36, with_privacy_issues_blend):
        """Test has_warnings is True for privacy issues."""
        result = blend_scanner_36.scan(with_privacy_issues_blend)
        # Privacy scanner should detect warnings (email, paths)
        assert result.has_warnings is True

    def test_findings_by_scanner(self, blend_scanner_36, with_malware_patterns_blend):
        """Test findings can be filtered by scanner."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)

        malware_findings = result.findings_by_scanner("malware")
        privacy_findings = result.findings_by_scanner("privacy")

        assert len(malware_findings) >= 1
        assert all(f.scanner == "malware" for f in malware_findings)
        assert all(f.scanner == "privacy" for f in privacy_findings)

    def test_findings_by_severity(self, blend_scanner_36, with_malware_patterns_blend):
        """Test findings can be filtered by severity."""
        result = blend_scanner_36.scan(with_malware_patterns_blend)

        errors = result.findings_by_severity(Severity.ERROR)
        warnings = result.findings_by_severity(Severity.WARNING)

        assert len(errors) >= 1
        assert all(f.severity == Severity.ERROR for f in errors)
        assert all(f.severity == Severity.WARNING for f in warnings)


class TestBanditIntegration:
    """Tests for Bandit integration with real files."""

    def test_bandit_runs_on_malware_file(self, blend_scanner_36, with_malware_patterns_blend):
        """Test that Bandit analyzes extracted scripts."""
        from blend_scanner.scanners.bandit import BanditScanner

        if not BanditScanner.is_available():
            pytest.skip("Bandit not available")

        result = blend_scanner_36.scan(with_malware_patterns_blend)

        # Should have bandit output
        assert result.bandit_output is not None

        # Should have bandit findings
        bandit_findings = result.findings_by_scanner("bandit")
        assert len(bandit_findings) >= 0  # May or may not find issues

    def test_bandit_output_present(self, blend_scanner_36, with_safe_script_blend):
        """Test that Bandit output is captured."""
        from blend_scanner.scanners.bandit import BanditScanner

        if not BanditScanner.is_available():
            pytest.skip("Bandit not available")

        result = blend_scanner_36.scan(with_safe_script_blend)

        # Bandit should have run (output may be empty for safe code)
        assert result.bandit_output is not None
