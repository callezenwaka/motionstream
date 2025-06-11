# tests/test_scanner.py - Test version checking and severity logic
import pytest
from src.utils.scanner import is_version_affected, get_severity_from_score

class TestVersionScanner:
    """Test version checking and severity scoring."""
    
    @pytest.mark.parametrize("version,ranges,expected", [
        ("2.25.1", [">=2.25.0", "<2.26.0"], True),
        ("2.24.9", [">=2.25.0", "<2.26.0"], False),
        ("2.26.0", [">=2.25.0", "<2.26.0"], False),
        ("1.0.0", ["==1.0.0"], True),
        ("1.0.1", ["==1.0.0"], False),
        ("2.0.0", [], True),  # Empty ranges should return True
    ])
    def test_is_version_affected(self, version, ranges, expected):
        """Test version range checking."""
        result = is_version_affected(version, ranges)
        assert result == expected
    
    @pytest.mark.parametrize("score,expected", [
        (9.5, "CRITICAL"),
        (9.0, "CRITICAL"),
        (8.5, "HIGH"),
        (7.0, "HIGH"),
        (6.5, "MEDIUM"),
        (4.0, "MEDIUM"),
        (3.5, "LOW"),
        (0.1, "LOW"),
        (0.0, "UNKNOWN"),
        (-1.0, "UNKNOWN"),
    ])
    def test_get_severity_from_score(self, score, expected):
        """Test CVSS score to severity conversion."""
        result = get_severity_from_score(score)
        assert result == expected
    
    def test_invalid_version_handling(self):
        """Test handling of invalid version strings."""
        # Should not crash on invalid versions
        result = is_version_affected("invalid.version", [">=1.0.0"])
        assert isinstance(result, bool)
    
    def test_invalid_score_handling(self):
        """Test handling of invalid severity scores."""
        assert get_severity_from_score("invalid") == "UNKNOWN"
        assert get_severity_from_score(None) == "UNKNOWN"
