# tests/test_summary.py
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.summary import generate_basic_report, format_security_report, enhance_report_with_llm

class TestSummary(unittest.TestCase):
    
    def setUp(self):
        """Set up test data."""
        # Sample vulnerability data
        self.vuln = {
            "cve_id": "CVE-2023-12345",
            "summary": "Test vulnerability",
            "base_score": 7.5,
            "severity": "High",
            "fixed_versions": ["2.0.1"],
            "references": ["https://example.com/vuln1"]
        }
        
        # Sample scan result for a vulnerable package
        self.vulnerable_result = {
            "package": "test-package",
            "version": "1.0.0",
            "vulnerabilities": [self.vuln],
            "name_similarity": {
                "potential_typosquatting": False,
                "similar_packages": [],
                "risk_level": "Low"
            },
            "reputation": {
                "risk_level": "Low",
                "package_age": "2 years (Established)",
                "download_count": 50000
            }
        }
        
        # Sample scan result for a safe package
        self.safe_result = {
            "package": "safe-package",
            "version": "1.0.0",
            "vulnerabilities": [],
            "name_similarity": {
                "potential_typosquatting": False,
                "similar_packages": [],
                "risk_level": "Low"
            },
            "reputation": {
                "risk_level": "Low",
                "package_age": "3 years (Mature)",
                "download_count": 100000
            }
        }
        
        # Sample result with typosquatting concern
        self.typo_result = {
            "package": "reqeusts",
            "version": "1.0.0",
            "vulnerabilities": [],
            "name_similarity": {
                "potential_typosquatting": True,
                "similar_packages": [{"similar_to": "requests", "similarity_score": 0.9, "risk_level": "High"}],
                "risk_level": "High"
            },
            "reputation": {
                "risk_level": "High",
                "suspicious_patterns": ["Very new package (less than 30 days old)"],
                "package_age": "5 days (Very New)",
                "download_count": 100
            }
        }
        
        # Mock LLM model
        self.mock_model = MagicMock()
        self.mock_model.return_value = [{"generated_text": "Enhanced security report"}]
    
    def test_generate_basic_report_with_vulnerable_package(self):
        """Test basic report generation for a vulnerable package."""
        report = generate_basic_report([self.vulnerable_result])
        
        # Check that the report contains expected information
        self.assertIn("Security Analysis: test-package", report)
        self.assertIn("HIGH SECURITY ISSUES FOUND", report)
        self.assertIn("CVE-2023-12345", report)
        self.assertIn("Fixed in versions: 2.0.1", report)
        self.assertIn("pip install test-package>=2.0.1", report)
    
    def test_generate_basic_report_with_safe_package(self):
        """Test basic report generation for a safe package."""
        report = generate_basic_report([self.safe_result])
        
        # Check that the report contains expected information
        self.assertIn("Security Analysis: safe-package", report)
        self.assertIn("No known vulnerabilities found", report)
        self.assertNotIn("SECURITY ISSUES FOUND", report)
    
    def test_generate_basic_report_with_typosquatting(self):
        """Test basic report generation for a package with typosquatting concerns."""
        report = generate_basic_report([self.typo_result])
        
        # Check that the report contains expected information
        self.assertIn("Security Analysis: reqeusts", report)
        self.assertIn("Typosquatting Concerns", report)
        self.assertIn("Similar to: requests", report)
        self.assertIn("Package Reputation Concerns", report)
        self.assertIn("Very new package", report)
    
    def test_format_security_report_without_model(self):
        """Test security report formatting without a model."""
        report = format_security_report([self.vulnerable_result], model=None)
        
        # Should be identical to the basic report
        basic_report = generate_basic_report([self.vulnerable_result])
        self.assertEqual(report, basic_report)
    
    def test_format_security_report_with_model(self):
        """Test security report formatting with a model."""
        report = format_security_report([self.vulnerable_result], model=self.mock_model)
        
        # Should return the enhanced report from the model
        self.assertEqual(report, "Enhanced security report")
        
        # Verify the model was called once
        self.mock_model.assert_called_once()
    
    @patch('tools.summary.enhance_report_with_llm')
    def test_format_security_report_with_model_error(self, mock_enhance):
        """Test error handling when LLM enhancement fails."""
        # Set up the mock to raise an exception
        mock_enhance.side_effect = Exception("LLM error")
        
        # Should fall back to the basic report
        report = format_security_report([self.vulnerable_result], model=self.mock_model)
        basic_report = generate_basic_report([self.vulnerable_result])
        self.assertEqual(report, basic_report)
    
    def test_enhance_report_with_llm(self):
        """Test report enhancement with LLM."""
        basic_report = "Basic security report"
        enhanced_report = enhance_report_with_llm(basic_report, [self.vulnerable_result], self.mock_model)
        
        # Should return the enhanced report
        self.assertEqual(enhanced_report, "Enhanced security report")
        
        # Verify the model was called with appropriate context
        call_args = self.mock_model.call_args[0][0]
        self.assertIn("Basic security report", call_args)
        self.assertIn("Vulnerable packages: test-package==1.0.0", call_args)
        self.assertIn("CVE-2023-12345", call_args)

if __name__ == '__main__':
    unittest.main()