# tests/test_summary.py
import pytest
from tools.summary import generate_basic_report, format_security_report, enhance_report_with_llm

def test_generate_basic_report_with_vulnerable_package(vulnerable_package_result):
    """Test basic report generation for a vulnerable package."""
    report = generate_basic_report([vulnerable_package_result])
    
    # Check that the report contains expected information
    assert "Security Analysis: test-package" in report
    assert "HIGH SECURITY ISSUES FOUND" in report
    assert "CVE-2023-12345" in report
    # Fix: match the actual bold Markdown formatting
    assert "**Fixed in versions**: 2.0.1" in report
    assert "pip install test-package>=2.0.1" in report

def test_generate_basic_report_with_safe_package(safe_package_result):
    """Test basic report generation for a safe package."""
    report = generate_basic_report([safe_package_result])
    
    # Check that the report contains expected information
    assert "Security Analysis: safe-package" in report
    assert "No known vulnerabilities found" in report
    assert "SECURITY ISSUES FOUND" not in report

def test_generate_basic_report_with_typosquatting(typosquatting_package_result):
    """Test basic report generation for a package with typosquatting concerns."""
    report = generate_basic_report([typosquatting_package_result])
    
    # Check that the report contains expected information
    assert "Security Analysis: reqeusts" in report
    assert "Typosquatting Concerns" in report
    assert "Similar to: requests" in report
    assert "Package Reputation Concerns" in report
    assert "Very new package" in report

def test_format_security_report_without_model(vulnerable_package_result):
    """Test security report formatting without a model."""
    report = format_security_report([vulnerable_package_result], model=None)
    
    # Should be identical to the basic report
    basic_report = generate_basic_report([vulnerable_package_result])
    assert report == basic_report

def test_format_security_report_with_model(vulnerable_package_result, mock_model):
    """Test security report formatting with a model."""
    report = format_security_report([vulnerable_package_result], model=mock_model)
    
    # Should return the enhanced report from the model
    assert report == "Enhanced security report by LLM"
    
    # Verify the model was called once
    mock_model.assert_called_once()

def test_format_security_report_with_model_error(vulnerable_package_result, mock_model, mocker):
    """Test error handling when LLM enhancement fails."""
    # Set up the mock to raise an exception
    mock_enhance = mocker.patch('tools.summary.enhance_report_with_llm')
    mock_enhance.side_effect = Exception("LLM error")
    
    # Should fall back to the basic report
    report = format_security_report([vulnerable_package_result], model=mock_model)
    basic_report = generate_basic_report([vulnerable_package_result])
    assert report == basic_report

def test_enhance_report_with_llm(vulnerable_package_result, mock_model):
    """Test report enhancement with LLM."""
    basic_report = "Basic security report"
    enhanced_report = enhance_report_with_llm(basic_report, [vulnerable_package_result], mock_model)
    
    # Should return the enhanced report
    assert enhanced_report == "Enhanced security report by LLM"
    
    # Verify the model was called with appropriate context
    call_args = mock_model.call_args[0][0]
    assert "Basic security report" in call_args
    assert "Vulnerable packages: test-package==1.0.0" in call_args
    assert "CVE-2023-12345" in call_args

def test_generate_basic_report_with_dependency_info(vulnerable_package_result, dependency_result):
    """Test report generation with dependency chain information."""
    # Add dependency results to the package result
    vulnerable_package_result['dependencies'] = dependency_result
    
    report = generate_basic_report([vulnerable_package_result])
    
    # Check that dependency information is included
    assert "Dependency Chain Analysis" in report
    assert "Dependencies" in report
    assert "Vulnerable dependencies:" in report

def test_generate_basic_report_with_multiple_packages(vulnerable_package_result, safe_package_result):
    """Test report generation with multiple packages."""
    report = generate_basic_report([vulnerable_package_result, safe_package_result])
    
    # Check that vulnerable package information is included
    assert "test-package" in report
    
    # Check that the correct formatting is used for counts (with bold)
    assert "Found **1** vulnerabilities in **1** packages" in report
    
    # Note: We're not asserting "safe-package" is in the report because the current
    # implementation only shows details for vulnerable packages. If this changes in
    # the future, this test will need to be updated.