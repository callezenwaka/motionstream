# tests/conftest.py
import os
import sys
import pytest
import tempfile
from unittest.mock import MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability data."""
    return {
        "cve_id": "CVE-2023-12345",
        "summary": "Test vulnerability for unit tests",
        "details": "This is a test vulnerability used for unit testing.",
        "base_score": 7.5,
        "severity": "High",
        "fixed_versions": ["2.0.1"],
        "references": ["https://example.com/vuln1", "https://example.com/vuln2"],
        "published_date": "2023-01-15T00:00:00Z",
        "source": "NVD"
    }

@pytest.fixture
def vulnerable_package_result(sample_vulnerability):
    """Sample scan result for a vulnerable package."""
    return {
        "package": "test-package",
        "version": "1.0.0",
        "vulnerabilities": [sample_vulnerability],
        "name_similarity": {
            "potential_typosquatting": False,
            "similar_packages": [],
            "risk_level": "Low"
        },
        "reputation": {
            "risk_level": "Low",
            "package_age": "2 years (Established)",
            "download_count": 50000,
            "suspicious_patterns": []
        }
    }

@pytest.fixture
def safe_package_result():
    """Sample scan result for a safe package."""
    return {
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
            "download_count": 100000,
            "suspicious_patterns": []
        }
    }

@pytest.fixture
def typosquatting_package_result():
    """Sample scan result for a package with typosquatting concerns."""
    return {
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
            "suspicious_patterns": ["Very new package (less than 30 days old)", "Few GitHub stars"],
            "package_age": "5 days (Very New)",
            "download_count": 100,
            "github_stars": 2
        }
    }

@pytest.fixture
def dependency_result(vulnerable_package_result):
    """Sample dependency chain analysis result."""
    return {
        "dependency_tree": {
            "root-package": {
                "version": "1.0.0",
                "dependencies": {
                    "test-package": {
                        "version": "1.0.0",
                        "dependencies": {},
                        "path": ["root-package"]
                    },
                    "safe-dep": {
                        "version": "2.0.0",
                        "dependencies": {},
                        "path": ["root-package"]
                    }
                },
                "path": []
            }
        },
        "all_packages": {
            "root-package": {"version": "1.0.0", "path": []},
            "test-package": {"version": "1.0.0", "path": ["root-package"]},
            "safe-dep": {"version": "2.0.0", "path": ["root-package"]}
        },
        "vulnerable_dependencies": {
            "test-package": {
                "version": "1.0.0",
                "vulnerabilities": [vulnerable_package_result["vulnerabilities"][0]],
                "path": ["root-package"],
                "vulnerability_count": 1
            }
        },
        "total_dependencies": 3,
        "vulnerable_dependency_count": 1,
        "total_vulnerability_count": 1,
        "visualization": "base64-encoded-image-data"  # Placeholder for actual visualization
    }

@pytest.fixture
def mock_model():
    """Mock LLM model."""
    mock = MagicMock()
    mock.return_value = [{"generated_text": "Enhanced security report by LLM"}]
    return mock

@pytest.fixture
def temp_config_file():
    """Create a temporary config file."""
    # Create a temporary config file
    temp_config = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml')
    temp_config.write("""
llm:
  model: test-model-from-config
  offline_mode: false
security:
  nvd:
    enabled: true
    api_key: null
  osv:
    enabled: true
  pypi:
    enabled: true
""")
    temp_config.close()
    
    # Return the path to the file
    yield temp_config.name
    
    # Clean up after the test
    os.unlink(temp_config.name)

@pytest.fixture
def temp_prompts_file():
    """Create a temporary prompts file."""
    # Create a temporary prompts file
    temp_prompts = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml')
    temp_prompts.write("""
security_enhancement_prompt: |
  I have a security analysis report for Python dependencies.
  
  Technical Context:
  {technical_context}
  
  Original Report:
  {basic_report}
  
  Please enhance this report by:
  1. Adding more context about the vulnerabilities
  2. Providing more detailed remediation steps
  3. Explaining the security implications in plain language
""")
    temp_prompts.close()
    
    # Return the path to the file
    yield temp_prompts.name
    
    # Clean up after the test
    os.unlink(temp_prompts.name)

@pytest.fixture
def patch_open_for_config(temp_config_file):
    """Patch the open function to use the temporary config file."""
    original_open = open
    
    def patched_open(file, *args, **kwargs):
        if file == "config/default_config.yaml":
            return original_open(temp_config_file, *args, **kwargs)
        return original_open(file, *args, **kwargs)
    
    # We can't directly patch the built-in open function
    # This is a placeholder for the actual implementation in tests
    return patched_open, temp_config_file

@pytest.fixture
def patch_open_for_prompts(temp_prompts_file):
    """Patch the open function to use the temporary prompts file."""
    original_open = open
    
    def patched_open(file, *args, **kwargs):
        if file == "prompts.yaml":
            return original_open(temp_prompts_file, *args, **kwargs)
        return original_open(file, *args, **kwargs)
    
    # We can't directly patch the built-in open function
    # This is a placeholder for the actual implementation in tests
    return patched_open, temp_prompts_file