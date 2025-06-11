# tests/conftest.py - Test configuration and fixtures
import pytest
import tempfile
from pathlib import Path

@pytest.fixture
def sample_requirements_txt():
    """Create a temporary requirements.txt file for testing."""
    content = """
# This is a comment
requests==2.25.1
django>=3.0.0
flask~=2.0.0
numpy
-r other-requirements.txt
git+https://github.com/user/repo.git#egg=package
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(content)
        f.flush()
        yield f.name
    Path(f.name).unlink()

@pytest.fixture
def sample_environment_yml():
    """Create a temporary environment.yml file for testing."""
    content = """
name: test-env
dependencies:
  - python=3.9
  - requests=2.25.1
  - django>=3.0
  - pip:
    - flask==2.0.0
    - numpy>=1.20.0
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(content)
        f.flush()
        yield f.name
    Path(f.name).unlink()

@pytest.fixture
def sample_vulnerabilities():
    """Sample vulnerability data for testing."""
    return [
        {
            "package": "requests",
            "package_version": "2.25.1",
            "vulnerability_id": "GHSA-j8r2-6x86-q33q",
            "modified_date": "2023-03-14T05:47:39.989396Z",
            "source": "OSV"
        },
        {
            "package": "django",
            "package_version": "2.1.0",
            "vulnerability_id": "GHSA-8x94-hmjh-97hh",
            "modified_date": "2023-02-14T05:47:39.989396Z",
            "source": "OSV"
        }
    ]