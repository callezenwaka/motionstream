# Santé quickstart

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A comprehensive security scanning tool for Python dependencies that detects vulnerabilities, identifies typosquatting attempts, and visualizes dependency chains.

![Security Report Example](https://via.placeholder.com/800x400?text=Security+Report+Example)

## Features

- **Vulnerability Detection**: Scans packages for known security vulnerabilities (CVEs)
- **Typosquatting Protection**: Identifies malicious packages with names similar to popular libraries
- **Dependency Chain Analysis**: Visualizes complete dependency trees with vulnerability highlighting
- **Multiple File Format Support**: Works with requirements.txt, Pipfile, poetry.lock, environment.yml, and more
- **Automated Monitoring**: Watches dependency files for changes and triggers security scans
- **LLM Enhancement (Optional)**: Uses AI to provide in-depth security insights when available

## Installation

```bash
# Clone the repository
git clone https://github.com/callezenwaka/sante.git

# Navigate to the toolkit directory
cd sante

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Basic Security Scan

Scan your project's requirements file for vulnerabilities:

```bash
# Scan requirements.txt
python app.py --file /path/to/your/project/requirements.txt

# Save the report to a file
python app.py --file /path/to/your/project/requirements.txt --output security_report.md
```

### Advanced Analysis

For deeper security insights:

```bash
# Include dependency chain analysis
python app.py --file /path/to/your/project/requirements.txt --check-deps

# Use LLM enhancement (if available)
python app.py --file /path/to/your/project/requirements.txt --model mistralai/Mistral-7B-Instruct-v0.2

# With Ollama (if installed)
python app.py --file /path/to/your/project/requirements.txt --model llama2
```

### Continuous Monitoring

Set up automatic monitoring for dependency changes:

```bash
# Start watching your project directory
python watcher.py --directory /path/to/your/project

# Start with immediate scan
python watcher.py --directory /path/to/your/project --scan
```

## Integrating Into Your Workflow

### Pre-Commit Check

Add a security check before committing dependency changes:

```bash
# Before committing dependency changes:
cd /path/to/sante
python app.py --file /path/to/your/project/requirements.txt
```

### CI/CD Integration

Add this to your CI/CD configuration:

```yaml
# Example for GitHub Actions
- name: Check dependencies for security issues
  run: |
    git clone https://github.com/callezenwaka/sante.git
    cd sante
    pip install -r requirements.txt
    python app.py --file ../requirements.txt --output ../security_report.md
```

## Understanding Security Reports

The security report includes several key sections:

### 1. Vulnerability Summary

Overview of detected security issues with severity levels:
- 🚨 **Critical**: Requires immediate attention
- ⚠️ **High**: Serious security concern
- 🔶 **Medium**: Moderate risk
- ℹ️ **Low**: Minor security issue

### 2. Vulnerability Details

For each vulnerability:
- CVE ID or vulnerability identifier
- Severity rating
- Description of the vulnerability
- Fixed versions
- References to security advisories

### 3. Typosquatting Concerns

Identifies packages with suspicious names similar to popular libraries, which could indicate malicious typosquatting attempts.

### 4. Package Reputation Analysis

Evaluates the trustworthiness of packages based on:
- Package age
- Download counts
- Development activity
- Suspicious patterns

### 5. Dependency Chain Analysis

Maps the complete dependency tree showing:
- Direct and transitive dependencies
- Vulnerability paths
- Color-coded security status

### 6. Recommendations

Actionable steps to address security issues:
- Specific version upgrades
- Package replacements
- Security best practices

## Example Workflow

For a typical project workflow:

1. **Initial Assessment**:
   ```bash
   python app.py --file /path/to/your/project/requirements.txt --check-deps --output security_assessment.md
   ```

2. **Continuous Monitoring**:
   ```bash
   python watcher.py --directory /path/to/your/project --scan
   ```

3. **New Dependency Check**:
   ```bash
   # After adding new dependencies
   python app.py --file /path/to/your/project/requirements.txt
   ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Python Dependency Security Assistant is not affiliated with PyPI or the Python Software Foundation.*