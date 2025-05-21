# Santé /sɑ̃te/

A comprehensive security scanning tool for Python dependencies that detects vulnerabilities, identifies typosquatting attempts, and visualizes dependency chains.

![Security Report Example](https://via.placeholder.com/800x400?text=Security+Report+Example)

## Features

- **Vulnerability Detection**: Scans packages for known security vulnerabilities (CVEs)
- **Typosquatting Protection**: Identifies malicious packages with names similar to popular libraries
- **Dependency Chain Analysis**: Visualizes complete dependency trees with vulnerability highlighting
- **Multiple File Format Support**: Works with requirements.txt, Pipfile, poetry.lock, environment.yml, and more
- **Automated Monitoring**: Watches dependency files for changes and triggers security scans
- **Comprehensive Reports**: Generates detailed security reports with remediation recommendations

## Installation

```bash
# Install directly from GitHub
pip install git+https://github.com/yourusername/Python_Dependency_Security_Assistant.git

# Or clone and install locally
git clone https://github.com/yourusername/Python_Dependency_Security_Assistant.git
cd Python_Dependency_Security_Assistant
pip install -r requirements.txt
```

## Quick Start

### Scan a Package

```bash
# Scan a specific package
python app.py requests

# Scan a specific version
python app.py requests --version 2.25.0

# Include dependency chain analysis
python app.py requests --check-deps
```

### Scan a Dependency File

```bash
# Scan a requirements file
python app.py --file requirements.txt

# Scan a conda environment file
python app.py --file environment.yml

# Scan any supported dependency file
python app.py --file Pipfile
```

### Watch for Changes

```bash
# Monitor the current directory for dependency file changes
python watcher.py

# Monitor a specific directory
python watcher.py --directory /path/to/project

# Scan immediately when started
python watcher.py --scan
```

## LLM Enhancement (Optional)

The tool works completely without an LLM, but can be enhanced with one:

```bash
# Run with default settings (no LLM)
python app.py --file requirements.txt

# Use a specific model
python app.py --file requirements.txt --model mistralai/Mistral-7B-Instruct-v0.2

# Use a local model file
python app.py --file requirements.txt --model ./models/my-local-model

# Use Ollama
python app.py --file requirements.txt --model llama2

# Explicitly disable LLM enhancement
python app.py --file requirements.txt --no-llm

# Basic usage (no LLM)
python app.py requests

# With specific model
python app.py requests --model mistralai/Mistral-7B-Instruct-v0.2

# With Ollama model
python app.py requests --model llama2

# Explicitly disable LLM
python app.py requests --no-llm
```

## LLM Enhancement (Optional)

This tool can use an LLM to enhance security reports:

```bash
# Run with default settings (no LLM)
python app.py requests

# Use a specific model
python app.py requests --model mistralai/Mistral-7B-Instruct-v0.2

# Use a local Ollama model
python app.py requests --model llama2

# Explicitly disable LLM
python app.py requests --no-llm

### Web Interface

```bash
# Launch the web interface
python Gradio_UI.py
```

![Gradio UI Example](https://via.placeholder.com/800x400?text=Gradio+UI+Example)

## Security Features

### Vulnerability Detection

The tool scans packages against multiple security databases:
- National Vulnerability Database (NVD)
- Open Source Vulnerabilities (OSV) database
- PyPI security advisories

Vulnerabilities are categorized by severity (Critical, High, Medium, Low) with detailed information and remediation steps.

### Typosquatting Protection

Detects potentially malicious packages with names similar to popular libraries:
- Text similarity analysis
- Keyboard-adjacency typo detection
- Package reputation assessment

This helps protect against supply-chain attacks like the "vibe coding" security issue where hackers publish malicious packages with commonly mistyped names.

### Dependency Chain Analysis

Visualizes the complete dependency tree of a package with:
- Color-coded vulnerability indicators
- Path tracing to vulnerable dependencies
- Transitive vulnerability detection

This reveals security issues hidden deep in dependency chains that might otherwise go unnoticed.

## Configuration

You can customize the tool's behavior by creating a `config.yaml` file:

```yaml
# Basic configuration example
features:
  vulnerability_scan: true
  name_similarity: true
  package_reputation: true
  dependency_chain: true

security:
  nvd:
    enabled: true
    api_key: "your-api-key"  # Optional

watcher:
  interval: 10  # Check every 10 seconds

output:
  report_dir: "./my_security_reports"
```

See the [full configuration options](config/default_config.yaml) for more details.

## Report Example

```markdown
# Security Analysis: requests==2.25.0

Scanned on 2023-05-21 15:30:45

## Summary

⚠️ **HIGH SECURITY ISSUES FOUND**

* Found **2** vulnerabilities in **1** packages
* Severity breakdown:
  * Critical: **0**
  * High: **1**
  * Medium: **1**
  * Low: **0**

## Vulnerability Details

### requests (version 2.25.0)

#### ⚠️ CVE-2023-32681 (High)

**Summary**: URL Parsing Vulnerability in Requests

**Details**: URL parsing in Requests before 2.31.0 may cause a maliciously crafted URL to be parsed differently by different components.

**Fixed in versions**: 2.31.0

**References**:
* https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q

#### Remediation

Upgrade to version **2.31.0** or later.

```
pip install requests>=2.31.0
```
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- National Vulnerability Database for security data
- Open Source Vulnerabilities database
- The Python packaging community

---

*Python Dependency Security Assistant is not affiliated with PyPI or the Python Software Foundation.*