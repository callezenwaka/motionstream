# Python Package Security Scanner - CLI Commands

Complete reference for all available command-line interface (CLI) commands.

## Installation

```bash
# Install from GitHub
pip install git+https://github.com/callezenwaka/sante.git

# Verify installation
sante --help
```

## Command Structure

```bash
sante <command> [arguments] [options]
```

---

## 1. Package Scanning

Scan individual Python packages for security vulnerabilities.

### Basic Usage

```bash
# Scan latest version of package
sante package requests

# Scan specific version
sante package requests --version 2.25.0
```

### Advanced Options

```bash
# Include dependency chain analysis
sante package requests --check-deps

# Save report to file
sante package requests --output report.md

# Use specific LLM model for enhanced reporting
sante package requests --model mistralai/Mistral-7B-Instruct-v0.2
sante package requests --model llama2

# Disable LLM enhancement (faster)
sante package requests --no-llm
```

### Combined Examples

```bash
# Comprehensive scan with all features
sante package django --version 4.2.0 --check-deps --model llama2 --output django_report.md

# Quick scan without LLM
sante package flask --version 2.0.1 --no-llm --output flask_report.md

# Dependency analysis with custom model
sante package numpy --check-deps --model mistralai/Mistral-7B-Instruct-v0.2
```

### Package Command Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--version` | | Specific package version | `--version 2.25.0` |
| `--check-deps` | | Include dependency chain analysis | `--check-deps` |
| `--output` | `-o` | Output report to file | `--output report.md` |
| `--model` | | LLM model for enhancement | `--model llama2` |
| `--no-llm` | | Disable LLM enhancement | `--no-llm` |

---

## 2. File Scanning

Scan dependency files for security vulnerabilities.

### Supported File Types

- `requirements.txt`
- `environment.yml` (conda)
- `Pipfile`
- `Pipfile.lock`
- `pyproject.toml`
- `setup.py`

### Basic Usage

```bash
# Scan requirements file
sante file requirements.txt

# Scan conda environment file
sante file environment.yml

# Scan Pipfile
sante file Pipfile
```

### Advanced Options

```bash
# Save report to file
sante file requirements.txt --output security_report.md

# Use specific LLM model
sante file requirements.txt --model mistralai/Mistral-7B-Instruct-v0.2

# Disable LLM enhancement
sante file requirements.txt --no-llm
```

### Combined Examples

```bash
# Comprehensive file scan with LLM
sante file requirements.txt --model llama2 --output comprehensive_report.md

# Quick scan without LLM
sante file Pipfile --no-llm --output pipfile_security.md

# Multiple file scans
sante file environment.yml --model mistralai/Mistral-7B-Instruct-v0.2 --output conda_security.md
```

### File Command Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output report to file | `--output report.md` |
| `--model` | | LLM model for enhancement | `--model llama2` |
| `--no-llm` | | Disable LLM enhancement | `--no-llm` |

---

## 3. Directory Watching

Monitor directories for changes in dependency files and automatically scan them.

### Basic Usage

```bash
# Watch current directory
sante watch

# Watch specific directory
sante watch --directory /path/to/project

# Scan immediately when watcher starts
sante watch --scan
```

### Advanced Examples

```bash
# Watch project directory and scan immediately
sante watch --directory /my/project --scan

# Monitor multiple project directories (run multiple instances)
sante watch --directory /project1 --scan &
sante watch --directory /project2 --scan &
```

### Watch Command Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--directory` | | Directory to watch | `--directory /path/to/project` |
| `--scan` | | Scan immediately on startup | `--scan` |

### Monitored Files

The watcher automatically detects changes in:
- `requirements.txt`
- `Pipfile`
- `Pipfile.lock`
- `poetry.lock`
- `pyproject.toml`
- `setup.py`
- `environment.yml`

---

## 4. Web Interface

Launch an interactive web interface for conversational security scanning.

### Basic Usage

```bash
# Launch web interface (default settings)
sante web

# Access at: http://localhost:7860
```

### Advanced Options

```bash
# Use different HuggingFace model
sante web --model microsoft/DialoGPT-large

# Run on specific port
sante web --port 8080

# Create public shareable link
sante web --share
```

### Combined Examples

```bash
# Launch with custom model and public sharing
sante web --model llama2 --port 9000 --share

# Launch for local development
sante web --model microsoft/DialoGPT-medium --port 3000
```

### Web Command Options

| Option | Short | Description | Default | Example |
|--------|-------|-------------|---------|---------|
| `--model` | | HuggingFace model for agent | `microsoft/DialoGPT-medium` | `--model llama2` |
| `--port` | | Port to run interface on | `7860` | `--port 8080` |
| `--share` | | Create public shareable link | `False` | `--share` |

### Web Interface Features

- **Conversational interface** - Ask questions in natural language
- **File uploads** - Upload dependency files for analysis
- **Real-time scanning** - Uses your CLI tools behind the scenes
- **Interactive reports** - Explore vulnerabilities interactively

---

## 5. Help Commands

Get help and usage information for any command.

```bash
# General help
sante --help
sante -h

# Command-specific help
sante package --help
sante file --help
sante watch --help
sante web --help
```

---

## LLM Model Options

The scanner supports various LLM models for enhanced reporting:

### HuggingFace Models
```bash
--model mistralai/Mistral-7B-Instruct-v0.2
--model microsoft/DialoGPT-medium
--model microsoft/DialoGPT-large
```

### Ollama Models (if installed locally)
```bash
--model llama2
--model codellama
--model mistral
```

### Local Models
```bash
--model ./models/my-local-model
```

### Disable LLM
```bash
--no-llm
```

---

## Output Formats

All commands generate reports in **Markdown** format by default.

### Example Report Structure
```markdown
# Security Analysis: package-name

Generated on 2024-01-15 10:30:45

## Summary
⚠️ **HIGH SECURITY ISSUES FOUND**
* Found **3** vulnerabilities in **2** packages

## Vulnerability Details
### requests (version 2.25.1)
#### ⚠️ CVE-2023-32681 (High)
**Summary**: Session fixation vulnerability...
**Fixed in versions**: 2.31.0
**Remediation**: Upgrade to version 2.31.0 or later
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - No vulnerabilities found |
| `1` | Vulnerabilities found or error occurred |

---

## Examples by Use Case

### Quick Security Check
```bash
# Fast scan without LLM
sante package requests --no-llm
```

### Comprehensive Analysis
```bash
# Full analysis with dependency chain and LLM
sante package django --check-deps --model llama2 --output full_report.md
```

### CI/CD Pipeline
```bash
# Automated scanning for CI/CD
sante file requirements.txt --no-llm --output security_scan.md
```

### Development Workflow
```bash
# Watch for changes during development
sante watch --directory . --scan
```

### Interactive Analysis
```bash
# Launch web interface for team collaboration
sante web --share --model mistralai/Mistral-7B-Instruct-v0.2
```

---

## Troubleshooting

### Common Issues

**Command not found:**
```bash
# Reinstall the package
pip install --force-reinstall git+https://github.com/callezenwaka/sante.git
```

**Permission errors:**
```bash
# Install with user flag
pip install --user git+https://github.com/callezenwaka/sante.git
```

**Missing dependencies:**
```bash
# Install with all extras
pip install git+https://github.com/callezenwaka/sante.git[all]
```

---

## Version Information

```bash
# Check version (if implemented)
sante --version
```

For more information, visit the project repository or check the documentation.