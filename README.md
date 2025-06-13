# MotionStream

**AI-Powered Python Package Security Scanner**

MotionStream is a proof-of-concept security scanner that uses artificial intelligence to analyze Python package dependencies for vulnerabilities, malicious packages, and security risks. It leverages the OSV (Open Source Vulnerabilities) database and advanced AI agents to provide comprehensive security analysis.

## ✨ Features

- 🚀 **Batch Vulnerability Scanning** - Efficiently scans multiple packages using OSV's batch API
- 🤖 **AI-Powered Analysis** - Uses Hugging Face AI agents for intelligent security assessment
- 📊 **Multiple Output Formats** - Console, JSON, and HTML reports
- 📋 **Multi-Format Support** - Works with `requirements.txt` and `environment.yml` files
- ⚡ **Fast Performance** - 10-20x faster than individual package scanning
- 🛡️ **Comprehensive Reporting** - Detailed vulnerability analysis with remediation recommendations

## 🚀 Quick Start

### Installation

```bash
# Install directly from GitHub
pip install git+https://github.com/callezenwaka/motionstream.git

# Or clone and install in development mode
git clone https://github.com/callezenwaka/motionstream.git
cd motionstream
pip install -e .
```

### Setup

1. Get a Hugging Face token from [https://huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
2. Set your environment variable:
```bash
export HF_TOKEN='huggingface_token'
```

### Basic Usage

```bash
# Scan a requirements.txt file
motionstream scan requirements.txt

# Scan a conda environment file
motionstream scan environment.yml

# Generate JSON report
motionstream scan requirements.txt --output json

# Generate HTML report
motionstream scan requirements.txt --output html

# Or with custom model
motionstream scan requirements.txt
motionstream scan environment.yml --output json
motionstream scan requirements.txt --output html
motionstream scan requirements.txt --model "model-id"
motionstream scan requirements.txt --model "model-id" --output json
```

## 📖 Usage Guide

### Command Line Interface

```
usage: motionstream [-h] [--output {console,json,html}] {scan} file_path

🔒 MotionStream - AI-Powered Python Security Scanner

positional arguments:
  {scan}                Command to execute
  file_path            Path to requirements.txt or environment.yml

optional arguments:
  -h, --help           show this help message and exit
  --output {console,json,html}
                       Output format (default: console)
```

### Supported File Formats

#### requirements.txt
```txt
requests==2.25.1
django>=3.0.0
flask~=2.0.0
numpy
```

#### environment.yml
```yaml
name: myproject
dependencies:
  - python=3.9
  - requests=2.25.1
  - pip:
    - django==3.2.0
    - flask>=2.0.0
```

## 🖥️ Output Examples

### Console Output
```
🔒 MotionStream Security Scanner
----------------------------------------
📦 Parsed 15 packages from requirements.txt

🔍 Running comprehensive security analysis...

# Install dependencies without changing package managers
pip install -r requirements.txt

# Safety secures every installation request
Installed django 5.1.7
Installed boto3 1.37.26
Installed requests 2.31.0
⚠ Blocked "tensorflow" - malicious package detected!

Securely installed 3 dependencies, blocked 1.

# Reports on vulnerabilities in your dependencies
⚠ Warning: requests 2.31.0 has a vulnerability impacting
the Session class. Upgrade to 2.32.0 to fix.

✅ Security analysis completed successfully!
```

### JSON Output
```json
{
  "scan_timestamp": "2025-01-11T10:30:00",
  "dependencies_scanned": 15,
  "vulnerabilities_found": 3,
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0
  },
  "dependencies": [...],
  "vulnerabilities": [...],
  "agent_analysis": "..."
}
```

## 🛠️ Development

### Requirements
- Python 3.8+
- Hugging Face account and API token
- Internet connection for OSV and PyPI APIs

### Dependencies
```
smolagents>=0.1.0
requests>=2.28.0
pyyaml>=6.0
packaging>=21.0
huggingface-hub>=0.16.0
```

### Running Tests
```bash
# Test the package scanner directly
python -c "
from src.tools.package_scan import PackageScanTool
scanner = PackageScanTool()
result = scanner.forward([{'name': 'requests', 'version': '2.25.1'}])
print(f'Found {len(result)} vulnerabilities')
"
```

## 🔍 How It Works

1. **Parse Dependencies** - Extracts package names and versions from dependency files
2. **Batch Vulnerability Scan** - Uses OSV's `/v1/querybatch` API for efficient scanning
3. **AI Analysis** - Processes scan results through specialized AI agent
4. **Risk Assessment** - Evaluates severity, impact, and provides recommendations
5. **Report Generation** - Formats results in user-specified format

## 🚨 Security Considerations

- **API Keys** - Keep your Hugging Face token secure
- **Network Requests** - Tool makes external API calls to OSV and PyPI
- **False Positives** - Always verify vulnerability reports manually
- **Rate Limits** - Respects API rate limits automatically

## 📝 Examples

### Generate HTML Report
```bash
motionstream scan requirements.txt --output html
# Creates: security_report_YYYYMMDD_HHMMSS.html
```

### Scan Conda Environment
```bash
# Export your current environment
conda env export > environment.yml

# Scan it
motionstream scan environment.yml
```

## Run tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_parser.py -v

# Run with coverage
pip install pytest-cov
pytest --cov=src tests/
```

## 🤝 Contributing

This is a proof-of-concept project. For improvements:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OSV (Open Source Vulnerabilities)](https://osv.dev/) - Vulnerability database
- [Hugging Face](https://huggingface.co/) - AI model hosting
- [smolagents](https://github.com/huggingface/smolagents) - AI agent framework

## ⚠️ Disclaimer

MotionStream is a proof-of-concept tool for educational and research purposes. While it uses reliable vulnerability databases and AI analysis, always verify security findings manually and use additional security tools in production environments.

---