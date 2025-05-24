#!/usr/bin/env python3
import argparse
import sys
import os
import threading
import time

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class Spinner:
    """Simple spinner for showing progress during long-running operations."""
    
    def __init__(self, message="Scanning", delay=0.1):
        self.spinner_symbols = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.delay = delay
        self.message = message
        self.running = False
        self.thread = None
    
    def spin(self):
        """Display the spinner."""
        while self.running:
            for symbol in self.spinner_symbols:
                if not self.running:
                    break
                sys.stdout.write(f'\r{symbol} {self.message}...')
                sys.stdout.flush()
                time.sleep(self.delay)
    
    def start(self):
        """Start the spinner."""
        self.running = True
        self.thread = threading.Thread(target=self.spin)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self, success_message=None):
        """Stop the spinner."""
        self.running = False
        if self.thread:
            self.thread.join()
        
        # Clear the spinner line
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        sys.stdout.flush()
        
        if success_message:
            print(f"✓ {success_message}")

def run_with_spinner(func, spinner_message, success_message=None):
    """Run a function with a spinner display."""
    spinner = Spinner(spinner_message)
    
    try:
        spinner.start()
        result = func()
        spinner.stop(success_message)
        return result
    except Exception as e:
        spinner.stop()
        print(f"✗ Error: {e}")
        return None
    except KeyboardInterrupt:
        spinner.stop()
        print("\n✗ Scan interrupted by user")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        prog="sante",
        description="Python Package Security Scanner - Identify vulnerabilities in Python packages and dependencies",
        epilog="""
            Examples:
            sante package requests                              Scan requests package for vulnerabilities
            sante package django --version 4.2.0 --check-deps Scan specific Django version with dependency analysis
            sante file requirements.txt --model llama2         Scan requirements file with LLM enhancement
            sante watch --directory /project --scan            Monitor project directory for changes
            sante web --share --port 8080                      Launch web interface with public access

            For more information about each command, use:
            sante <command> --help

            Report bugs and request features at: https://github.com/callezenwaka/sante
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add version argument
    parser.add_argument(
        '-V', '--version',
        action='version',
        version='Python Package Security Scanner v0.1.0'
    )
    
    subparsers = parser.add_subparsers(
        dest="command", 
        title="Commands",
        description="Available security scanning commands",
        help="Use 'sante <command> --help' for detailed command information"
    )
    
    # Package command
    pkg_parser = subparsers.add_parser(
        "package", 
        help="Scan a single Python package for security vulnerabilities",
        description="""
            Scan individual Python packages for known security vulnerabilities.
            This command checks the specified package against multiple vulnerability
            databases and provides detailed security reports with remediation guidance.
        """,
        epilog="""
            Examples:
            sante package requests                     Scan latest version of requests
            sante package flask --version 2.0.1       Scan specific Flask version
            sante package django --check-deps         Include dependency chain analysis
            sante package numpy --model llama2        Use LLM for enhanced reporting
            sante package pandas --no-llm -o report   Fast scan with file output
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    pkg_parser.add_argument(
        "package", 
        help="Name of the Python package to scan (e.g., 'requests', 'django')"
    )
    pkg_parser.add_argument(
        "--version", 
        metavar="VERSION",
        help="Specific package version to scan (e.g., '2.25.0'). If not specified, uses latest or installed version"
    )
    pkg_parser.add_argument(
        "--check-deps", 
        action="store_true",
        help="Include dependency chain analysis to identify vulnerabilities in package dependencies"
    )
    pkg_parser.add_argument(
        "--output", "-o", 
        metavar="FILE",
        help="Save security report to specified file (e.g., 'security_report.md')"
    )
    pkg_parser.add_argument(
        "--model", 
        metavar="MODEL",
        help="LLM model for enhanced reporting (e.g., 'llama2', 'mistralai/Mistral-7B-Instruct-v0.2')"
    )
    pkg_parser.add_argument(
        "--no-llm", 
        action="store_true",
        help="Disable LLM enhancement for faster scanning (recommended for CI/CD)"
    )
    
    # File command
    file_parser = subparsers.add_parser(
        "file", 
        help="Scan dependency files for security vulnerabilities",
        description="""
            Scan dependency files for security vulnerabilities across all listed packages.
            Supports multiple file formats including requirements.txt, Pipfile, environment.yml,
            pyproject.toml, and setup.py files. Provides comprehensive security analysis
            for entire project dependencies.
        """,
        epilog="""
            Supported file formats:
            requirements.txt       Standard pip requirements file
            Pipfile               Pipenv dependency file
            Pipfile.lock          Pipenv lock file with exact versions
            environment.yml       Conda environment file
            pyproject.toml        Modern Python project file
            setup.py              Traditional Python setup file

            Examples:
            sante file requirements.txt                    Scan pip requirements
            sante file environment.yml                    Scan conda environment
            sante file Pipfile --model llama2             Scan Pipfile with LLM
            sante file pyproject.toml --no-llm -o report  Fast scan with output file
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    file_parser.add_argument(
        "file", 
        help="Path to dependency file to scan (supports requirements.txt, Pipfile, environment.yml, etc.)"
    )
    file_parser.add_argument(
        "--output", "-o", 
        metavar="FILE",
        help="Save comprehensive security report to specified file"
    )
    file_parser.add_argument(
        "--model", 
        metavar="MODEL",
        help="LLM model for enhanced reporting and vulnerability analysis"
    )
    file_parser.add_argument(
        "--no-llm", 
        action="store_true",
        help="Disable LLM enhancement for faster bulk scanning"
    )
    
    # Watch command
    watch_parser = subparsers.add_parser(
        "watch", 
        help="Monitor directories for dependency file changes",
        description="""
            Continuously monitor directories for changes in dependency files and
            automatically perform security scans when modifications are detected.
            Useful for development environments and CI/CD pipelines to maintain
            ongoing security awareness.
        """,
        epilog="""
            Monitored file types:
            requirements.txt, Pipfile, Pipfile.lock, poetry.lock,
            pyproject.toml, setup.py, environment.yml

            Examples:
            sante watch                                Monitor current directory
            sante watch --directory /project          Monitor specific directory  
            sante watch --scan                        Scan immediately on startup
            sante watch --directory /app --scan       Monitor and scan project directory
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    watch_parser.add_argument(
        "--directory", 
        metavar="DIR",
        help="Directory to monitor for dependency file changes (default: current directory)"
    )
    watch_parser.add_argument(
        "--scan", 
        action="store_true",
        help="Perform initial security scan immediately when watcher starts"
    )
    
    # Web interface command
    web_parser = subparsers.add_parser(
        "web", 
        help="Launch interactive web interface",
        description="""
            Launch an interactive web-based interface for conversational security analysis.
            Provides a chat-like interface where you can ask security questions, upload
            dependency files, and get interactive vulnerability reports. Powered by
            AI agents for enhanced user experience.
        """,
        epilog="""
            Web interface features:
            - Conversational security analysis
            - File upload support (requirements.txt, etc.)
            - Interactive vulnerability exploration
            - Real-time scanning and reporting
            - Shareable public links (with --share)

            Examples:
            sante web                                  Launch on default port (7860)
            sante web --port 8080                     Launch on custom port
            sante web --share                         Create public shareable link
            sante web --model llama2 --share          Use custom model with sharing
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    web_parser.add_argument(
        "--model", 
        default="microsoft/DialoGPT-medium",
        metavar="MODEL",
        help="HuggingFace model for conversational agent (default: microsoft/DialoGPT-medium)"
    )
    web_parser.add_argument(
        "--port", 
        type=int, 
        default=7860,
        metavar="PORT",
        help="Port to run web interface on (default: 7860)"
    )
    web_parser.add_argument(
        "--share", 
        action="store_true",
        help="Create public shareable link (accessible from internet)"
    )
    
    args = parser.parse_args()
    
    if args.command == "package":
        def run_package_scan():
            # Call app.py: python app.py requests --version 2.25.0 --check-deps --model llama2
            import app
            sys.argv = ["app.py", args.package]
            if args.version:
                sys.argv.extend(["--version", args.version])
            if args.check_deps:
                sys.argv.append("--check-deps")
            if args.output:
                sys.argv.extend(["--output", args.output])
            if args.model:
                sys.argv.extend(["--model", args.model])
            if args.no_llm:
                sys.argv.append("--no-llm")
            app.main()
        
        # Create spinner message
        version_info = f" (v{args.version})" if args.version else ""
        spinner_msg = f"Scanning {args.package}{version_info}"
        success_msg = f"Scan completed for {args.package}"
        
        run_with_spinner(run_package_scan, spinner_msg, success_msg)
        
    elif args.command == "file":
        def run_file_scan():
            # Call app.py: python app.py --file requirements.txt --model mistralai/Mistral-7B-Instruct-v0.2
            import app
            sys.argv = ["app.py", "--file", args.file]
            if args.output:
                sys.argv.extend(["--output", args.output])
            if args.model:
                sys.argv.extend(["--model", args.model])
            if args.no_llm:
                sys.argv.append("--no-llm")
            app.main()
        
        # Create spinner message
        filename = os.path.basename(args.file)
        spinner_msg = f"Scanning {filename}"
        success_msg = f"Scan completed for {filename}"
        
        run_with_spinner(run_file_scan, spinner_msg, success_msg)
        
    elif args.command == "watch":
        def run_watcher():
            # Call watcher.py: python watcher.py --directory /path/to/project --scan
            import watcher
            sys.argv = ["watcher.py"]
            if args.directory:
                sys.argv.extend(["--directory", args.directory])
            if args.scan:
                sys.argv.append("--scan")
            watcher.main()
        
        # No spinner for watcher since it has its own output
        run_watcher()
    
    # elif args.command == "web":
    #     def run_web_interface():
    #         # Launch web interface
    #         import launch_ui
    #         sys.argv = ["launch_ui.py"]
    #         if args.model != "microsoft/DialoGPT-medium":
    #             sys.argv.extend(["--model", args.model])
    #         if args.port != 7860:
    #             sys.argv.extend(["--port", str(args.port)])
    #         if args.share:
    #             sys.argv.append("--share")
    #         launch_ui.main()
        
    #     spinner_msg = f"Launching web interface on port {args.port}"
    #     success_msg = f"Web interface ready at http://localhost:{args.port}"
        
    #     run_with_spinner(run_web_interface, spinner_msg, success_msg)
        
    else:
        parser.print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main())