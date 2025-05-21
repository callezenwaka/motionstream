# app.py
import argparse
import yaml
import json
from pathlib import Path
from tools.vulnerability_scan import scan_vulnerabilities
from tools.dependency_chain import analyze_dependency_chain
from tools.name_similarity import check_name_similarity
from tools.package_reputation import check_package_reputation
from tools.summary import format_security_report
from tools.llm_utils import load_model

def main():
    parser = argparse.ArgumentParser(description="Python Dependency Security Assistant")
    parser.add_argument("package", nargs="?", help="Package name to analyze")
    parser.add_argument("--version", "-v", help="Package version")
    parser.add_argument("--file", "-f", help="Dependency file to scan")
    parser.add_argument("--check-deps", "-d", action="store_true", help="Check dependency chain")
    parser.add_argument("--output", "-o", help="Output file for report")
    parser.add_argument("--model", help="Path or name of LLM model to use")
    parser.add_argument("--no-llm", action="store_true", help="Run without LLM enhancements")
    args = parser.parse_args()

    # In your main function, load the model
    model = load_model(args.model, args.no_llm)

    # Determine what to scan
    if args.file:
        # File-based scanning
        from tools.dependency_parser import parse_dependency_file
        print(f"Scanning dependencies in {args.file}...")
        packages = parse_dependency_file(args.file)
        
        results = []
        for package_name, version in packages:
            result = scan_package(package_name, version, args.check_deps)
            results.append(result)
            
        # Generate combined report
        report = format_security_report(results, file_path=args.file, model=model)
        
    elif args.package:
        # Single package scanning
        result = scan_package(args.package, args.version, args.check_deps)
        report = format_security_report([result])
    else:
        parser.print_help()
        return
    
    # Output report
    print(report)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report saved to {args.output}")

def scan_package(package_name, version=None, check_deps=False):
    """Perform comprehensive security scan on a package."""
    print(f"Scanning {package_name}{f'=={version}' if version else ''}...")
    
    # Core vulnerability scanning
    vulnerabilities = scan_vulnerabilities(package_name, version)
    
    # Check for typosquatting
    name_similarity = check_name_similarity(package_name)
    
    # Check package reputation
    reputation = check_package_reputation(package_name)
    
    # Analyze dependency chain if requested
    dependency_results = None
    if check_deps:
        dependency_results = analyze_dependency_chain(package_name, version)
    
    # Combine results
    return {
        "package": package_name,
        "version": version,
        "vulnerabilities": vulnerabilities,
        "name_similarity": name_similarity,
        "reputation": reputation,
        "dependencies": dependency_results
    }

if __name__ == "__main__":
    main()