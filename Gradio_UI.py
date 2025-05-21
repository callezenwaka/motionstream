# Gradio_UI.py
import gradio as gr
import json
from tools.vulnerability_scan import scan_vulnerabilities
from tools.dependency_chain import analyze_dependency_chain
from tools.name_similarity import check_name_similarity
from tools.package_reputation import check_package_reputation
from tools.summary import format_security_report
from tools.dependency_parser import parse_dependency_file

def analyze_package(package_name=None, version=None, file_content=None, check_deps=False):
    """Analyze a package or dependency file for security issues."""
    results = []
    
    if file_content:
        # Save uploaded file content temporarily
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as tmp:
            tmp.write(file_content)
            tmp_path = tmp.name
        
        # Parse dependency file
        try:
            packages = parse_dependency_file(tmp_path)
            for package_name, version in packages:
                result = scan_single_package(package_name, version, check_deps)
                results.append(result)
        except Exception as e:
            return f"Error parsing dependency file: {str(e)}"
        finally:
            # Clean up temporary file
            import os
            os.unlink(tmp_path)
    
    elif package_name:
        # Scan single package
        result = scan_single_package(package_name, version, check_deps)
        results.append(result)
    else:
        return "Please provide a package name or upload a dependency file."
    
    # Generate report
    report = format_security_report(results)
    return report

def scan_single_package(package_name, version=None, check_deps=False):
    """Scan a single package for security issues."""
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

# Create Gradio interface
with gr.Blocks(title="Python Dependency Security Assistant") as demo:
    gr.Markdown("# Python Dependency Security Assistant")
    gr.Markdown("Scan Python packages for security vulnerabilities, typosquatting, and suspicious behaviors")
    
    with gr.Tabs():
        with gr.TabItem("Package Analysis"):
            with gr.Row():
                package_input = gr.Textbox(label="Package Name", placeholder="e.g., requests")
                version_input = gr.Textbox(label="Version (optional)", placeholder="e.g., 2.25.0")
            
            deps_checkbox = gr.Checkbox(label="Analyze dependency chain", value=False)
            scan_button = gr.Button("Scan Package")
            package_output = gr.Markdown(label="Security Analysis")
            
            scan_button.click(
                analyze_package, 
                inputs=[package_input, version_input, None, deps_checkbox], 
                outputs=package_output
            )
            
        with gr.TabItem("File Analysis"):
            file_input = gr.Textbox(label="Paste requirements.txt content", lines=10)
            file_deps_checkbox = gr.Checkbox(label="Analyze dependency chains", value=False)
            file_scan_button = gr.Button("Scan Dependencies")
            file_output = gr.Markdown(label="Security Analysis")
            
            file_scan_button.click(
                analyze_package,
                inputs=[None, None, file_input, file_deps_checkbox],
                outputs=file_output
            )

    gr.Markdown("## How it works")
    gr.Markdown("""
    This tool checks for:
    1. Known security vulnerabilities (CVEs)
    2. Typosquatting attempts (similar names to popular packages)
    3. Package reputation and trustworthiness
    4. Issues in the dependency chain
    
    For best results, analyze your full requirements.txt file.
    """)

if __name__ == "__main__":
    demo.launch()