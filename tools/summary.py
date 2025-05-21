# tools/summary.py
import yaml
from datetime import datetime
from pathlib import Path

def format_security_report(scan_results, file_path=None, model=None):
    """
    Format security scan results into a report, with optional LLM enhancement.
    
    Args:
        scan_results: List of security scan results for packages
        file_path: Original dependency file path (optional)
        model: Optional LLM model for enhanced analysis
        
    Returns:
        Formatted Markdown report as a string
    """
    # Generate the basic report structure
    report = generate_basic_report(scan_results, file_path)
    
    # Enhance with LLM if available
    if model is not None:
        try:
            enhanced_report = enhance_report_with_llm(report, scan_results, model)
            return enhanced_report
        except Exception as e:
            print(f"Error enhancing report with LLM: {e}")
    
    # Return the basic report if no model or enhancement failed
    return report

def enhance_report_with_llm(basic_report, scan_results, model):
    """
    Enhance a basic security report with LLM-generated insights.
    
    Args:
        basic_report: The basic report generated without LLM
        scan_results: The original scan results for additional context
        model: The LLM model to use
    
    Returns:
        Enhanced report with LLM-generated insights
    """
    # Load prompts for enhancement
    prompts = {}
    try:
        with open("prompts.yaml", "r") as f:
            prompts = yaml.safe_load(f)
    except Exception:
        pass
    
    # Extract key details from scan_results for better context
    vulnerable_pkgs = []
    for result in scan_results:
        if result.get('vulnerabilities', []):
            pkg_name = result.get('package')
            pkg_version = result.get('version')
            vulnerable_pkgs.append(f"{pkg_name}=={pkg_version}")
    
    # Create a context section with technical details
    technical_context = ""
    if vulnerable_pkgs:
        technical_context = "Vulnerable packages: " + ", ".join(vulnerable_pkgs) + "\n\n"
        
        # Add CVE IDs or vulnerability identifiers
        cve_ids = []
        for result in scan_results:
            for vuln in result.get('vulnerabilities', []):
                vuln_id = vuln.get('cve_id') or vuln.get('id')
                if vuln_id:
                    cve_ids.append(vuln_id)
        
        if cve_ids:
            technical_context += "Vulnerability IDs: " + ", ".join(cve_ids) + "\n\n"
    
    enhancement_prompt = prompts.get("security_enhancement_prompt", """
    I have a security analysis report for Python dependencies.
    
    Technical Context:
    {technical_context}
    
    Original Report:
    {basic_report}
    
    Please enhance this report by:
    1. Adding more context about the vulnerabilities
    2. Providing more detailed remediation steps 
    3. Explaining the security implications in plain language
    
    Keep the same Markdown formatting and structure.
    """)
    
    # Prepare the prompt with the actual report and context
    prompt = enhancement_prompt.format(
        basic_report=basic_report,
        technical_context=technical_context
    )
    
    # Get enhanced report from LLM
    try:
        response = model(prompt, max_tokens=2000, temperature=0.1)
        enhanced_text = response[0]['generated_text']
        
        # Extract just the response part if needed
        if "Original Report:" in enhanced_text and enhanced_text.index("Original Report:") > 0:
            enhanced_text = enhanced_text.split("Original Report:")[0].strip()
        
        return enhanced_text
    except Exception as e:
        print(f"Error getting LLM enhancement: {e}")
        return basic_report


def generate_basic_report(scan_results, file_path=None):
    """
    Generate a basic security report without LLM enhancement.
    
    Format security scan results into a comprehensive Markdown report.
    
    Args:
        scan_results: List of security scan results for packages
        file_path: Original dependency file path (optional)
        
    Returns:
        Formatted Markdown report as a string
    """
    
    # Initialize report
    report = []
    
    # Add header
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if file_path:
        report.append(f"# Security Analysis: {Path(file_path).name}")
        report.append(f"\nScanned on {timestamp}\n")
    else:
        package_info = scan_results[0]['package'] if scan_results else "Unknown"
        report.append(f"# Security Analysis: {package_info}")
        report.append(f"\nScanned on {timestamp}\n")
    
    # Count total vulnerabilities and categorize by severity
    total_vulnerabilities = 0
    critical = 0
    high = 0
    medium = 0
    low = 0
    unknown = 0
    vulnerable_packages = []
    
    for result in scan_results:
        vulnerabilities = result.get('vulnerabilities', [])
        if vulnerabilities:
            vulnerable_packages.append(result)
            total_vulnerabilities += len(vulnerabilities)
            
            # Count by severity
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                if severity == 'Critical':
                    critical += 1
                elif severity == 'High':
                    high += 1
                elif severity == 'Medium':
                    medium += 1
                elif severity == 'Low':
                    low += 1
                else:
                    unknown += 1
    
    # Add summary
    if total_vulnerabilities > 0:
        report.append(f"## Summary\n")
        
        if critical > 0:
            report.append(f"🚨 **CRITICAL SECURITY ISSUES FOUND**\n")
        elif high > 0:
            report.append(f"⚠️ **HIGH SECURITY ISSUES FOUND**\n")
        elif medium > 0:
            report.append(f"🔶 **MEDIUM SECURITY ISSUES FOUND**\n")
        else:
            report.append(f"ℹ️ **MINOR SECURITY ISSUES FOUND**\n")
        
        report.append(f"* Found **{total_vulnerabilities}** vulnerabilities in **{len(vulnerable_packages)}** packages")
        report.append(f"* Severity breakdown:")
        report.append(f"  * Critical: **{critical}**")
        report.append(f"  * High: **{high}**")
        report.append(f"  * Medium: **{medium}**")
        report.append(f"  * Low: **{low}**")
        if unknown > 0:
            report.append(f"  * Unknown: **{unknown}**")
        
        report.append("\n")
    else:
        report.append("## Summary\n")
        report.append("✅ **No known vulnerabilities found**\n")
        report.append("No security issues were identified in the scanned packages.\n")
    
    # Add typosquatting check results
    has_typosquatting = False
    for result in scan_results:
        name_similarity = result.get('name_similarity', {})
        if name_similarity and name_similarity.get('potential_typosquatting'):
            has_typosquatting = True
            break
    
    if has_typosquatting:
        report.append("## Typosquatting Concerns\n")
        report.append("⚠️ **Potential typosquatting detected**\n")
        report.append("The following packages have names similar to popular packages and may be typosquatting attempts:\n")
        
        for result in scan_results:
            name_similarity = result.get('name_similarity', {})
            if name_similarity and name_similarity.get('potential_typosquatting'):
                package_name = result.get('package')
                similar_to = [s.get('similar_to') for s in name_similarity.get('similar_packages', [])]
                risk = name_similarity.get('risk_level')
                
                report.append(f"* **{package_name}** ({risk} Risk)")
                report.append(f"  * Similar to: {', '.join(similar_to)}")
        
        report.append("\n**Recommendation**: Verify these packages are legitimate before using them.\n")
    
    # Add reputation concerns
    has_reputation_concerns = False
    for result in scan_results:
        reputation = result.get('reputation', {})
        risk_level = reputation.get('risk_level')
        
        if risk_level in ['High', 'Medium']:
            has_reputation_concerns = True
            break
    
    if has_reputation_concerns:
        report.append("## Package Reputation Concerns\n")
        report.append("⚠️ **Some packages have reputation concerns**\n")
        
        for result in scan_results:
            reputation = result.get('reputation', {})
            risk_level = reputation.get('risk_level')
            
            if risk_level in ['High', 'Medium']:
                package_name = result.get('package')
                
                report.append(f"* **{package_name}** ({risk_level} Risk)")
                
                suspicious = reputation.get('suspicious_patterns', [])
                if suspicious:
                    report.append(f"  * Suspicious patterns: {'; '.join(suspicious)}")
                
                package_age = reputation.get('package_age', 'Unknown')
                download_count = reputation.get('download_count', 'Unknown')
                
                report.append(f"  * Package age: {package_age}")
                report.append(f"  * Downloads: {download_count}")
        
        report.append("\n**Recommendation**: Review these packages carefully before use.\n")
    
    # Add detailed vulnerability information for each vulnerable package
    if vulnerable_packages:
        report.append("## Vulnerability Details\n")
        
        for result in vulnerable_packages:
            package_name = result.get('package')
            package_version = result.get('version')
            vulnerabilities = result.get('vulnerabilities', [])
            
            report.append(f"### {package_name} (version {package_version})\n")
            
            # Sort vulnerabilities by severity
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: severity_order.get(v.get('severity', 'Unknown'), 5)
            )
            
            for vuln in sorted_vulns:
                severity = vuln.get('severity', 'Unknown')
                vuln_id = vuln.get('cve_id') or vuln.get('id') or "No ID"
                
                # Use appropriate emoji based on severity
                if severity == 'Critical':
                    emoji = "🚨"
                elif severity == 'High':
                    emoji = "⚠️"
                elif severity == 'Medium':
                    emoji = "🔶"
                elif severity == 'Low':
                    emoji = "ℹ️"
                else:
                    emoji = "❓"
                
                report.append(f"#### {emoji} {vuln_id} ({severity})\n")
                
                # Add vulnerability details
                if 'summary' in vuln:
                    report.append(f"**Summary**: {vuln['summary']}\n")
                
                if 'details' in vuln and vuln['details']:
                    # Limit details to a reasonable length
                    details = vuln['details']
                    if len(details) > 500:
                        details = details[:497] + "..."
                    report.append(f"**Details**: {details}\n")
                
                # Add fixed versions if available
                fixed_versions = vuln.get('fixed_versions', [])
                if fixed_versions:
                    report.append(f"**Fixed in versions**: {', '.join(fixed_versions)}\n")
                
                # Add references if available
                references = vuln.get('references', [])
                if references:
                    report.append("**References**:")
                    for ref in references[:5]:  # Limit to 5 references
                        report.append(f"* {ref}")
                    if len(references) > 5:
                        report.append(f"* ... and {len(references) - 5} more")
                    report.append("")
            
            # Add remediation recommendations
            report.append("#### Remediation\n")
            
            # Check if there are fixed versions
            all_fixed_versions = []
            for vuln in vulnerabilities:
                fixed_vers = vuln.get('fixed_versions', [])
                all_fixed_versions.extend(fixed_vers)
            
            if all_fixed_versions:
                # Find the minimum fixed version
                try:
                    min_fixed_version = min(all_fixed_versions, key=lambda v: [int(x) for x in v.split('.')])
                    report.append(f"Upgrade to version **{min_fixed_version}** or later.\n")
                    report.append(f"```\npip install {package_name}>={min_fixed_version}\n```\n")
                except Exception:
                    report.append(f"Upgrade to the latest version of {package_name}.\n")
                    report.append(f"```\npip install --upgrade {package_name}\n```\n")
            else:
                report.append(f"Upgrade to the latest version of {package_name}.\n")
                report.append(f"```\npip install --upgrade {package_name}\n```\n")
    
    # Add dependency chain information if available
    has_dependency_results = False
    for result in scan_results:
        if 'dependencies' in result and result['dependencies']:
            has_dependency_results = True
            break
    
    if has_dependency_results:
        report.append("## Dependency Chain Analysis\n")
        
        for result in scan_results:
            if 'dependencies' in result and result['dependencies']:
                package_name = result.get('package')
                deps = result.get('dependencies')
                
                vulnerable_deps = deps.get('vulnerable_dependencies', {})
                total_deps = deps.get('total_dependencies', 0)
                
                report.append(f"### {package_name} Dependencies\n")
                report.append(f"* Total dependencies: **{total_deps}**")
                report.append(f"* Vulnerable dependencies: **{len(vulnerable_deps)}**")
                report.append(f"* Total vulnerabilities in dependencies: **{deps.get('total_vulnerability_count', 0)}**\n")
                
                if vulnerable_deps:
                    report.append("#### Vulnerable Dependencies\n")
                    
                    for dep_name, dep_info in vulnerable_deps.items():
                        path = ' → '.join(dep_info['path'] + [dep_name])
                        vuln_count = dep_info.get('vulnerability_count', 0)
                        
                        report.append(f"* **{dep_name}** (version {dep_info['version']})")
                        report.append(f"  * **{vuln_count}** vulnerabilities")
                        report.append(f"  * Path: {path}")
                    
                    report.append("\n**Note**: Transitive dependencies with vulnerabilities may still affect your application even if you don't use them directly.\n")
    
    # Add overall recommendations
    report.append("## Recommendations\n")
    
    if total_vulnerabilities > 0:
        report.append("1. **Update vulnerable packages** to the recommended versions\n")
        
        if critical > 0 or high > 0:
            report.append("2. **Prioritize critical and high-severity vulnerabilities**\n")
        
        if has_typosquatting:
            report.append("3. **Verify suspicious packages** to ensure they are legitimate\n")
        
        report.append("4. **Consider setting up automated security scanning** for your dependencies\n")
    else:
        report.append("1. **Continue regular scanning** of dependencies for new vulnerabilities\n")
        report.append("2. **Keep dependencies updated** to minimize security risks\n")
    
    # Add footer
    report.append("\n---\n")
    report.append("*This report was generated by the Python Dependency Security Assistant*")
    
    return "\n".join(report)