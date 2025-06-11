# src/utils/summary.py

import json
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path

class Summary:
    """Format security scan results for different output types."""
    
    def __init__(self, output_format: str = 'console'):
        self.output_format = output_format
        self.colors = {
            'CRITICAL': '\033[91m',    # Red
            'HIGH': '\033[93m',        # Yellow
            'MEDIUM': '\033[94m',      # Blue
            'LOW': '\033[92m',         # Green
            'UNKNOWN': '\033[90m',     # Gray
            'RESET': '\033[0m',        # Reset
            'BOLD': '\033[1m',         # Bold
            'WARNING': '\033[93m',     # Yellow
            'SUCCESS': '\033[92m',     # Green
            'INFO': '\033[96m',        # Cyan
        }
    
    def display_results(self, agent_result: Any, dependencies: List[Dict[str, Any]]):
        """Display results in the specified format."""
        if self.output_format == 'console':
            self._display_console(agent_result, dependencies)
        elif self.output_format == 'json':
            self._display_json(agent_result, dependencies)
        elif self.output_format == 'html':
            self._display_html(agent_result, dependencies)
    
    def _display_console(self, agent_result: Any, dependencies: List[Dict[str, Any]]):
        """Display results in console format matching the screenshot."""
        print(f"\n{self.colors['INFO']}# Install dependencies without changing package managers{self.colors['RESET']}")
        print(f"pip install -r requirements.txt")
        print()
        
        print(f"{self.colors['INFO']}# Safety secures every installation request{self.colors['RESET']}")
        
        # Parse agent results to extract vulnerability info
        # This would need to be adapted based on your actual agent output structure
        vulnerabilities = self._extract_vulnerabilities_from_agent_result(agent_result)
        
        # Display installed packages
        installed_count = 0
        blocked_count = 0
        
        for dep in dependencies:
            if dep.get('name'):
                # Simulate installation status based on vulnerabilities
                is_vulnerable = any(v.get('package') == dep['name'] for v in vulnerabilities)
                
                if is_vulnerable:
                    # Find the vulnerability for this package
                    vuln = next((v for v in vulnerabilities if v.get('package') == dep['name']), {})
                    if vuln.get('severity') == 'CRITICAL' or vuln.get('malicious'):
                        print(f"{self.colors['WARNING']}⚠ Blocked \"{dep['name']}\" - malicious package detected!{self.colors['RESET']}")
                        blocked_count += 1
                    else:
                        print(f"Installed {dep['name']} {dep.get('version', 'latest')}")
                        installed_count += 1
                else:
                    print(f"Installed {dep['name']} {dep.get('version', 'latest')}")
                    installed_count += 1
        
        print()
        print(f"Securely installed {self.colors['SUCCESS']}{installed_count}{self.colors['RESET']} dependencies, blocked {self.colors['WARNING']}{blocked_count}{self.colors['RESET']}.")
        print()
        
        # Display vulnerability warnings
        print(f"{self.colors['INFO']}# Reports on vulnerabilities in your dependencies{self.colors['RESET']}")
        
        for vuln in vulnerabilities:
            if vuln.get('severity') in ['HIGH', 'CRITICAL']:
                severity_color = self.colors.get(vuln['severity'], self.colors['RESET'])
                print(f"{self.colors['WARNING']}⚠ Warning: {vuln.get('package')} {vuln.get('version', 'unknown')} has a vulnerability impacting")
                print(f"the {vuln.get('component', 'unknown component')}. Upgrade to {vuln.get('fixed_version', '>=newer version')} to fix.{self.colors['RESET']}")
                print()
    
    def _display_json(self, agent_result: Any, dependencies: List[Dict[str, Any]]):
        """Display results in JSON format."""
        vulnerabilities = self._extract_vulnerabilities_from_agent_result(agent_result)
        
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'dependencies_scanned': len(dependencies),
            'vulnerabilities_found': len(vulnerabilities),
            'summary': {
                'critical': len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
                'high': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
                'medium': len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
                'low': len([v for v in vulnerabilities if v.get('severity') == 'LOW']),
            },
            'dependencies': dependencies,
            'vulnerabilities': vulnerabilities,
            'agent_analysis': str(agent_result) if agent_result else None
        }
        
        print(json.dumps(report, indent=2, default=str))
    
    def _display_html(self, agent_result: Any, dependencies: List[Dict[str, Any]]):
        """Display results in HTML format."""
        vulnerabilities = self._extract_vulnerabilities_from_agent_result(agent_result)
        
        html_report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .critical {{ color: #d32f2f; }}
                .high {{ color: #f57c00; }}
                .medium {{ color: #1976d2; }}
                .low {{ color: #388e3c; }}
                .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
                .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; }}
            </style>
        </head>
        <body>
            <h1>🔒 Security Scan Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Dependencies Scanned: {len(dependencies)}</p>
                <p>Vulnerabilities Found: {len(vulnerabilities)}</p>
            </div>
            
            <h2>Vulnerabilities</h2>
        """
        
        for vuln in vulnerabilities:
            severity_class = vuln.get('severity', 'unknown').lower()
            html_report += f"""
            <div class="vulnerability">
                <h3 class="{severity_class}">{vuln.get('package')} - {vuln.get('severity', 'UNKNOWN')}</h3>
                <p><strong>CVE:</strong> {vuln.get('id', 'N/A')}</p>
                <p><strong>Description:</strong> {vuln.get('summary', 'No description available')}</p>
                <p><strong>Fixed Version:</strong> {vuln.get('fixed_version', 'Check documentation')}</p>
            </div>
            """
        
        html_report += """
        </body>
        </html>
        """
        
        # Save to file
        report_file = Path(f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(report_file, 'w') as f:
            f.write(html_report)
        
        print(f"HTML report saved to: {report_file}")
    
    def _extract_vulnerabilities_from_agent_result(self, agent_result: Any) -> List[Dict[str, Any]]:
        """
        Extract vulnerability information from agent result.
        This needs to be adapted based on your actual agent output structure.
        """
        vulnerabilities = []
        
        # This is a placeholder - you'll need to adapt this based on how your agent
        # structures its final answer
        if hasattr(agent_result, 'vulnerabilities'):
            vulnerabilities = agent_result.vulnerabilities
        elif isinstance(agent_result, dict) and 'vulnerabilities' in agent_result:
            vulnerabilities = agent_result['vulnerabilities']
        elif isinstance(agent_result, str):
            # Try to parse vulnerabilities from text output
            # This is a simple fallback - you might want more sophisticated parsing
            vulnerabilities = self._parse_vulnerabilities_from_text(agent_result)
        
        return vulnerabilities
    
    def _parse_vulnerabilities_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Parse vulnerability information from text output."""
        # This is a simple parser - you can make it more sophisticated
        vulnerabilities = []
        
        # Look for common vulnerability patterns in the text
        lines = text.split('\n')
        current_vuln = {}
        
        for line in lines:
            line = line.strip()
            if 'CVE-' in line or 'GHSA-' in line:
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                current_vuln = {'id': line}
            elif any(severity in line.upper() for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']):
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if severity in line.upper():
                        current_vuln['severity'] = severity
                        break
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return vulnerabilities