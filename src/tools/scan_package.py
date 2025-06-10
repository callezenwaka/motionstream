# src/tools/scan_ppackage.py

import requests
import re # Needed for severity parsing

from typing import Any, Optional, List, Dict
from smolagents.tools import Tool 
from src.utils.scanner import is_version_affected, get_severity_from_score

class ScanPackageTool(Tool):
    name = "scan_ppackage"
    description = "Scans a Python package for known security vulnerabilities using the OSV database."
    inputs = {
        'package_name': {
            'type': 'str',
            'description': 'The name of the Python package to scan (e.g., "requests").'
        },
        'package_version': {
            'type': 'str',
            'description': 'The specific version of the package to check (e.g., "2.31.0"). Optional.',
            'optional': True
        }
    }
    output_type = "list" # A list of vulnerability dictionaries

    def __init__(self, **kwargs):
        super().__init__()
        self.is_initialized = False # You might use this for setup if needed

    def forward(self, package_name: str, package_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Executes the vulnerability scan for a given Python package directly querying the OSV database.
        
        Args:
            package_name: The name of the package.
            package_version: The specific version to check (optional).
            
        Returns:
            A list of vulnerability dictionaries found for the package.
        """
        print(f"Agent executing scan_ppackage tool for {package_name} {package_version or ''}...")
        
        # If no version provided, try to get installed version (this logic is typically
        # for a CLI tool, agents usually get explicit info. Keep for robustness)
        if not package_version:
            try:
                import pkg_resources
                package_version = pkg_resources.get_distribution(package_name).version
                print(f"Determined installed version: {package_version}")
            except Exception:
                print(f"Could not determine installed version for {package_name}; proceeding without explicit version.")
        
        # --- Start of _query_osv_database logic, moved here ---
        vulnerabilities = []
        try:
            url = "https://api.osv.dev/v1/query"
            query_data = {
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                }
            }
            if package_version:
                query_data["version"] = package_version
            
            response = requests.post(url, json=query_data, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Deduplicate vulnerabilities and enrich
            unique_vulnerabilities = {}
            for vuln in data.get("vulns", []):
                key = vuln.get('id') # OSV ID is unique
                
                # Extract affected versions
                affected_versions = []
                fixed_versions = []
                for affected in vuln.get("affected", []):
                    if affected.get("package", {}).get("name") == package_name:
                        for affected_range in affected.get("ranges", []):
                            if affected_range.get("type") == "SEMVER":
                                for event in affected_range.get("events", []):
                                    if event.get("introduced"):
                                        affected_versions.append(f">={event.get('introduced')}")
                                    if event.get("fixed"):
                                        affected_versions.append(f"<{event.get('fixed')}")
                                        fixed_versions.append(event.get("fixed"))
                
                # If a specific package_version was provided, filter out vulnerabilities that don't affect it
                if package_version and not is_version_affected(package_version, affected_versions):
                    continue
                
                # Extract references
                references = [ref.get("url") for ref in vuln.get("references", [])]
                
                # Extract severity details (CVSS, etc.)
                severity_details = {}
                base_score = 0
                severity_level = "Unknown"
                
                for sev in vuln.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        severity_details["CVSS_V3_Vector"] = sev.get("score")
                        try:
                            match = re.search(r"(\d+\.\d+)$", sev.get("score", ""))
                            if match:
                                base_score = float(match.group(1))
                            else:
                                base_score = float(sev.get("score"))
                            severity_level = get_severity_from_score(base_score)
                        except ValueError:
                            pass
                    elif sev.get("type"):
                        severity_details[sev.get("type")] = sev.get("score")
                
                # Create vulnerability record
                vulnerability = {
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary"),
                    "details": vuln.get("details"),
                    "affected_versions": affected_versions,
                    "fixed_versions": list(set(fixed_versions)),
                    "references": references,
                    "published_date": vuln.get("published"),
                    "modified_date": vuln.get("modified"),
                    "source": "OSV",
                    "severity": severity_level,
                    "base_score": base_score,
                    "severity_details": severity_details
                }
                
                if key not in unique_vulnerabilities:
                    # Enrich severity if missing from OSV, using base_score if available
                    if 'severity' not in vulnerability and 'base_score' in vulnerability:
                        vulnerability['severity'] = get_severity_from_score(vulnerability['base_score'])
                    unique_vulnerabilities[key] = vulnerability
            
            # Sort vulnerabilities by severity (Critical first)
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4} # OSV uses uppercase severity
            sorted_vulnerabilities = sorted(
                list(unique_vulnerabilities.values()),
                key=lambda v: severity_order.get(v.get('severity', 'UNKNOWN').upper(), 5)
            )
            
            return sorted_vulnerabilities
        
        except requests.exceptions.RequestException as e:
            print(f"Error querying OSV database: {e}")
            return []
        except Exception as e:
            print(f"An unexpected error occurred while processing OSV data: {e}")
            return []
        # --- End of _query_osv_database logic ---