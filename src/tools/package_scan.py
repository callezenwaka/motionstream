# src/tools/package_scan.py

import re
import requests
from typing import Any, Optional, List, Dict
from smolagents.tools import Tool 

class PackageScanTool(Tool):
    name = "package_scan"
    description = "Scans specified Python packages for vulnerabilities using OSV batch API. Only scans the explicitly provided packages."
    
    inputs = {
        'packages': {
            'type': 'array',
            'description': 'List of package dictionaries with "name" and optionally "version" keys for batch scanning.',
        }
    }
    output_type = "array"

    def __init__(self, **kwargs):
        super().__init__()
        self.osv_batch_url = "https://api.osv.dev/v1/querybatch"

    def forward(self, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan multiple packages using OSV batch API.
        Automatically fetches latest version if not specified.
        """
        print(f"🚀 Batch scanning {len(packages)} packages...")
        
        try:
            # Build batch query with version resolution
            queries = []
            prepared_packages = []
            
            for pkg in packages:
                package_name = pkg.get("name")
                package_version = pkg.get("version")
                
                # Get latest version if not provided
                if not package_version:
                    try:
                        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
                        response.raise_for_status()
                        package_version = response.json().get("info", {}).get("version")
                        print(f"package_version: {package_version}")
                    except Exception:
                        print(f"⚠️ Could not fetch latest version for {package_name}")
                
                prepared_packages.append({"name": package_name, "version": package_version})
                
                # Build OSV query
                query = {
                    "package": {
                        "name": package_name,
                        "ecosystem": "PyPI"
                    }
                }
                if package_version:
                    query["version"] = package_version
                queries.append(query)
            
            # Execute batch request
            response = requests.post(self.osv_batch_url, json={"queries": queries}, timeout=30)
            response.raise_for_status()
            batch_results = response.json()
            
            # Process results
            vulnerabilities = []
            for i, result in enumerate(batch_results.get("results", [])):
                if i >= len(prepared_packages):
                    continue
                    
                pkg_info = prepared_packages[i]
                for vuln in result.get("vulns", []):
                    vulnerabilities.append({
                        "package": pkg_info["name"],
                        "package_version": pkg_info["version"],
                        "vulnerability_id": vuln.get("id"),
                        "modified_date": vuln.get("modified"),
                        "source": "OSV"
                    })
            
            print(f"✅ Found {len(vulnerabilities)} vulnerabilities across {len(packages)} packages")
            return vulnerabilities
            
        except Exception as e:
            print(f"❌ Batch scan failed: {e}")
            return []