# src/tools/package_scan.py

import re
import requests

from typing import Any, Optional, List, Dict
from smolagents.tools import Tool 
# from src.utils.scanner import is_version_affected, get_severity_from_score

class PackageScanTool(Tool):
    name = "package_scan"
    description = "Scans Python packages for vulnerabilities using OSV batch API. Perfect for scanning requirements.txt or environment.yml files."
    
    inputs = {
        'packages': {
            'type': 'array',  # ✅ Fixed: changed from 'list' to 'array'
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
        Simple and efficient for PoC requirements.
        """
        print(f"🚀 Batch scanning {len(packages)} packages...")
        
        try:
            # Build batch query
            queries = []
            for pkg in packages:
                query = {
                    "package": {
                        "name": pkg.get("name"),
                        "ecosystem": "PyPI"
                    }
                }
                if pkg.get("version"):
                    query["version"] = pkg.get("version")
                queries.append(query)
            
            # Execute batch request
            response = requests.post(
                self.osv_batch_url, 
                json={"queries": queries}, 
                timeout=30
            )
            response.raise_for_status()
            batch_results = response.json()
            
            # Process results
            vulnerabilities = []
            results = batch_results.get("results", [])
            
            for i, result in enumerate(results):
                if i >= len(packages):
                    continue
                    
                package_name = packages[i]["name"]
                package_version = packages[i].get("version")
                
                # Add each vulnerability found
                for vuln in result.get("vulns", []):
                    vulnerabilities.append({
                        "package": package_name,
                        "package_version": package_version,
                        "vulnerability_id": vuln.get("id"),
                        "modified_date": vuln.get("modified"),
                        "source": "OSV"
                    })
            
            print(f"✅ Found {len(vulnerabilities)} vulnerabilities across {len(packages)} packages")
            return vulnerabilities
            
        except Exception as e:
            print(f"❌ Batch scan failed: {e}")
            return []
        