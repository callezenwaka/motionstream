# src/tools/pypi_tool.py

import requests
from typing import Any, Dict
from smolagents.tools import Tool 

class PypiTool(Tool):
    name = "pypi_tool"
    description = "Fetches basic package information from PyPI (name, version, summary, author, license)."
    inputs = {
        'package_name': {
            'type': 'string',
            'description': 'The name of the Python package to fetch details for (e.g., "requests").'
        }
    }
    output_type = "object" # A dictionary containing basic PyPI details

    def __init__(self, **kwargs):
        super().__init__()
        self.is_initialized = False

    def forward(self, package_name: str) -> Dict[str, Any]:
        """
        Fetches basic package information from PyPI (excludes dependency information).
        
        Args:
            package_name: The name of the package to fetch details for.
            
        Returns:
            A dictionary containing basic PyPI details (no dependencies).
        """
        print(f"Agent executing pypi_tool tool for: {package_name}")
        
        try:
            response = requests.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            # Extract only basic info (no dependency-related fields)
            info = data.get("info", {})
            
            return {
                "name": info.get("name", ""),
                "version": info.get("version", ""),
                "summary": info.get("summary", ""),
                "author": info.get("author", ""),
                "author_email": info.get("author_email", ""),
                "license": info.get("license", ""),
                "home_page": info.get("home_page", ""),
                "project_urls": info.get("project_urls", {}),
                "requires_python": info.get("requires_python", ""),
                "classifiers": info.get("classifiers", []),
                "package_url": f"https://pypi.org/project/{package_name}/"
            }
        except requests.exceptions.RequestException as e:
            print(f"Error fetching PyPI info for {package_name}: {e}")
            return {
                "package_name": package_name,
                "note": "Package not found on PyPI or error fetching information."
            }