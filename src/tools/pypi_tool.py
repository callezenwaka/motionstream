# src/tools/pypi_tool.py

import requests
from typing import Any, Dict
from smolagents.tools import Tool 

class PypiTool(Tool):
    name = "pypi_tool"
    description = "Fetches detailed general information about a Python package from PyPI."
    inputs = {
        'package_name': {
            'type': 'str',
            'description': 'The name of the Python package to fetch details for (e.g., "requests").'
        }
    }
    output_type = "dict" # A dictionary containing PyPI details

    def __init__(self, **kwargs):
        super().__init__()
        self.is_initialized = False # You might use this for setup if needed

    def forward(self, package_name: str) -> Dict[str, Any]:
        """
        Executes the fetching of detailed general information about a package from PyPI.
        
        Args:
            package_name: The name of the package to fetch details for.
            
        Returns:
            A dictionary containing PyPI details.
        """
        print(f"Agent executing pypi_tool tool for: {package_name}")
        
        try:
            response = requests.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=5
            )
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            data = response.json()
            
            # Extract relevant info from the 'info' key
            info = data.get("info", {})
            
            return {
                "name": info.get("name"),
                "version": info.get("version"),
                "summary": info.get("summary"),
                "description": info.get("description"),
                "author": info.get("author"),
                "author_email": info.get("author_email"),
                "license": info.get("license"),
                "home_page": info.get("home_page"),
                "project_urls": info.get("project_urls"),
                "requires_python": info.get("requires_python"),
                "classifiers": info.get("classifiers"),
                "last_serial": info.get("last_serial"), # This is PyPI's internal ID for the release
                "package_url": f"https://pypi.org/project/{package_name}/"
            }
        except requests.exceptions.RequestException as e:
            print(f"Error fetching general PyPI info for {package_name}: {e}")
            return {
                "package_name": package_name,
                "note": "Package not found on PyPI or error fetching information."
            }