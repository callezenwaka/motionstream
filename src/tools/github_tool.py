# src/tools/github_tool.py

import requests
import re
from typing import Any, Dict
from smolagents.tools import Tool

class GithubTool(Tool):
    name = "github_tool"
    description = "Fetches basic detailed information about a GitHub repository from its main API endpoint."
    inputs = {
        'github_url': {
            'type': 'string',
            'description': 'The URL of the GitHub repository (e.g., "https://github.com/owner/repo").'
        }
    }
    output_type = "object" # A dictionary containing core GitHub repository details

    def __init__(self, **kwargs):
        super().__init__()
        self.is_initialized = False # You might use this for setup if needed

    def forward(self, github_url: str) -> Dict[str, Any]:
        """
        Executes the fetching of basic detailed information about a GitHub repository.
        
        Args:
            github_url: The URL of the GitHub repository.
            
        Returns:
            A dictionary containing core GitHub repository details.
        """
        print(f"Agent executing github_tool tool for: {github_url}")
        
        # Extract owner/repo directly from the URL
        owner_repo = None
        parts = github_url.split('github.com/')
        if len(parts) > 1:
            owner_repo = parts[1].strip('/')
            if not (owner_repo and '/' in owner_repo and owner_repo.count('/') == 1): # Ensure 'owner/repo' format
                owner_repo = None
            
        if not owner_repo:
            return {
                "url": github_url,
                "note": "Invalid GitHub URL format provided. Expected format: https://github.com/owner/repo."
            }
        
        try:
            api_url = f"https://api.github.com/repos/{owner_repo}"
            response = requests.get(api_url, timeout=5)
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            data = response.json()
            
            return {
                "name": data.get("name"),
                "full_name": data.get("full_name"),
                "description": data.get("description"),
                "stargazers_count": data.get("stargazers_count"),
                "forks_count": data.get("forks_count"),
                "open_issues_count": data.get("open_issues_count"),
                "created_at": data.get("created_at"),
                "updated_at": data.get("updated_at"),
                "license": data.get("license", {}).get("spdx_id") if data.get("license") else None,
                "default_branch": data.get("default_branch"),
                "language": data.get("language"),
                "html_url": data.get("html_url") # Direct link to the repo
            }
        except requests.exceptions.RequestException as e:
            print(f"Error fetching GitHub repo info for {owner_repo}: {e}")
            return {
                "url": github_url,
                "owner_repo": owner_repo,
                "note": f"Could not retrieve repository details. Error: {e}. It might not exist or there's an API issue."
            }