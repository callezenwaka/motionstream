# tools/package_reputation.py
from typing import Any, Optional, List, Dict
from smolagents.tools import Tool
import requests
import time
from datetime import datetime, timedelta

class ReputationTool(Tool):
    name = "package_reputation"
    description = "Analyzes the reputation and trustworthiness of a Python package by checking PyPI metadata, GitHub metrics, download statistics, and security advisories. Returns a comprehensive reputation assessment with risk level."
    inputs = {
        'package_name': {'type': 'string', 'description': 'The name of the Python package to scan for vulnerabilities.'},
        'package_version': {'type': 'string', 'description': 'Optional specific version to check. If not provided, will attempt to detect installed version.', 'required': False, 'nullable': True}
    }
    output_type = "string"

    def __init__(self, **kwargs):
        super().__init__()
        
        # Check required dependencies
        try:
            import requests
            from datetime import datetime
        except ImportError as e:
            raise ImportError(
                "You must install package `requests` to run this tool: run `pip install requests`."
            ) from e
            
        # Initialize session for API requests
        self.session = requests.Session()
        self.session.timeout = 10

    def forward(self, package_name: str, package_version: Optional[str] = None) -> str:
        """
        Analyze package reputation and security advisories.
        
        Args:
            package_name: Name of the package to analyze
            package_version: Specific version to check for security advisories (optional)
            
        Returns:
            Formatted string with reputation analysis and security advisories
        """
        try:
            # Get reputation analysis
            reputation = self._check_package_reputation(package_name)
            
            # Get PyPI security advisories
            advisories = self._check_pypi_advisories(package_name, package_version)
            
            return self._format_results(package_name, package_version, reputation, advisories)
        except Exception as e:
            return f"Error analyzing {package_name}: {str(e)}"

    def _check_package_reputation(self, package_name: str) -> Dict:
        """Check the reputation and trustworthiness of a package."""
        # Get package info from PyPI
        pypi_info = self._get_pypi_info(package_name)
        
        if not pypi_info:
            return {
                "error": "Package not found on PyPI",
                "risk_level": "Unknown"
            }
        
        # Extract key reputation indicators
        author = pypi_info.get("author", "Unknown")
        author_email = pypi_info.get("author_email", "Unknown")
        home_page = pypi_info.get("home_page", "")
        project_urls = pypi_info.get("project_urls", {})
        github_url = None
        
        # Try to find GitHub URL
        if project_urls:
            for url_type, url in project_urls.items():
                if "github.com" in url:
                    github_url = url
                    break
        
        if not github_url and home_page and "github.com" in home_page:
            github_url = home_page
        
        # Get release history
        releases = pypi_info.get("releases", {})
        release_dates = []
        
        for version, release_info in releases.items():
            if release_info:
                upload_time = release_info[0].get("upload_time", "")
                if upload_time:
                    release_dates.append(upload_time)
        
        # Sort release dates (newest first)
        release_dates.sort(reverse=True)
        
        # Calculate reputation metrics
        metrics = {
            "package_age": self._calculate_package_age(release_dates),
            "release_frequency": self._calculate_release_frequency(release_dates),
            "has_documentation": bool(pypi_info.get("docs_url") or "docs" in project_urls),
            "has_source_repository": bool(github_url),
            "download_count": self._get_download_count(package_name)
        }
        
        # Add GitHub metrics if available
        if github_url:
            github_metrics = self._get_github_metrics(github_url)
            metrics.update(github_metrics)
        
        # Analyze package for suspicious patterns
        suspicious_patterns = self._check_suspicious_patterns(pypi_info, metrics)
        
        # Calculate overall reputation score
        score = self._calculate_reputation_score(metrics, suspicious_patterns)
        
        return {
            "package": package_name,
            "author": author,
            "author_email": author_email,
            "package_age": metrics["package_age"],
            "release_frequency": metrics["release_frequency"],
            "download_count": metrics["download_count"],
            "has_documentation": metrics["has_documentation"],
            "has_source_repository": metrics["has_source_repository"],
            "github_stars": metrics.get("stars", "Unknown"),
            "github_forks": metrics.get("forks", "Unknown"),
            "github_contributors": metrics.get("contributors", "Unknown"),
            "suspicious_patterns": suspicious_patterns,
            "reputation_score": score,
            "risk_level": self._get_risk_level(score, suspicious_patterns)
        }

    def _check_pypi_advisories(self, package_name: str, package_version: str = None) -> List[Dict]:
        """Check PyPI for security advisories."""
        vulnerabilities = []
        
        try:
            # Get package information from PyPI
            url = f"https://pypi.org/pypi/{package_name}/json"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Check release history for security advisories
            if package_version:
                try:
                    from packaging import version
                    current_version = version.parse(package_version)
                    releases = data.get("releases", {})
                    
                    # Look for security fixes in newer versions
                    for rel_version, rel_files in releases.items():
                        try:
                            # Skip older or current versions
                            if version.parse(rel_version) <= current_version:
                                continue
                            
                            # Look for security-related comments in release files
                            for rel_file in rel_files:
                                comment = rel_file.get("comment_text", "").lower()
                                has_security_terms = any(term in comment for term in 
                                                        ["security", "vulnerability", "cve", "fix", "issue"])
                                
                                if has_security_terms:
                                    # Found a potential security fix
                                    vulnerability = {
                                        "id": f"PYPI-{package_name}-{rel_version}",
                                        "summary": f"Potential security fix in version {rel_version}",
                                        "details": comment,
                                        "fixed_versions": [rel_version],
                                        "source": "PyPI",
                                        "severity": "Unknown"  # Can't determine from PyPI alone
                                    }
                                    vulnerabilities.append(vulnerability)
                                    break
                        except Exception:
                            # Skip versions that can't be parsed
                            continue
                except ImportError:
                    # packaging not available, skip version comparison
                    pass
        
        except Exception as e:
            print(f"Error checking PyPI advisories: {e}")
        
        return vulnerabilities

    def _get_pypi_info(self, package_name: str) -> Optional[Dict]:
        """Get package information from PyPI."""
        try:
            response = self.session.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("info", {})
            return None
        except Exception:
            return None

    def _calculate_package_age(self, release_dates: List[str]) -> str:
        """Calculate the age of a package based on its first release."""
        if not release_dates:
            return "Unknown"
        
        try:
            # Get the oldest release date
            oldest_date = min(datetime.fromisoformat(date.replace("Z", "+00:00")) 
                             for date in release_dates)
            
            # Calculate age
            age_days = (datetime.now(oldest_date.tzinfo) - oldest_date).days
            
            if age_days < 30:
                return f"{age_days} days (Very New)"
            elif age_days < 90:
                return f"{age_days} days (New)"
            elif age_days < 365:
                return f"{age_days} days (Established)"
            else:
                years = age_days // 365
                return f"{years} years (Mature)"
        except Exception:
            return "Unknown"

    def _calculate_release_frequency(self, release_dates: List[str]) -> str:
        """Calculate the frequency of releases."""
        if len(release_dates) < 2:
            return "Insufficient data"
        
        try:
            # Parse dates
            dates = [datetime.fromisoformat(date.replace("Z", "+00:00")) 
                     for date in release_dates]
            dates.sort()
            
            # Calculate average time between releases
            time_diffs = [(dates[i] - dates[i-1]).days for i in range(1, len(dates))]
            avg_days = sum(time_diffs) / len(time_diffs)
            
            if avg_days < 7:
                return "Very frequent (less than weekly)"
            elif avg_days < 30:
                return "Frequent (about monthly)"
            elif avg_days < 90:
                return "Regular (about quarterly)"
            else:
                return "Infrequent (more than quarterly)"
        except Exception:
            return "Calculation error"

    def _get_download_count(self, package_name: str):
        """Get download statistics for a package."""
        try:
            # Try to get download count from PyPI Stats
            response = self.session.get(
                f"https://pypistats.org/api/packages/{package_name}/recent",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("data", {}).get("last_month", 0)
        except Exception:
            pass
        
        return "Unknown"

    def _get_github_metrics(self, github_url: str) -> Dict:
        """Get metrics from GitHub repository."""
        # Extract owner and repo from GitHub URL
        parts = github_url.split('github.com/')
        if len(parts) < 2:
            return {}
        
        owner_repo = parts[1].strip('/')
        if not owner_repo:
            return {}
        
        try:
            # Get repository info from GitHub API
            api_url = f"https://api.github.com/repos/{owner_repo}"
            response = self.session.get(api_url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "stars": data.get("stargazers_count", 0),
                    "forks": data.get("forks_count", 0),
                    "issues": data.get("open_issues_count", 0),
                    "contributors": self._get_contributor_count(owner_repo)
                }
        except Exception:
            pass
        
        return {}

    def _get_contributor_count(self, owner_repo: str):
        """Get the number of contributors to a GitHub repository."""
        try:
            api_url = f"https://api.github.com/repos/{owner_repo}/contributors?per_page=1&anon=true"
            response = self.session.get(api_url, timeout=5)
            
            if response.status_code == 200:
                # Get contributor count from Link header
                link_header = response.headers.get('Link', '')
                if 'rel="last"' in link_header:
                    last_page = link_header.split('page=')[-1].split('>')[0]
                    return int(last_page)
                else:
                    # Count contributors in the response
                    return len(response.json())
        except Exception:
            pass
        
        return "Unknown"

    def _check_suspicious_patterns(self, pypi_info: Dict, metrics: Dict) -> List[str]:
        """Check for suspicious patterns that might indicate malicious packages."""
        suspicious = []
        
        # Check if package is very new (less than 30 days)
        if isinstance(metrics["package_age"], str) and "days" in metrics["package_age"]:
            try:
                days = int(metrics["package_age"].split(" ")[0])
                if days < 30:
                    suspicious.append("Very new package (less than 30 days old)")
            except Exception:
                pass
        
        # Check for minimal or missing description
        description = pypi_info.get("description", "")
        if not description or len(description) < 100:
            suspicious.append("Minimal or missing package description")
        
        # Check for missing home page or repository
        if not pypi_info.get("home_page") and not pypi_info.get("project_urls"):
            suspicious.append("No homepage or repository links")
        
        # Check for minimal or missing classifiers
        classifiers = pypi_info.get("classifiers", [])
        if len(classifiers) < 3:
            suspicious.append("Few or no classifiers specified")
        
        # Check for very few releases
        releases = pypi_info.get("releases", {})
        if len(releases) < 2:
            suspicious.append("Very few releases (potential one-off package)")
        
        # Check for low GitHub metrics if available
        if "stars" in metrics and metrics["stars"] < 5:
            suspicious.append("Very few GitHub stars")
        
        if "contributors" in metrics and metrics["contributors"] == 1:
            suspicious.append("Single contributor repository")
        
        return suspicious

    def _calculate_reputation_score(self, metrics: Dict, suspicious_patterns: List[str]) -> int:
        """Calculate a simple reputation score based on metrics."""
        score = 0
        
        # Add points for package age
        if isinstance(metrics["package_age"], str):
            if "Very New" in metrics["package_age"]:
                score += 0
            elif "New" in metrics["package_age"]:
                score += 1
            elif "Established" in metrics["package_age"]:
                score += 2
            elif "Mature" in metrics["package_age"]:
                score += 3
        
        # Add points for downloads
        if isinstance(metrics["download_count"], int):
            if metrics["download_count"] > 1000000:
                score += 3
            elif metrics["download_count"] > 100000:
                score += 2
            elif metrics["download_count"] > 10000:
                score += 1
        
        # Add points for documentation and source repository
        if metrics["has_documentation"]:
            score += 1
        if metrics["has_source_repository"]:
            score += 1
        
        # Add points for GitHub metrics
        if "stars" in metrics:
            if metrics["stars"] > 1000:
                score += 3
            elif metrics["stars"] > 100:
                score += 2
            elif metrics["stars"] > 10:
                score += 1
        
        if "contributors" in metrics and isinstance(metrics["contributors"], int):
            if metrics["contributors"] > 10:
                score += 2
            elif metrics["contributors"] > 3:
                score += 1
        
        # Subtract points for suspicious patterns
        score -= len(suspicious_patterns)
        
        # Ensure score is within bounds
        return max(0, min(score, 10))

    def _get_risk_level(self, score: int, suspicious_patterns: List[str]) -> str:
        """Determine risk level based on reputation score and suspicious patterns."""
        if score < 3 or len(suspicious_patterns) > 2:
            return "High"
        elif score < 6 or len(suspicious_patterns) > 0:
            return "Medium"
        else:
            return "Low"

    def _format_results(self, package_name: str, package_version: Optional[str], 
                       reputation: Dict, advisories: List[Dict]) -> str:
        """Format reputation analysis and security advisories into a readable string."""
        if reputation.get("error"):
            return f"❌ **Error:** {reputation['error']}"
        
        # Build header
        version_info = f" version {package_version}" if package_version else ""
        result = f"📊 **Package Reputation Analysis for {package_name}{version_info}**\n\n"
        
        # Risk level with emoji
        risk_level = reputation.get("risk_level", "Unknown")
        risk_emoji = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}.get(risk_level, "⚪")
        result += f"**Overall Risk Level:** {risk_emoji} {risk_level}\n"
        result += f"**Reputation Score:** {reputation.get('reputation_score', 'Unknown')}/10\n\n"
        
        # Basic package info
        result += "## 📦 Package Information\n\n"
        result += f"**Author:** {reputation.get('author', 'Unknown')}\n"
        if reputation.get('author_email') != "Unknown":
            result += f"**Author Email:** {reputation.get('author_email')}\n"
        result += f"**Package Age:** {reputation.get('package_age', 'Unknown')}\n"
        result += f"**Release Frequency:** {reputation.get('release_frequency', 'Unknown')}\n"
        
        # Download and popularity metrics
        result += "\n## 📈 Popularity Metrics\n\n"
        downloads = reputation.get('download_count', 'Unknown')
        if isinstance(downloads, int):
            result += f"**Monthly Downloads:** {downloads:,}\n"
        else:
            result += f"**Monthly Downloads:** {downloads}\n"
        
        github_stars = reputation.get('github_stars', 'Unknown')
        if isinstance(github_stars, int):
            result += f"**GitHub Stars:** {github_stars:,}\n"
        else:
            result += f"**GitHub Stars:** {github_stars}\n"
        
        github_forks = reputation.get('github_forks', 'Unknown')
        if isinstance(github_forks, int):
            result += f"**GitHub Forks:** {github_forks:,}\n"
        else:
            result += f"**GitHub Forks:** {github_forks}\n"
        
        result += f"**Contributors:** {reputation.get('github_contributors', 'Unknown')}\n"
        
        # Quality indicators
        result += "\n## ✅ Quality Indicators\n\n"
        result += f"**Has Documentation:** {'✓' if reputation.get('has_documentation') else '✗'}\n"
        result += f"**Has Source Repository:** {'✓' if reputation.get('has_source_repository') else '✗'}\n"
        
        # Suspicious patterns
        suspicious_patterns = reputation.get('suspicious_patterns', [])
        if suspicious_patterns:
            result += "\n## ⚠️ Suspicious Patterns\n\n"
            for pattern in suspicious_patterns:
                result += f"- {pattern}\n"
        else:
            result += "\n## ✅ No Suspicious Patterns Detected\n\n"
        
        # PyPI Security Advisories
        if advisories:
            result += f"\n## 🔒 PyPI Security Advisories ({len(advisories)} found)\n\n"
            for i, advisory in enumerate(advisories, 1):
                result += f"### {i}. {advisory.get('id', 'Unknown ID')}\n\n"
                result += f"**Summary:** {advisory.get('summary', 'No summary')}\n\n"
                if advisory.get('details'):
                    result += f"**Details:** {advisory['details']}\n\n"
                if advisory.get('fixed_versions'):
                    result += f"**Fixed In:** {', '.join(advisory['fixed_versions'])}\n\n"
                result += "---\n\n"
        elif package_version:
            result += "\n## ✅ No PyPI Security Advisories Found\n\n"
        
        # Recommendations
        result += "## 💡 Recommendations\n\n"
        if risk_level == "High":
            result += "- **⚠️ High Risk:** Consider using an alternative package or thoroughly review the code before use\n"
        elif risk_level == "Medium":
            result += "- **⚠️ Medium Risk:** Review package carefully and monitor for updates\n"
        else:
            result += "- **✅ Low Risk:** Package appears trustworthy based on available metrics\n"
        
        if suspicious_patterns:
            result += "- Address the suspicious patterns identified above\n"
        
        if advisories:
            result += f"- Update to the latest version to address {len(advisories)} potential security issues\n"
        
        return result