# tools/package_reputation.py
import requests
import time
from datetime import datetime, timedelta

def check_package_reputation(package_name):
    """
    Check the reputation and trustworthiness of a package.
    
    Args:
        package_name: Name of the package to check
        
    Returns:
        Dictionary with reputation analysis
    """
    # Get package info from PyPI
    pypi_info = get_pypi_info(package_name)
    
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
        "package_age": calculate_package_age(release_dates),
        "release_frequency": calculate_release_frequency(release_dates),
        "has_documentation": bool(pypi_info.get("docs_url") or "docs" in project_urls),
        "has_source_repository": bool(github_url),
        "download_count": get_download_count(package_name)
    }
    
    # Add GitHub metrics if available
    if github_url:
        github_metrics = get_github_metrics(github_url)
        metrics.update(github_metrics)
    
    # Analyze package for suspicious patterns
    suspicious_patterns = check_suspicious_patterns(pypi_info, metrics)
    
    # Calculate overall reputation score
    score = calculate_reputation_score(metrics, suspicious_patterns)
    
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
        "risk_level": get_risk_level(score, suspicious_patterns)
    }

def get_pypi_info(package_name):
    """Get package information from PyPI."""
    try:
        response = requests.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("info", {})
        return None
    except Exception:
        return None

def calculate_package_age(release_dates):
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

def calculate_release_frequency(release_dates):
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

def get_download_count(package_name):
    """Get download statistics for a package."""
    try:
        # Try to get download count from PyPI Stats
        response = requests.get(
            f"https://pypistats.org/api/packages/{package_name}/recent",
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("last_month", 0)
    except Exception:
        pass
    
    return "Unknown"

def get_github_metrics(github_url):
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
        response = requests.get(api_url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            return {
                "stars": data.get("stargazers_count", 0),
                "forks": data.get("forks_count", 0),
                "issues": data.get("open_issues_count", 0),
                "contributors": get_contributor_count(owner_repo)
            }
    except Exception:
        pass
    
    return {}

def get_contributor_count(owner_repo):
    """Get the number of contributors to a GitHub repository."""
    try:
        api_url = f"https://api.github.com/repos/{owner_repo}/contributors?per_page=1&anon=true"
        response = requests.get(api_url, timeout=5)
        
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

def check_suspicious_patterns(pypi_info, metrics):
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

def calculate_reputation_score(metrics, suspicious_patterns):
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

def get_risk_level(score, suspicious_patterns):
    """Determine risk level based on reputation score and suspicious patterns."""
    if score < 3 or len(suspicious_patterns) > 2:
        return "High"
    elif score < 6 or len(suspicious_patterns) > 0:
        return "Medium"
    else:
        return "Low"