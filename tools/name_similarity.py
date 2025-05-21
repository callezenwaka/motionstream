# tools/name_similarity.py
import requests
from difflib import SequenceMatcher

# Cache of popular packages
POPULAR_PACKAGES = None

def check_name_similarity(package_name):
    """
    Check if a package name is suspiciously similar to a popular package.
    This helps detect typosquatting attacks.
    
    Args:
        package_name: Name of the package to check
        
    Returns:
        Dictionary with similarity analysis
    """
    global POPULAR_PACKAGES
    
    # Load popular packages if not already loaded
    if POPULAR_PACKAGES is None:
        POPULAR_PACKAGES = get_popular_packages()
    
    results = []
    
    # Check for similarity with popular packages
    for popular_pkg in POPULAR_PACKAGES:
        similarity = SequenceMatcher(None, package_name.lower(), popular_pkg.lower()).ratio()
        
        # If names are similar but not identical
        if similarity > 0.7 and similarity < 1.0:
            results.append({
                "similar_to": popular_pkg,
                "similarity_score": similarity,
                "risk_level": "High" if similarity > 0.9 else "Medium"
            })
    
    # Check for keyboard adjacency typos (e.g., reqeusts vs requests)
    keyboard_adjacency = check_keyboard_adjacency(package_name)
    if keyboard_adjacency:
        results.append(keyboard_adjacency)
    
    return {
        "potential_typosquatting": len(results) > 0,
        "similar_packages": results,
        "risk_level": get_risk_level(results)
    }

def get_popular_packages(limit=100):
    """Get a list of popular Python packages."""
    try:
        # PyPI Stats API to get popular packages
        response = requests.get(
            "https://pypistats.org/top",
            headers={"Accept": "application/json"},
            timeout=5
        )
        data = response.json()
        return [pkg["project"] for pkg in data["rows"][:limit]]
    except Exception:
        # Fallback to a static list of common packages
        return [
            "requests", "numpy", "pandas", "matplotlib", "django", "flask",
            "tensorflow", "torch", "scipy", "scikit-learn", "pillow",
            "beautifulsoup4", "pytest", "selenium", "sqlalchemy", "psycopg2",
            "pymongo", "redis", "cryptography", "pyyaml", "six", "urllib3",
            "pytest", "tqdm", "nltk", "celery", "jupyter", "sphinx", "black",
            "pylint", "boto3", "fastapi", "streamlit", "gunicorn", "click",
            "jinja2", "aiohttp", "asyncio", "dash", "httpx", "rich"
        ]

def check_keyboard_adjacency(package_name):
    """Check for keyboard adjacency typos in package name."""
    # Common keyboard adjacency patterns
    adjacent_keys = {
        'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'erfcxs',
        'e': 'rdsw', 'f': 'rtgvdc', 'g': 'tyhbvf', 'h': 'yujnbg',
        'i': 'uojk', 'j': 'uikmnh', 'k': 'iolmj', 'l': 'opk',
        'm': 'njk', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol',
        'q': 'asw', 'r': 'etdf', 's': 'wedazx', 't': 'ryfg',
        'u': 'yihj', 'v': 'cfgb', 'w': 'qeasd', 'x': 'zsdc',
        'y': 'tugh', 'z': 'asx'
    }
    
    # Get popular packages again (this is inefficient but simple for the example)
    popular_packages = get_popular_packages()
    
    for popular_pkg in popular_packages:
        if len(package_name) == len(popular_pkg) and package_name != popular_pkg:
            # Count differences that could be typos
            typo_count = 0
            typo_positions = []
            
            for i, (c1, c2) in enumerate(zip(package_name.lower(), popular_pkg.lower())):
                if c1 != c2:
                    # Check if these characters are adjacent on keyboard
                    if c2 in adjacent_keys.get(c1, '') or c1 in adjacent_keys.get(c2, ''):
                        typo_count += 1
                        typo_positions.append(i)
            
            # If package looks like a typo of a popular package
            if 0 < typo_count <= 2:  # Allow up to 2 potential typos
                return {
                    "similar_to": popular_pkg,
                    "similarity_score": 0.9,  # High similarity for keyboard typos
                    "risk_level": "High",
                    "typo_positions": typo_positions,
                    "typo_type": "keyboard_adjacency"
                }
    
    return None

def get_risk_level(results):
    """Determine overall risk level based on similarity results."""
    if not results:
        return "Low"
    
    # Check if any high-risk matches
    if any(r["risk_level"] == "High" for r in results):
        return "High"
    
    # Check if multiple medium-risk matches
    if len([r for r in results if r["risk_level"] == "Medium"]) > 1:
        return "High"
    
    # Default to medium if we have any results
    return "Medium"