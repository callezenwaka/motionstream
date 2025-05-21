# tools/dependency_parser.py
import os
import re
import yaml
import json
import toml
from pathlib import Path

def parse_dependency_file(file_path, include_dev=False):
    """
    Parse a dependency file to extract package names and versions.
    
    Args:
        file_path: Path to dependency file
        include_dev: Whether to include development dependencies
        
    Returns:
        List of (package_name, version) tuples
    """
    file_path = Path(file_path)
    file_name = file_path.name.lower()
    file_extension = file_path.suffix.lower()
    
    # Determine the file type
    if file_name == "requirements.txt" or file_extension == ".txt":
        return parse_requirements_txt(file_path)
    elif file_name == "pipfile" or file_name == "pipfile.lock":
        return parse_pipfile(file_path, include_dev)
    elif file_name == "poetry.lock" or (file_name == "pyproject.toml" and is_poetry_file(file_path)):
        return parse_poetry_file(file_path, include_dev)
    elif file_extension in [".yml", ".yaml"]:
        return parse_conda_environment(file_path)
    elif file_name == "package.json":
        return parse_package_json(file_path, include_dev)
    elif file_name == "setup.py" or file_name == "setup.cfg":
        return parse_setup_py(file_path)
    else:
        # Try to guess the file type based on content
        file_content = read_file_content(file_path)
        
        if '{"packages":' in file_content or '"dependencies":' in file_content:
            if '{' in file_content and '}' in file_content:
                try:
                    # Try parsing as JSON
                    return parse_package_json(file_path, include_dev)
                except:
                    pass
                    
        if '[tool.poetry]' in file_content or '[build-system]' in file_content:
            return parse_poetry_file(file_path, include_dev)
        
        if '[packages]' in file_content or '[dev-packages]' in file_content:
            return parse_pipfile(file_path, include_dev)
        
        if 'name:' in file_content and 'dependencies:' in file_content:
            return parse_conda_environment(file_path)
        
        # Default to requirements.txt format
        return parse_requirements_txt(file_path)

def read_file_content(file_path):
    """Read file content as string."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        # Try with different encoding
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()
        except:
            return ""

def parse_requirements_txt(file_path):
    """
    Parse a requirements.txt file.
    
    Args:
        file_path: Path to requirements.txt file
        
    Returns:
        List of (package_name, version) tuples
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#') or line.startswith('-r '):
                    continue
                
                # Skip options
                if line.startswith('--'):
                    continue
                
                # Strip inline comments
                if '#' in line:
                    line = line.split('#')[0].strip()
                
                # Handle URL requirements (like git+https://...)
                if line.startswith(('git+', 'hg+', 'svn+', 'http:', 'https:')):
                    # Extract package name from egg fragment or path
                    if '#egg=' in line:
                        pkg_name = line.split('#egg=')[1].split('&')[0].strip()
                        packages.append((pkg_name, 'URL'))
                    else:
                        # Try to extract name from URL path
                        url_path = line.split('/')[-1]
                        if '.' in url_path:
                            pkg_name = url_path.split('.')[0]
                            packages.append((pkg_name, 'URL'))
                    continue
                
                # Handle editable installs
                if line.startswith('-e '):
                    line = line[3:].strip()
                    
                    # Handle local path editable installs
                    if line.startswith(('.', '/')):
                        # Try to extract package name from setup.py
                        setup_path = Path(line) / 'setup.py'
                        if setup_path.exists():
                            pkg_name = extract_name_from_setup(setup_path)
                            if pkg_name:
                                packages.append((pkg_name, 'editable'))
                        continue
                    
                    # Handle URL editable installs
                    if '#egg=' in line:
                        pkg_name = line.split('#egg=')[1].split('&')[0].strip()
                        packages.append((pkg_name, 'editable'))
                        continue
                
                # Handle version specifiers
                if '==' in line:
                    parts = line.split('==', 1)
                    pkg_name = parts[0].strip()
                    version = parts[1].strip()
                    
                    # Handle markers like "pandas==1.3.0; python_version >= '3.7'"
                    if ';' in version:
                        version = version.split(';')[0].strip()
                    
                    packages.append((pkg_name, version))
                elif '>=' in line:
                    parts = line.split('>=', 1)
                    pkg_name = parts[0].strip()
                    version = parts[1].strip()
                    
                    # Handle additional constraints
                    if ',' in version:
                        version = version.split(',')[0].strip()
                    
                    # Handle markers
                    if ';' in version:
                        version = version.split(';')[0].strip()
                    
                    packages.append((pkg_name, version))
                elif '>' in line:
                    parts = line.split('>', 1)
                    pkg_name = parts[0].strip()
                    version = parts[1].strip()
                    
                    # Handle additional constraints
                    if ',' in version:
                        version = version.split(',')[0].strip()
                    
                    # Handle markers
                    if ';' in version:
                        version = version.split(';')[0].strip()
                    
                    packages.append((pkg_name, f">{version}"))
                elif '<=' in line or '<' in line or '~=' in line or '!=' in line:
                    # Packages with complex version specifiers
                    # Extract just the package name
                    pkg_name = re.split(r'[<=>!~]', line)[0].strip()
                    
                    # Try to get installed version
                    try:
                        import pkg_resources
                        version = pkg_resources.get_distribution(pkg_name).version
                    except:
                        version = "unknown"
                    
                    packages.append((pkg_name, version))
                else:
                    # Simple package name without version
                    pkg_name = line
                    
                    # Try to get installed version
                    try:
                        import pkg_resources
                        version = pkg_resources.get_distribution(pkg_name).version
                    except:
                        version = "latest"
                    
                    packages.append((pkg_name, version))
    except Exception as e:
        print(f"Error parsing requirements.txt: {e}")
    
    return packages

def parse_pipfile(file_path, include_dev=False):
    """
    Parse a Pipfile or Pipfile.lock.
    
    Args:
        file_path: Path to Pipfile or Pipfile.lock
        include_dev: Whether to include dev packages
        
    Returns:
        List of (package_name, version) tuples
    """
    packages = []
    file_path = Path(file_path)
    
    try:
        # Handle Pipfile.lock (JSON)
        if file_path.name.lower() == "pipfile.lock":
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse default packages
            for pkg_name, pkg_info in data.get("default", {}).items():
                version = pkg_info.get("version", "")
                if version.startswith("=="):
                    version = version[2:]
                packages.append((pkg_name, version))
            
            # Parse dev packages if requested
            if include_dev:
                for pkg_name, pkg_info in data.get("develop", {}).items():
                    version = pkg_info.get("version", "")
                    if version.startswith("=="):
                        version = version[2:]
                    packages.append((pkg_name, version))
        
        # Handle Pipfile (TOML-like)
        else:
            file_content = read_file_content(file_path)
            
            # Extract [packages] section
            packages_match = re.search(r'\[packages\](.*?)(?=\[\w+\]|\Z)', file_content, re.DOTALL)
            if packages_match:
                packages_section = packages_match.group(1)
                packages.extend(parse_pipfile_section(packages_section))
            
            # Extract [dev-packages] section if requested
            if include_dev:
                dev_match = re.search(r'\[dev-packages\](.*?)(?=\[\w+\]|\Z)', file_content, re.DOTALL)
                if dev_match:
                    dev_section = dev_match.group(1)
                    packages.extend(parse_pipfile_section(dev_section))
    
    except Exception as e:
        print(f"Error parsing Pipfile: {e}")
    
    return packages

def parse_pipfile_section(section_content):
    """Parse a section from Pipfile."""
    packages = []
    
    # Match package declarations
    for line in section_content.split('\n'):
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Match package name and version
        match = re.match(r'([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"', line)
        if match:
            pkg_name = match.group(1)
            version_spec = match.group(2)
            
            # Handle different version specs
            if version_spec.startswith('=='):
                version = version_spec[2:]
            elif version_spec.startswith('>='):
                version = version_spec[2:]
            elif version_spec == "*":
                version = "latest"
            else:
                version = version_spec
            
            packages.append((pkg_name, version))
    
    return packages

def is_poetry_file(file_path):
    """Check if a pyproject.toml file is a Poetry file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return '[tool.poetry]' in content
    except:
        return False

def parse_poetry_file(file_path, include_dev=False):
    """
    Parse a poetry.lock or pyproject.toml file.
    
    Args:
        file_path: Path to poetry.lock or pyproject.toml
        include_dev: Whether to include dev dependencies
        
    Returns:
        List of (package_name, version) tuples
    """
    packages = []
    file_path = Path(file_path)
    
    try:
        # Parse poetry.lock
        if file_path.name.lower() == "poetry.lock":
            file_content = read_file_content(file_path)
            
            # Parse package sections
            package_sections = re.findall(r'(\[\[package\]\].*?)\n\s*(?:\[\[|\Z)', file_content, re.DOTALL)
            
            for section in package_sections:
                name_match = re.search(r'name\s*=\s*"([^"]+)"', section)
                version_match = re.search(r'version\s*=\s*"([^"]+)"', section)
                category_match = re.search(r'category\s*=\s*"([^"]+)"', section)
                
                if name_match and version_match:
                    pkg_name = name_match.group(1)
                    version = version_match.group(1)
                    
                    # Check if dev dependency
                    if category_match and category_match.group(1) == "dev" and not include_dev:
                        continue
                    
                    packages.append((pkg_name, version))
        
        # Parse pyproject.toml
        else:
            try:
                data = toml.load(file_path)
            except:
                # Fallback to manual parsing if toml module not available
                file_content = read_file_content(file_path)
                return parse_pyproject_toml_manually(file_content, include_dev)
            
            # Get dependencies
            dependencies = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            
            for pkg_name, version_spec in dependencies.items():
                # Skip python dependency
                if pkg_name == "python":
                    continue
                
                # Handle complex dependency specs
                if isinstance(version_spec, dict):
                    version = version_spec.get("version", "latest")
                else:
                    version = version_spec
                
                # Clean up version string
                if isinstance(version, str):
                    if version.startswith(("^", "~", "==")):
                        version = version[1:] if version.startswith(("^", "~")) else version[2:]
                    elif version == "*":
                        version = "latest"
                
                packages.append((pkg_name, str(version)))
            
            # Get dev dependencies if requested
            if include_dev:
                dev_groups = ["dev", "test", "docs", "dev-dependencies"]
                for group in dev_groups:
                    if group == "dev-dependencies":
                        dev_deps = data.get("tool", {}).get("poetry", {}).get(group, {})
                    else:
                        dev_deps = data.get("tool", {}).get("poetry", {}).get("group", {}).get(group, {}).get("dependencies", {})
                    
                    for pkg_name, version_spec in dev_deps.items():
                        # Handle complex dependency specs
                        if isinstance(version_spec, dict):
                            version = version_spec.get("version", "latest")
                        else:
                            version = version_spec
                        
                        # Clean up version string
                        if isinstance(version, str):
                            if version.startswith(("^", "~", "==")):
                                version = version[1:] if version.startswith(("^", "~")) else version[2:]
                            elif version == "*":
                                version = "latest"
                        
                        packages.append((pkg_name, str(version)))
    
    except Exception as e:
        print(f"Error parsing Poetry file: {e}")
    
    return packages

def parse_pyproject_toml_manually(content, include_dev=False):
    """Manually parse pyproject.toml if toml module is not available."""
    packages = []
    
    # Extract dependencies section
    deps_match = re.search(r'\[tool\.poetry\.dependencies\](.*?)(?=\[\w+|\Z)', content, re.DOTALL)
    if deps_match:
        deps_section = deps_match.group(1)
        for line in deps_section.split('\n'):
            line = line.strip()
            
            # Skip empty lines, comments, and python dependency
            if not line or line.startswith('#') or line.startswith('python'):
                continue
            
            # Match "package = "version""
            match = re.match(r'([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"', line)
            if match:
                pkg_name = match.group(1)
                version = match.group(2)
                
                # Clean up version string
                if version.startswith(("^", "~", "==")):
                    version = version[1:] if version.startswith(("^", "~")) else version[2:]
                elif version == "*":
                    version = "latest"
                
                packages.append((pkg_name, version))
    
    # Extract dev dependencies if requested
    if include_dev:
        # Look for both old and new Poetry formats
        dev_sections = []
        
        # Old format: [tool.poetry.dev-dependencies]
        dev_match = re.search(r'\[tool\.poetry\.dev-dependencies\](.*?)(?=\[\w+|\Z)', content, re.DOTALL)
        if dev_match:
            dev_sections.append(dev_match.group(1))
        
        # New format: [tool.poetry.group.dev.dependencies]
        for group in ["dev", "test", "docs"]:
            group_match = re.search(fr'\[tool\.poetry\.group\.{group}\.dependencies\](.*?)(?=\[\w+|\Z)', content, re.DOTALL)
            if group_match:
                dev_sections.append(group_match.group(1))
        
        # Parse each dev section
        for section in dev_sections:
            for line in section.split('\n'):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Match "package = "version""
                match = re.match(r'([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"', line)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(2)
                    
                    # Clean up version string
                    if version.startswith(("^", "~", "==")):
                        version = version[1:] if version.startswith(("^", "~")) else version[2:]
                    elif version == "*":
                        version = "latest"
                    
                    packages.append((pkg_name, version))
    
    return packages

def parse_conda_environment(file_path):
    """
    Parse a conda environment.yml file.
    
    Args:
        file_path: Path to environment.yml file
        
    Returns:
        List of (package_name, version) tuples
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            env_data = yaml.safe_load(f)
        
        # Get dependencies list
        dependencies = env_data.get('dependencies', [])
        
        for dep in dependencies:
            # Handle pip dependencies
            if isinstance(dep, dict) and 'pip' in dep:
                pip_deps = dep['pip']
                for pip_dep in pip_deps:
                    # Parse pip dependency like a requirements.txt line
                    for pkg_name, version in parse_requirements_txt(pip_dep):
                        packages.append((pkg_name, version))
                continue
            
            # Handle conda dependency
            if not isinstance(dep, str):
                continue
            
            # Skip meta-packages like 'python'
            if dep.startswith('python'):
                continue
            
            # Parse conda dependency
            if '=' in dep:
                parts = dep.split('=')
                pkg_name = parts[0]
                
                # Handle cases like 'package=1.0=py37_0'
                if len(parts) >= 2:
                    version = parts[1]
                    packages.append((pkg_name, version))
            else:
                # No version specified
                packages.append((dep, 'latest'))
    
    except Exception as e:
        print(f"Error parsing conda environment file: {e}")
    
    return packages

def parse_package_json(file_path, include_dev=False):
    """
    Parse a package.json file for JavaScript dependencies.
    
    Args:
        file_path: Path to package.json file
        include_dev: Whether to include devDependencies
        
    Returns:
        List of (package_name, version) tuples
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Get dependencies
        dependencies = data.get('dependencies', {})
        for pkg_name, version in dependencies.items():
            # Clean up version string
            version = version.lstrip('^~=v')
            packages.append((pkg_name, version))
        
        # Get devDependencies if requested
        if include_dev:
            dev_dependencies = data.get('devDependencies', {})
            for pkg_name, version in dev_dependencies.items():
                # Clean up version string
                version = version.lstrip('^~=v')
                packages.append((pkg_name, version))
    
    except Exception as e:
        print(f"Error parsing package.json: {e}")
    
    return packages

def parse_setup_py(file_path):
    """
    Parse a setup.py or setup.cfg file.
    
    Args:
        file_path: Path to setup.py or setup.cfg file
        
    Returns:
        List of (package_name, version) tuples
    """
    packages = []
    file_path = Path(file_path)
    
    try:
        # Handle setup.cfg (INI format)
        if file_path.name.lower() == "setup.cfg":
            import configparser
            config = configparser.ConfigParser()
            config.read(file_path)
            
            if 'options' in config and 'install_requires' in config['options']:
                requires = config['options']['install_requires'].strip().split('\n')
                for req in requires:
                    req = req.strip()
                    if req:
                        for pkg_name, version in parse_requirements_txt(req):
                            packages.append((pkg_name, version))
            
            return packages
        
        # Handle setup.py
        # This is challenging since it's Python code, so we'll use a simpler approach
        setup_content = read_file_content(file_path)
        
        # Look for install_requires in setup.py
        install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', setup_content, re.DOTALL)
        if install_requires_match:
            requires_text = install_requires_match.group(1)
            
            # Extract requirements strings
            req_pattern = r'[\'"]([^\'",]+)[\'"]'
            requires = re.findall(req_pattern, requires_text)
            
            for req in requires:
                req = req.strip()
                if req:
                    for pkg_name, version in parse_requirements_txt(req):
                        packages.append((pkg_name, version))
    
    except Exception as e:
        print(f"Error parsing setup file: {e}")
    
    return packages

def extract_name_from_setup(setup_path):
    """Extract package name from setup.py."""
    try:
        setup_content = read_file_content(setup_path)
        name_match = re.search(r'name\s*=\s*[\'"]([^\'"]+)[\'"]', setup_content)
        if name_match:
            return name_match.group(1)
    except:
        pass
    
    return None