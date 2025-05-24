# tools/dependency_chain.py
import io
import base64
import matplotlib
import pkg_resources
import networkx as nx
import matplotlib.pyplot as plt
from packaging import version
from .vulnerability_scan import scan_vulnerabilities

def analyze_dependency_chain(package_name, package_version=None):
    """
    Analyze the complete dependency tree for a package and find vulnerabilities.
    
    Args:
        package_name: The name of the package to analyze
        package_version: The version of the package (optional)
        
    Returns:
        Dictionary with dependency tree and vulnerability information
    """
    print(f"Analyzing dependency chain for {package_name}{f'=={package_version}' if package_version else ''}...")
    
    # Build the dependency tree
    dependency_tree = build_dependency_tree(package_name, package_version)
    
    if not dependency_tree:
        return {
            "error": f"Could not build dependency tree for {package_name}",
            "dependency_tree": {},
            "vulnerable_dependencies": {},
            "visualization": None
        }
    
    # Get all packages in the tree
    all_packages = extract_all_packages(dependency_tree)
    
    # Scan each package for vulnerabilities
    vulnerable_dependencies = {}
    vulnerability_count = 0
    
    for pkg_name, pkg_info in all_packages.items():
        print(f"Scanning dependency: {pkg_name}=={pkg_info['version']}...")
        vulnerabilities = scan_vulnerabilities(pkg_name, pkg_info['version'])
        
        if vulnerabilities:
            vulnerable_dependencies[pkg_name] = {
                'version': pkg_info['version'],
                'vulnerabilities': vulnerabilities,
                'path': pkg_info['path'],
                'vulnerability_count': len(vulnerabilities)
            }
            vulnerability_count += len(vulnerabilities)
    
    # Generate visualization if there are dependencies
    visualization = None
    if all_packages:
        visualization = generate_dependency_visualization(dependency_tree, vulnerable_dependencies)
    
    return {
        'dependency_tree': dependency_tree,
        'all_packages': all_packages,
        'vulnerable_dependencies': vulnerable_dependencies,
        'total_dependencies': len(all_packages),
        'vulnerable_dependency_count': len(vulnerable_dependencies),
        'total_vulnerability_count': vulnerability_count,
        'visualization': visualization
    }

def build_dependency_tree(package_name, package_version=None, visited=None, path=None):
    """
    Build a complete dependency tree for the package.
    
    Args:
        package_name: The name of the package
        package_version: The version of the package (optional)
        visited: Set of already visited packages (to avoid cycles)
        path: Current path from root package
        
    Returns:
        Nested dictionary representing the dependency tree
    """
    if visited is None:
        visited = set()
    
    if path is None:
        path = []
    
    # Get package distribution
    try:
        # If version is specified but different from installed, we need a different approach
        has_different_version = False
        
        if package_version:
            try:
                dist = pkg_resources.get_distribution(package_name)
                installed_version = dist.version
                
                if installed_version != package_version:
                    has_different_version = True
            except:
                has_different_version = True
        else:
            dist = pkg_resources.get_distribution(package_name)
            package_version = dist.version
        
        # If we need a different version, we'll try pip show or return basic info
        if has_different_version:
            return {
                package_name: {
                    'version': package_version,
                    'dependencies': {},
                    'path': path
                }
            }
    except pkg_resources.DistributionNotFound:
        # Package not installed, return basic structure
        return {
            package_name: {
                'version': package_version if package_version else 'unknown',
                'dependencies': {},
                'path': path
            }
        }
    
    # Check if we've already processed this package (avoid cycles)
    package_key = f"{package_name}=={package_version}"
    if package_key in visited:
        return {}
    
    # Mark as visited
    visited.add(package_key)
    
    # Get direct dependencies
    dependencies = {}
    try:
        for req in dist.requires():
            # Parse requirement
            req_name = req.name
            req_specs = [(s[0], s[1]) for s in req.specs]  # [(op, version), ...]
            
            # Find installed version of dependency
            try:
                req_dist = pkg_resources.get_distribution(req_name)
                req_version = req_dist.version
                
                # Check if installed version satisfies specs
                version_match = True
                if req_specs:
                    version_match = all(
                        compare_versions(req_version, op, spec_ver) 
                        for op, spec_ver in req_specs
                    )
                
                req_version_str = req_version
                if not version_match:
                    req_version_str = f"{req_version} (MISMATCH: {req_specs})"
                
                # Recursively get dependencies
                new_path = path + [package_name]
                sub_dependencies = build_dependency_tree(req_name, req_version, visited, new_path)
                
                dependencies[req_name] = {
                    'version': req_version,
                    'dependencies': sub_dependencies,
                    'path': new_path,
                    'specs': req_specs
                }
            except pkg_resources.DistributionNotFound:
                # Dependency not installed
                dependencies[req_name] = {
                    'version': 'Not installed',
                    'dependencies': {},
                    'path': path + [package_name],
                    'specs': req_specs
                }
    except Exception as e:
        # Handle errors
        dependencies['ERROR'] = {
            'message': str(e),
            'path': path
        }
    
    return {
        package_name: {
            'version': package_version,
            'dependencies': dependencies,
            'path': path
        }
    }

def compare_versions(version_str, operator, spec_version):
    """
    Compare two versions based on the given operator.
    
    Args:
        version_str: Version string to compare
        operator: Operator ('==', '!=', '>', '>=', '<', '<=')
        spec_version: Version specification to compare against
        
    Returns:
        True if comparison succeeds, False otherwise
    """
    try:
        ver = version.parse(version_str)
        spec = version.parse(spec_version)
        
        if operator == '==':
            return ver == spec
        elif operator == '!=':
            return ver != spec
        elif operator == '>':
            return ver > spec
        elif operator == '>=':
            return ver >= spec
        elif operator == '<':
            return ver < spec
        elif operator == '<=':
            return ver <= spec
    except Exception:
        # If parsing fails, assume it doesn't match
        return False
    
    return False

def extract_all_packages(dependency_tree):
    """
    Extract all packages from the dependency tree into a flat dictionary.
    
    Args:
        dependency_tree: Nested dependency tree dictionary
        
    Returns:
        Dictionary mapping package names to information
    """
    all_packages = {}
    
    def extract_recursively(tree, path=[]):
        for pkg_name, pkg_info in tree.items():
            if pkg_name == 'ERROR':
                continue
                
            all_packages[pkg_name] = {
                'version': pkg_info['version'],
                'path': pkg_info['path']
            }
            
            if 'dependencies' in pkg_info and pkg_info['dependencies']:
                extract_recursively(pkg_info['dependencies'], path + [pkg_name])
    
    extract_recursively(dependency_tree)
    return all_packages

def generate_dependency_visualization(dependency_tree, vulnerable_dependencies):
    """
    Generate a visualization of the dependency tree with vulnerabilities highlighted.
    
    Args:
        dependency_tree: Nested dependency tree dictionary
        vulnerable_dependencies: Dictionary of dependencies with vulnerabilities
        
    Returns:
        Base64-encoded PNG image of the dependency graph
    """
    # Set Matplotlib to use a non-interactive backend
    matplotlib.use('Agg')
    
    # Create a directed graph
    G = nx.DiGraph()
    
    # Helper function to add nodes and edges recursively
    def add_nodes_edges(tree, parent=None):
        for pkg_name, pkg_info in tree.items():
            if pkg_name == 'ERROR':
                continue
                
            # Format node label
            version_str = pkg_info['version']
            if len(version_str) > 10:
                version_str = version_str[:8] + "..."
            node_label = f"{pkg_name}\n{version_str}"
            
            # Determine node color based on vulnerability
            if pkg_name in vulnerable_dependencies:
                # Count severities
                severities = [v.get('severity', 'Unknown') for v in 
                             vulnerable_dependencies[pkg_name]['vulnerabilities']]
                
                if 'Critical' in severities:
                    node_color = '#ff5252'  # Red
                elif 'High' in severities:
                    node_color = '#ff9100'  # Orange
                elif 'Medium' in severities:
                    node_color = '#ffeb3b'  # Yellow
                else:
                    node_color = '#81c784'  # Light green
            else:
                node_color = '#81c784'  # Light green (safe)
            
            # Add node
            G.add_node(node_label, color=node_color)
            
            # Add edge from parent if exists
            if parent:
                G.add_edge(parent, node_label)
            
            # Process dependencies
            if 'dependencies' in pkg_info and pkg_info['dependencies']:
                add_nodes_edges(pkg_info['dependencies'], node_label)
    
    # Build the graph
    add_nodes_edges(dependency_tree)
    
    # Create visualization
    plt.figure(figsize=(12, 8))
    
    # Get node colors
    node_colors = [G.nodes[node].get('color', '#81c784') for node in G.nodes()]
    
    # Determine layout based on graph size
    if len(G) <= 20:
        pos = nx.spring_layout(G, seed=42)  # For reproducible layout
    else:
        # For larger graphs, use hierarchical layout
        pos = nx.nx_agraph.graphviz_layout(G, prog='dot') if nx.nx_agraph is not None else nx.spring_layout(G, seed=42)
    
    # Draw the graph
    nx.draw(G, pos, with_labels=True, node_color=node_colors, 
            node_size=2000, font_size=8, font_weight='bold',
            arrows=True, arrowsize=15, edge_color='gray')
    
    # Add title
    root_package = list(dependency_tree.keys())[0]
    root_version = dependency_tree[root_package]['version']
    plt.title(f"Dependency Tree for {root_package}=={root_version}")
    
    # Add legend
    import matplotlib.patches as mpatches
    legend_elements = [
        mpatches.Patch(color='#81c784', label='Safe'),
        mpatches.Patch(color='#ffeb3b', label='Medium Vulnerability'),
        mpatches.Patch(color='#ff9100', label='High Vulnerability'),
        mpatches.Patch(color='#ff5252', label='Critical Vulnerability')
    ]
    plt.legend(handles=legend_elements, loc='upper right')
    
    # Convert plot to base64 image
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close()
    
    return f"data:image/png;base64,{image_base64}"

def save_dependency_visualization(visualization, output_path):
    """
    Save the dependency visualization to a file.
    
    Args:
        visualization: Base64-encoded image data
        output_path: Path to save the image to
        
    Returns:
        Path to the saved file
    """
    if not visualization or not visualization.startswith('data:image/png;base64,'):
        return None
    
    try:
        # Extract the base64 data
        image_data = visualization.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        
        # Save to file
        with open(output_path, 'wb') as f:
            f.write(image_bytes)
        
        return output_path
    except Exception as e:
        print(f"Error saving visualization: {e}")
        return None