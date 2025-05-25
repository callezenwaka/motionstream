# tools/dependency_chain.py
from typing import Any, Optional, Dict, List, Set
from smolagents.tools import Tool
import io
import base64

class DependencyChainTool(Tool):
    name = "dependency_analysis"
    description = "Analyzes the complete dependency tree for a Python package, identifies vulnerabilities in all dependencies, and generates a visual dependency graph. Shows the full chain of dependencies and their security status."
    inputs = {
        'package_name': {'type': 'string', 'description': 'The name of the Python package to analyze dependencies for.'},
        'package_version': {'type': 'string', 'description': 'Optional specific version of the package to analyze. If not provided, will use installed version or latest.', 'required': False, 'nullable': True},
        'include_visualization': {'type': 'boolean', 'description': 'Whether to generate a visual dependency graph (requires matplotlib). Default is True.', 'required': False, 'nullable': True}
    }
    output_type = "string"

    def __init__(self, **kwargs):
        super().__init__()
        
        # Check required dependencies
        try:
            import pkg_resources
            from packaging import version
        except ImportError as e:
            raise ImportError(
                "You must install packages `pkg_resources` and `packaging` to run this tool: run `pip install packaging`."
            ) from e
        
        # Check optional dependencies for visualization
        self.visualization_available = True
        try:
            import matplotlib
            import networkx as nx
            matplotlib.use('Agg')  # Set non-interactive backend
        except ImportError:
            self.visualization_available = False
        
        # Initialize vulnerability scanner tool for reuse
        from .vulnerability_scan import ScanTool
        self.vulnerability_scanner = ScanTool()

    def forward(self, package_name: str, package_version: Optional[str] = None, 
               include_visualization: bool = True) -> str:
        """
        Analyze dependency chain and find vulnerabilities.
        
        Args:
            package_name: The name of the package to analyze
            package_version: The version of the package (optional)
            include_visualization: Whether to generate visual graph (optional)
            
        Returns:
            Formatted string with dependency analysis and vulnerability information
        """
        try:
            analysis = self._analyze_dependency_chain(package_name, package_version, include_visualization)
            return self._format_results(package_name, package_version, analysis)
        except Exception as e:
            return f"Error analyzing dependency chain for {package_name}: {str(e)}"

    def _analyze_dependency_chain(self, package_name: str, package_version: str = None, 
                                 include_visualization: bool = True) -> Dict:
        """Core dependency chain analysis logic."""
        # Build the dependency tree
        dependency_tree = self._build_dependency_tree(package_name, package_version)
        
        if not dependency_tree:
            return {
                "error": f"Could not build dependency tree for {package_name}",
                "dependency_tree": {},
                "vulnerable_dependencies": {},
                "visualization": None
            }
        
        # Get all packages in the tree
        all_packages = self._extract_all_packages(dependency_tree)
        
        # Scan each package for vulnerabilities
        vulnerable_dependencies = {}
        vulnerability_count = 0
        
        for pkg_name, pkg_info in all_packages.items():
            vulnerabilities = self._scan_package_vulnerabilities(pkg_name, pkg_info['version'])
            
            if vulnerabilities:
                vulnerable_dependencies[pkg_name] = {
                    'version': pkg_info['version'],
                    'vulnerabilities': vulnerabilities,
                    'path': pkg_info['path'],
                    'vulnerability_count': len(vulnerabilities)
                }
                vulnerability_count += len(vulnerabilities)
        
        # Generate visualization if requested and available
        visualization = None
        if include_visualization and self.visualization_available and all_packages:
            visualization = self._generate_dependency_visualization(dependency_tree, vulnerable_dependencies)
        
        return {
            'dependency_tree': dependency_tree,
            'all_packages': all_packages,
            'vulnerable_dependencies': vulnerable_dependencies,
            'total_dependencies': len(all_packages),
            'vulnerable_dependency_count': len(vulnerable_dependencies),
            'total_vulnerability_count': vulnerability_count,
            'visualization': visualization
        }

    def _build_dependency_tree(self, package_name: str, package_version: str = None, 
                              visited: Set[str] = None, path: List[str] = None) -> Dict:
        """Build a complete dependency tree for the package."""
        if visited is None:
            visited = set()
        
        if path is None:
            path = []
        
        # Get package distribution
        try:
            import pkg_resources
            
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
                            self._compare_versions(req_version, op, spec_ver) 
                            for op, spec_ver in req_specs
                        )
                    
                    req_version_str = req_version
                    if not version_match:
                        req_version_str = f"{req_version} (MISMATCH: {req_specs})"
                    
                    # Recursively get dependencies
                    new_path = path + [package_name]
                    sub_dependencies = self._build_dependency_tree(req_name, req_version, visited, new_path)
                    
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

    def _compare_versions(self, version_str: str, operator: str, spec_version: str) -> bool:
        """Compare two versions based on the given operator."""
        try:
            from packaging import version
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

    def _extract_all_packages(self, dependency_tree: Dict) -> Dict:
        """Extract all packages from the dependency tree into a flat dictionary."""
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

    def _scan_package_vulnerabilities(self, package_name: str, package_version: str) -> List[Dict]:
        """Scan a single package for vulnerabilities using the existing ScanTool."""
        if package_version == 'Not installed' or package_version == 'unknown':
            return []
        
        try:
            # Use the existing vulnerability scanner
            return self.vulnerability_scanner._scan_vulnerabilities(package_name, package_version)
        except Exception:
            return []

    def _generate_dependency_visualization(self, dependency_tree: Dict, 
                                         vulnerable_dependencies: Dict) -> Optional[str]:
        """Generate a visualization of the dependency tree with vulnerabilities highlighted."""
        if not self.visualization_available:
            return None
        
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
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
            
            # Use spring layout for positioning
            pos = nx.spring_layout(G, seed=42)  # For reproducible layout
            
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
            
        except Exception:
            return None

    def _format_results(self, package_name: str, package_version: Optional[str], 
                       analysis: Dict) -> str:
        """Format dependency analysis results into a readable string."""
        if analysis.get("error"):
            return f"❌ **Error:** {analysis['error']}"
        
        # Build header
        version_info = f" version {package_version}" if package_version else ""
        result = f"🔍 **Dependency Chain Analysis for {package_name}{version_info}**\n\n"
        
        # Summary statistics
        total_deps = analysis.get('total_dependencies', 0)
        vulnerable_deps = analysis.get('vulnerable_dependency_count', 0)
        total_vulns = analysis.get('total_vulnerability_count', 0)
        
        result += "## 📊 Summary\n\n"
        result += f"**Total Dependencies:** {total_deps}\n"
        result += f"**Vulnerable Dependencies:** {vulnerable_deps}\n"
        result += f"**Total Vulnerabilities:** {total_vulns}\n\n"
        
        # Risk assessment
        if vulnerable_deps == 0:
            result += "✅ **Status:** All dependencies appear secure\n\n"
        elif vulnerable_deps / total_deps <= 0.1:
            result += "🟡 **Status:** Low risk - few vulnerable dependencies\n\n"
        elif vulnerable_deps / total_deps <= 0.3:
            result += "🟠 **Status:** Medium risk - several vulnerable dependencies\n\n"
        else:
            result += "🔴 **Status:** High risk - many vulnerable dependencies\n\n"
        
        # List all dependencies
        all_packages = analysis.get('all_packages', {})
        if all_packages:
            result += "## 📦 All Dependencies\n\n"
            for pkg_name, pkg_info in sorted(all_packages.items()):
                if pkg_name in analysis.get('vulnerable_dependencies', {}):
                    vuln_count = analysis['vulnerable_dependencies'][pkg_name]['vulnerability_count']
                    result += f"- ⚠️ **{pkg_name}** {pkg_info['version']} ({vuln_count} vulnerabilities)\n"
                else:
                    result += f"- ✅ **{pkg_name}** {pkg_info['version']}\n"
            result += "\n"
        
        # Detailed vulnerability information
        vulnerable_deps = analysis.get('vulnerable_dependencies', {})
        if vulnerable_deps:
            result += "## 🚨 Vulnerable Dependencies\n\n"
            
            for pkg_name, vuln_info in vulnerable_deps.items():
                result += f"### {pkg_name} {vuln_info['version']}\n\n"
                result += f"**Dependency Path:** {' → '.join(vuln_info['path']) + ' → ' if vuln_info['path'] else ''}{pkg_name}\n"
                result += f"**Vulnerabilities Found:** {vuln_info['vulnerability_count']}\n\n"
                
                # List vulnerabilities
                for i, vuln in enumerate(vuln_info['vulnerabilities'][:3], 1):  # Show first 3
                    severity = vuln.get('severity', 'Unknown')
                    emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Unknown": "⚪"}.get(severity, "⚪")
                    result += f"**{i}. {emoji} {vuln.get('id', 'Unknown ID')} - {severity}**\n"
                    result += f"   {vuln.get('summary', 'No summary available')}\n"
                    if vuln.get('fixed_versions'):
                        result += f"   *Fixed in: {', '.join(vuln['fixed_versions'])[:50]}*\n"
                    result += "\n"
                
                if len(vuln_info['vulnerabilities']) > 3:
                    result += f"   *... and {len(vuln_info['vulnerabilities']) - 3} more vulnerabilities*\n\n"
                
                result += "---\n\n"
        
        # Visualization note
        if analysis.get('visualization'):
            result += "## 📈 Dependency Graph\n\n"
            result += "Visual dependency graph generated (base64 encoded image data available)\n\n"
        elif not self.visualization_available:
            result += "## 📈 Visualization\n\n"
            result += "Install `matplotlib` and `networkx` for dependency graph visualization\n\n"
        
        # Recommendations
        result += "## 💡 Recommendations\n\n"
        if vulnerable_deps:
            result += "1. **Update vulnerable dependencies** to their latest secure versions\n"
            result += "2. **Review dependency paths** to understand how vulnerabilities are introduced\n"
            result += "3. **Consider alternative packages** for dependencies with critical vulnerabilities\n"
            result += "4. **Implement automated dependency scanning** in your CI/CD pipeline\n"
        else:
            result += "1. **Keep dependencies updated** regularly\n"
            result += "2. **Monitor for new vulnerabilities** in your dependency chain\n"
            result += "3. **Consider using dependency pinning** for production deployments\n"
        
        return result