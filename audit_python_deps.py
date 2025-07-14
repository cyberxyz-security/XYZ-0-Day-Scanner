import json
import subprocess
import sys
import os
from typing import Dict, List, Any, Optional

def get_dependency_tree() -> List[Dict[str, Any]]:
    """
    Generates a dependency tree using pipdeptree.
    """
    try:
        result = subprocess.run(
            ['pipdeptree', '--json-tree'],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error running pipdeptree: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing pipdeptree output: {e}", file=sys.stderr)
        sys.exit(1)

def get_vulnerabilities() -> Dict[str, Any]:
    """
    Gets vulnerabilities using pip-audit.
    """
    import shutil
    pip_audit_path = shutil.which("pip-audit")
    if not pip_audit_path:
        print("Error: 'pip-audit' not found. Please install it in your environment.", file=sys.stderr)
        sys.exit(1)

    try:
        command = [pip_audit_path, '--format', 'json']
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )
        if not result.stdout.strip():
            if result.returncode != 0:
                print(f"Error running pip-audit. Return code: {result.returncode}", file=sys.stderr)
                print(f"Stderr: {result.stderr}", file=sys.stderr)
            return {}
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error running pip-audit: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing pip-audit output: {e}", file=sys.stderr)
        sys.exit(1)


def calculate_risk_score(vulnerability: Dict[str, Any]) -> float:
    """
    Calculates a risk score for a vulnerability.
    This is a simple implementation, can be expanded.
    """
    # Using CVSS v3.1 score if available
    cvss_list = vulnerability.get('cvss', [])
    if cvss_list:
        # Assuming we take the first CVSS score if multiple exist
        cvss = cvss_list[0]
        if cvss and 'base_score' in cvss:
            return float(cvss['base_score'])
    return 5.0  # Default score if no CVSS data

def map_vulnerabilities_to_tree(tree: List[Dict[str, Any]], vulnerabilities_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Maps vulnerabilities to the dependency tree and flags transitive vulnerabilities.
    """
    vuln_map = {}
    dependencies = vulnerabilities_data.get('dependencies', [])
    for dep in dependencies:
        name = dep.get('name', '').lower()
        if name:
            if name not in vuln_map:
                vuln_map[name] = []
            vuln_map[name].extend(dep.get('vulns', []))

    def process_node(node: Dict[str, Any]) -> bool:
        node_key = node.get('key')
        is_vulnerable = False
        
        if node_key in vuln_map:
            node['vulnerabilities'] = [
                {
                    'id': v['id'],
                    'description': v.get('description', 'No description available.'),
                    'fix_versions': v.get('fix_versions', []),
                    'risk_score': calculate_risk_score(v)
                } for v in vuln_map[node_key]
            ]
            if node['vulnerabilities']:
                node['is_direct_vulnerability'] = True
                is_vulnerable = True

        has_transitive_vulnerability = False
        if 'dependencies' in node:
            for child in node['dependencies']:
                if process_node(child):
                    has_transitive_vulnerability = True
        
        if has_transitive_vulnerability:
            node['has_transitive_vulnerability'] = True
            is_vulnerable = True
            
        return is_vulnerable

    for node in tree:
        process_node(node)
        
    return tree

def main():
    """
    Main function to run the audit and print the results.
    """
    print("🐍 Auditing Python environment...", file=sys.stderr)
    
    print("🌳 Generating dependency tree...", file=sys.stderr)
    tree = get_dependency_tree()
    
    print("🛡️ Scanning for vulnerabilities...", file=sys.stderr)
    vulnerabilities = get_vulnerabilities()
    
    print("🔗 Correlating data...", file=sys.stderr)
    final_report = map_vulnerabilities_to_tree(tree, vulnerabilities)
    
    print("✅ Audit complete.", file=sys.stderr)
    
    print(json.dumps(final_report, indent=2))

if __name__ == "__main__":
    main()