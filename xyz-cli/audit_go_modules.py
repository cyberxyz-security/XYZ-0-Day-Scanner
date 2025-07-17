#!/usr/bin/env python3
"""
Enhanced Go Module Security Auditor Functions
Replace the corresponding functions in your existing script with these enhanced versions.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Enhanced Configuration with more trusted domains
TRUSTED_DOMAINS = [
    "golang.org",
    "google.golang.org", 
    "cloud.google.com",
    "github.com/golang",
    "github.com/google",
    "github.com/hashicorp",
    "gopkg.in",
    "go.uber.org",
    "go.opentelemetry.io",
    "k8s.io",
    "sigs.k8s.io",
    "github.com/grpc-ecosystem",
    "github.com/prometheus",
    "github.com/kubernetes",
    "github.com/spf13",
    "github.com/stretchr",
    "github.com/gorilla",
    # Additional trusted domains
    "github.com/gin-gonic",
    "github.com/labstack",
    "github.com/sirupsen",
    "github.com/go-chi",
    "github.com/dgrijalva",
    "go.mongodb.org",
    "github.com/lib",  # Common database drivers
    "github.com/go-sql-driver",
    "github.com/jackc",  # pgx PostgreSQL driver
    "github.com/redis",
    "github.com/aws/aws-sdk-go",
    "github.com/Azure/azure-sdk-for-go",
    "github.com/IBM/sarama",  # Kafka client
    "github.com/elastic/go-elasticsearch",
    "github.com/gogo/protobuf",
    "github.com/golang-migrate",
    "github.com/go-kit",
    "github.com/etcd-io",
    "go.etcd.io",
]

class ModuleAuditor:
    def __init__(self):
        self.depsdev_cmd = self._find_depsdev()
        self.go_mod_path = Path.home() / "go" / "pkg" / "mod"
        self.results = []
        self.stats = {
            "total": 0,
            "trusted": 0,
            "untrusted": 0,
            "with_advisories": 0
        }
    
    def _find_depsdev(self) -> Optional[str]:
        """Enhanced depsdev finder with better error handling"""
        # Check if depsdev is in PATH
        try:
            result = subprocess.run(["which", "depsdev"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                depsdev_path = result.stdout.strip()
                print(f"✅ depsdev CLI found in PATH at {depsdev_path} - will check for advisories", file=sys.stderr)
                return "depsdev"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Check common Go installation paths
        possible_paths = [
            Path.home() / "go" / "bin" / "depsdev",
            Path("/usr/local/go/bin/depsdev"),
            Path("/opt/go/bin/depsdev"),
        ]
        
        for path in possible_paths:
            if path.exists() and path.is_file():
                print(f"✅ depsdev CLI found at {path} - will check for advisories", file=sys.stderr)
                return str(path)
        
        print("⚠️  depsdev CLI not found. Install with: go install github.com/edoardottt/depsdev@latest", file=sys.stderr)
        print("   Will skip advisory checks for now.", file=sys.stderr)
        return None
    
    def _is_trusted(self, module_name: str) -> bool:
        """Enhanced trust checking with better matching"""
        # Normalize module name for comparison
        normalized_name = module_name.lower()
        
        # Check exact matches and prefix matches
        for domain in TRUSTED_DOMAINS:
            if normalized_name == domain.lower() or normalized_name.startswith(domain.lower() + "/"):
                return True
        
        # Additional heuristic: check for well-known organizational patterns
        well_known_orgs = [
            "github.com/microsoft/",
            "github.com/docker/",
            "github.com/moby/",
            "github.com/containerd/",
            "github.com/opencontainers/",
            "github.com/grpc/",
            "github.com/protocolbuffers/",
        ]
        
        for org in well_known_orgs:
            if normalized_name.startswith(org):
                return True
        
        return False
    
    def _get_advisory_info(self, module_name: str, module_version: Optional[str]) -> Tuple[str, bool, List[Dict]]:
        """Enhanced advisory checking with better error handling"""
        if not self.depsdev_cmd:
            return "❓ Advisory check skipped", False, []
        
        clean_module_name = module_name.split('@')[0]
        
        try:
            command = [self.depsdev_cmd, "info", "go", clean_module_name]
            if module_version:
                command.append(module_version)

            result = subprocess.run(command, capture_output=True, text=True, timeout=45)

            if result.returncode == 0:
                output = result.stdout.strip()
                if not output:
                    return "✅ No known advisories", False, []

                try:
                    data = json.loads(output)
                    advisories = data.get("advisoryKeys", [])
                    if advisories:
                        return f"🚨 HAS {len(advisories)} ADVISORIES", True, advisories
                    return "✅ No known advisories", False, []
                except json.JSONDecodeError:
                    return "❓ Failed to parse depsdev output", False, []
            else:
                if "not found" in result.stderr.lower():
                    return "✅ No known advisories", False, []
                else:
                    return f"❓ Advisory check failed: {result.stderr}", False, []
                
        except subprocess.TimeoutExpired:
            return "❓ Advisory check timeout", False, []
        except Exception as e:
            return f"❓ Advisory check error: {e}", False, []
    
    def _extract_module_info(self, path: Path) -> Tuple[Optional[str], Optional[str]]:
        """Extracts module name and version from a path."""
        try:
            path_str = str(path.relative_to(self.go_mod_path))
            
            # Split module path and version
            parts = path_str.split('@')
            module_name = parts[0]
            version = parts[1] if len(parts) > 1 else None

            # Decode URL-encoded characters
            decoded_name = urllib.parse.unquote(module_name)

            # Handle Go's special uppercase encoding
            if decoded_name.startswith('!'):
                name_parts = decoded_name[1:].split('/')
                if len(name_parts) > 1:
                    # This is a rough approximation and might need refinement
                    # For example, github.com/!azure/go-autorest becomes github.com/Azure/go-autorest
                    decoded_name = f"{name_parts[0]}/{'/'.join(name_parts[1:])}".replace("!","")


            return decoded_name, version

        except ValueError:
            return None, None
    
    def _scan_modules(self) -> List[Dict]:
        """Enhanced module scanning with progress indication and better filtering"""
        if not self.go_mod_path.exists():
            print(f"❌ Go modules directory not found at {self.go_mod_path}", file=sys.stderr)
            print("   Make sure you have Go installed and have downloaded some modules", file=sys.stderr)
            sys.exit(1)
        
        modules = []
        seen_modules = set()  # Track unique module names
        
        # Get all potential module directories
        print("📂 Discovering modules...", file=sys.stderr)
        all_paths = [p for p in self.go_mod_path.rglob("*@*") if p.is_dir()]
        total_paths = len(all_paths)
        
        if total_paths == 0:
            print("❌ No Go modules found. Try running 'go mod download' in a Go project first.", file=sys.stderr)
            sys.exit(1)
        
        print(f"📦 Found {total_paths} potential module directories", file=sys.stderr)
        
        processed = 0
        for path in all_paths:
            # Show progress every 10 modules
            if processed % 10 == 0 and processed > 0:
                print(f"🔄 Processing... {processed}/{total_paths} ({processed/total_paths*100:.1f}%)", end='\r', file=sys.stderr)
            
            # Enhanced filtering
            path_str = str(path)
            skip_patterns = [
                "cache/download",
                "testdata",
                "test/",
                ".git/",
                "vendor/",
                "node_modules/",
                "__pycache__/",
            ]
            
            if any(pattern in path_str for pattern in skip_patterns):
                processed += 1
                continue
            
            # Skip if it doesn't look like a real module directory
            if not any(file.suffix in ['.go', '.mod', '.sum'] for file in path.iterdir() if file.is_file()):
                processed += 1
                continue
            
            module_name, module_version = self._extract_module_info(path)
            if not module_name or module_name in seen_modules:
                processed += 1
                continue
            
            seen_modules.add(module_name)
            
            # Check if trusted
            is_trusted = self._is_trusted(module_name)
            trusted_status = "✅ Trusted" if is_trusted else "❓ Unverified"
            
            advisory_status, has_advisories, advisories = self._get_advisory_info(module_name, module_version)
            
            module_info = {
                "name": module_name,
                "version": module_version,
                "path": str(path),
                "is_trusted": is_trusted,
                "has_advisories": has_advisories,
                "advisories": advisories,
                "trusted_status": trusted_status,
                "advisory_status": advisory_status,
                "last_modified": path.stat().st_mtime if path.exists() else None
            }
            
            modules.append(module_info)
            
            # Update stats
            self.stats["total"] += 1
            if is_trusted:
                self.stats["trusted"] += 1
            else:
                self.stats["untrusted"] += 1
            if has_advisories:
                self.stats["with_advisories"] += 1
            
            processed += 1
        
        # Clear progress line
        print(" " * 80, end='\r', file=sys.stderr)
        
        # Sort modules by name for consistent output
        modules.sort(key=lambda x: x['name'].lower())
        
        return modules
    
    def print_console_output(self):
        """Enhanced console output with better formatting"""
        print(file=sys.stderr)
        
        # Group by trust status for better readability
        trusted_modules = [m for m in self.results if m['is_trusted']]
        untrusted_modules = [m for m in self.results if not m['is_trusted']]
        advisory_modules = [m for m in self.results if m['has_advisories']]
        
        # Show modules with advisories first (if any)
        if advisory_modules:
            print("🚨 MODULES WITH SECURITY ADVISORIES:", file=sys.stderr)
            print("=" * 50, file=sys.stderr)
            for module in advisory_modules:
                print(f"�� {module['advisory_status']} | {module['name']}", file=sys.stderr)
            print(file=sys.stderr)
        
        # Show trusted modules
        if trusted_modules:
            print("✅ TRUSTED MODULES:", file=sys.stderr)
            print("=" * 30, file=sys.stderr)
            for module in trusted_modules:
                print(f"{module['trusted_status']} | {module['advisory_status']} | {module['name']}", file=sys.stderr)
            print(file=sys.stderr)
        
        # Show untrusted modules
        if untrusted_modules:
            print("❓ UNVERIFIED MODULES:", file=sys.stderr)
            print("=" * 30, file=sys.stderr)
            for module in untrusted_modules:
                print(f"{module['trusted_status']} | {module['advisory_status']} | {module['name']}", file=sys.stderr)
            print(file=sys.stderr)
        
        # Enhanced summary
        print("📊 DETAILED SUMMARY", file=sys.stderr)
        print("=" * 20, file=sys.stderr)
        print(f"Total modules found: {self.stats['total']}", file=sys.stderr)
        print(f"Trusted modules: {self.stats['trusted']} ({self.stats['trusted']/self.stats['total']*100:.1f}%)", file=sys.stderr)
        print(f"Unverified modules: {self.stats['untrusted']} ({self.stats['untrusted']/self.stats['total']*100:.1f}%)", file=sys.stderr)
        
        if self.depsdev_cmd:
            print(f"Modules with advisories: {self.stats['with_advisories']}", file=sys.stderr)
            if self.stats['with_advisories'] > 0:
                print("   ⚠️  IMMEDIATE ATTENTION REQUIRED!", file=sys.stderr)
        
        # Provide actionable recommendations
        print("\n📋 RECOMMENDATIONS:", file=sys.stderr)
        print("=" * 20, file=sys.stderr)
        
        if self.stats['with_advisories'] > 0:
            print("🔴 HIGH PRIORITY: Update or replace modules with security advisories", file=sys.stderr)
        
        if self.stats['untrusted'] > 0:
            print("🟡 MEDIUM PRIORITY: Review unverified modules for legitimacy", file=sys.stderr)
            print("   - Check module repositories and maintainers", file=sys.stderr)
            print("   - Verify module necessity in your projects", file=sys.stderr)
            print("   - Consider alternatives from trusted sources", file=sys.stderr)
        
        if self.stats['untrusted'] == 0 and self.stats['with_advisories'] == 0:
            print("🟢 EXCELLENT: All modules are trusted with no known vulnerabilities", file=sys.stderr)
        
        print(file=sys.stderr)
    
    def export_json(self, filename: Optional[str] = None) -> Optional[str]:
        """Enhanced JSON export with more metadata. If filename is None, returns JSON string."""
        output = {
            "audit_date": datetime.utcnow().isoformat() + "Z",
            "audit_version": "2.0",
            "system_info": {
                "go_mod_path": str(self.go_mod_path),
                "depsdev_available": self.depsdev_cmd is not None,
                "total_trusted_domains": len(TRUSTED_DOMAINS)
            },
            "summary": self.stats,
            "trusted_domains": TRUSTED_DOMAINS,
            "modules": self.results,
            "recommendations": self._generate_recommendations()
        }
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2, default=str)
            print(f"📄 Enhanced JSON report saved to: {filename}", file=sys.stderr)
            return None
        else:
            return json.dumps(output, indent=2, default=str)
    
    def _generate_recommendations(self) -> Dict[str, List[str]]:
        """Generate actionable recommendations based on audit results"""
        recommendations = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": []
        }
        
        if self.stats['with_advisories'] > 0:
            recommendations["high_priority"].extend([
                f"Update or replace {self.stats['with_advisories']} modules with security advisories",
                "Run 'go mod tidy' and 'go get -u' to update dependencies",
                "Review advisory details using 'depsdev advisory' command"
            ])
        
        if self.stats['untrusted'] > 0:
            recommendations["medium_priority"].extend([
                f"Review {self.stats['untrusted']} unverified modules",
                "Check module repositories for active maintenance",
                "Verify module authors and organization legitimacy",
                "Consider adding frequently used domains to trusted list"
            ])
        
        recommendations["low_priority"].extend([
            "Set up automated dependency scanning in CI/CD",
            "Regularly audit dependencies (monthly recommended)",
            "Monitor security advisories for your technology stack"
        ])
        
        return recommendations

    def audit(self) -> List[Dict]:
        """Perform the audit"""
        print("🔍 Auditing Go modules...", file=sys.stderr)
        print(f"📂 Scanning: {self.go_mod_path}", file=sys.stderr)
        
        self.results = self._scan_modules()
        return self.results
    
    def export_markdown(self, filename: str):
        """Enhanced export results to Markdown"""
        with open(filename, 'w') as f:
            f.write("# Go Modules Security Audit Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Audit Version:** 2.0\n")
            f.write(f"**depsdev Available:** {'✅ Yes' if self.depsdev_cmd else '❌ No'}\n\n")
            
            # Enhanced Summary
            f.write("## 📊 Summary\n\n")
            f.write(f"- **Total modules found:** {self.stats['total']}\n")
            f.write(f"- **Trusted modules:** {self.stats['trusted']} ({self.stats['trusted']/self.stats['total']*100:.1f}%)\n")
            f.write(f"- **Unverified modules:** {self.stats['untrusted']} ({self.stats['untrusted']/self.stats['total']*100:.1f}%)\n")
            if self.depsdev_cmd:
                f.write(f"- **Modules with advisories:** {self.stats['with_advisories']}\n")
            f.write("\n")
            
            # Security Status
            if self.stats['with_advisories'] > 0:
                f.write("## 🚨 Security Alert\n\n")
                f.write(f"**{self.stats['with_advisories']} modules have known security vulnerabilities!**\n\n")
                f.write("These require immediate attention. See the detailed module list below.\n\n")
            
            # Trusted Domains
            f.write("## ✅ Trusted Domains\n\n")
            f.write("The following domains are considered trusted:\n\n")
            for domain in TRUSTED_DOMAINS:
                f.write(f"- `{domain}`\n")
            f.write("\n")
            
            # Modules with Advisories (if any)
            if self.stats['with_advisories'] > 0:
                advisory_modules = [m for m in self.results if m['has_advisories']]
                f.write("## 🚨 Modules with Security Advisories\n\n")
                f.write("| Module | Advisory Status | Path |\n")
                f.write("|--------|----------------|------|\n")
                for module in advisory_modules:
                    f.write(f"| `{module['name']}` | {module['advisory_status']} | `{module['path']}` |\n")
                f.write("\n")
            
            # All Module Details
            f.write("## 📋 All Module Details\n\n")
            f.write("| Trust Status | Advisory Status | Module | Path |\n")
            f.write("|-------------|----------------|--------|------|\n")
            
            for module in self.results:
                f.write(f"| {module['trusted_status']} | {module['advisory_status']} | `{module['name']}` | `{module['path']}` |\n")
            
            # Recommendations
            recommendations = self._generate_recommendations()
            f.write(f"\n## 📋 Recommendations\n\n")
            
            if recommendations['high_priority']:
                f.write(f"### 🔴 High Priority Actions\n\n")
                for rec in recommendations['high_priority']:
                    f.write(f"- {rec}\n")
                f.write("\n")
            
            if recommendations['medium_priority']:
                f.write(f"### 🟡 Medium Priority Actions\n\n")
                for rec in recommendations['medium_priority']:
                    f.write(f"- {rec}\n")
                f.write("\n")
            
            if recommendations['low_priority']:
                f.write(f"### 🟢 Low Priority Actions\n\n")
                for rec in recommendations['low_priority']:
                    f.write(f"- {rec}\n")
                f.write("\n")
            
            # Additional Security Guidance
            if self.stats['untrusted'] > 0:
                f.write(f"## 🔍 Unverified Module Review Guide\n\n")
                f.write("For each unverified module, consider:\n\n")
                f.write("1. **Repository Analysis**\n")
                f.write("   - Check GitHub/GitLab repository activity\n")
                f.write("   - Review commit history and contributors\n")
                f.write("   - Look for security policy and issue responses\n\n")
                f.write("2. **Code Quality Assessment**\n")
                f.write("   - Review source code if possible\n")
                f.write("   - Check for automated testing\n")
                f.write("   - Look for dependency management practices\n\n")
                f.write("3. **Community Trust**\n")
                f.write("   - Check download statistics\n")
                f.write("   - Review community feedback and issues\n")
                f.write("   - Look for endorsements from trusted sources\n\n")
                f.write("4. **Alternatives**\n")
                f.write("   - Search for similar modules from trusted domains\n")
                f.write("   - Consider implementing functionality in-house\n")
                f.write("   - Evaluate if the module is truly necessary\n\n")
            
            # Footer
            f.write("---\n")
            f.write("*Report generated by Enhanced Go Module Security Auditor v2.0*\n")
            f.write(f"*Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")
        
        print(f"📄 Enhanced Markdown report saved to: {filename}", file=sys.stderr)


def main():
    """Main function to run the auditor"""
    parser = argparse.ArgumentParser(
        description="Enhanced Go Module Security Auditor v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python audit_go_modules.py                    # Console output (default)
  python audit_go_modules.py --json             # Export to JSON
  python audit_go_modules.py --markdown         # Export to Markdown
  python audit_go_modules.py --json --markdown  # Export to both formats
        """
    )
    parser.add_argument("--json", action="store_true",
                        help="Export results to JSON file")
    parser.add_argument("--stdout", action="store_true",
                        help="Output JSON to stdout instead of a file")
    parser.add_argument("--markdown", action="store_true",
                       help="Export results to Markdown file")
    parser.add_argument("--console", action="store_true", 
                       help="Output to console (default)")
    parser.add_argument("--quiet", action="store_true",
                       help="Suppress progress output")
    parser.add_argument("--version", action="version", version="Go Module Security Auditor v2.0")
    
    args = parser.parse_args()
    
    # Default to console if no format specified
    if not (args.json or args.markdown):
        args.console = True
    
    try:
        # Create auditor and run audit
        auditor = ModuleAuditor()
        auditor.audit()
        
        # Always show console output unless explicitly suppressed
        if args.console or not (args.json or args.markdown):
            auditor.print_console_output()
        
        # Export if requested
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if args.json:
            if args.stdout:
                print(auditor.export_json())
            else:
                filename = f"go_modules_audit_{timestamp}.json"
                auditor.export_json(filename, file=sys.stderr)
        
        if args.markdown:
            filename = f"go_modules_audit_{timestamp}.md"
            auditor.export_markdown(filename, file=sys.stderr)
        
        # Exit with appropriate code based on findings
        if auditor.stats['with_advisories'] > 0:
            print("\n🚨 Critical: Found modules with security advisories!", file=sys.stderr)
            print("   Action required: Update or replace vulnerable modules", file=sys.stderr)
            sys.exit(2)  # Critical security issues
        elif auditor.stats['untrusted'] > 0:
            print("\n⚠️  Warning: Found unverified modules that may need review", file=sys.stderr)
            print("   Recommendation: Review unverified modules for security", file=sys.stderr)
            sys.exit(1)  # Warning condition
        else:
            print("\n✅ Excellent: All modules are from trusted sources with no known vulnerabilities", file=sys.stderr)
            sys.exit(0)  # All clear
            
    except KeyboardInterrupt:
        print("\n\n❌ Audit interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error during audit: {str(e)}", file=sys.stderr)
        if not args.quiet:
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
