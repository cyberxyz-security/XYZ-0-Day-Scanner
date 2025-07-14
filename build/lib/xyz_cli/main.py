#!/usr/bin/env python3
"""
XYZ CLI Tool - API-based Vulnerability Scanner
Unified command-line interface for vulnerability scanning via XYZ API
"""

import os
import sys
import json
import socket
import platform
import subprocess
import stat
import click
from typing import Optional, List, Dict, Any
from tabulate import tabulate
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from xyz_cli.client import XYZAPIClient

# Initialize Rich console for better formatting
console = Console()

# Global client instance
client = None

def get_computer_name():
    system = platform.system()
    if system == "Darwin":
        try:
            return subprocess.check_output(['scutil', '--get', 'ComputerName']).decode().strip()
        except Exception:
            return platform.node()
    elif system == "Windows":
        return platform.node()
    else:
        return socket.gethostname()

def init_client():
    """Initialize the API client"""
    global client
    if client is None:
        try:
            client = XYZAPIClient()
        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}")
            console.print("\n[yellow]Setup Instructions:[/yellow]")
            console.print("1. Login using: [bold]xyz login[/bold]")
            console.print("2. (or) Set your API key: [bold]export XYZ_API_KEY=sk_xyz_your_key_here[/bold]")
            console.print("3. Set API URL (optional): [bold]export XYZ_API_URL=https://api.xyz-security.com[/bold]")
            console.print("4. Contact support@xyz-security.com for access.")
            sys.exit(1)
        
        # Check if client is authenticated
        if 'Authorization' not in client.session.headers:
            console.print("[red]Error:[/red] You are not logged in and no API key is configured.")
            console.print("Please run [bold]xyz login[/bold] or set the [bold]XYZ_API_KEY[/bold] environment variable.")
            sys.exit(1)

def format_vulnerability_table(vulnerabilities: List[Dict], include_exploits: bool = False, package_version: Optional[str] = None) -> Table:
    """Format vulnerabilities as a Rich table"""
    title = "Vulnerability Results"
    if package_version:
        title += f" for version {package_version}"
    table = Table(title=title)
    
    # Add columns
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Package", style="magenta")
    table.add_column("Ecosystem", style="blue")
    table.add_column("Version", style="green")
    table.add_column("Severity", style="red")
    table.add_column("CVSS", justify="right")
    table.add_column("Published", style="yellow")
    table.add_column("Modified", style="blue")
    table.add_column("Aliases", style="dim")
    table.add_column("Summary", style="dim")
    
    if include_exploits:
        table.add_column("Exploits", style="red")
    
    for vuln in vulnerabilities:
        # Determine status indicators
        status_parts = []
        if vuln.get('malicious_info', {}).get('is_malicious'):
            status_parts.append("[red]MALICIOUS[/red]")
        if vuln.get('exploit_info', {}).get('has_exploits'):
            status_parts.append("[orange1]HAS EXPLOIT[/orange1]")
        if vuln.get('exploited_in_wild'):
            status_parts.append("[red]EXPLOITED IN WILD[/red]")
        
        status = " | ".join(status_parts) if status_parts else "Clean"
        
        # Format severity with color
        severity = (vuln.get('severity') or 'UNKNOWN').upper()
        
        cvss_score = vuln.get('cvss_score')
        if cvss_score:
            try:
                score = float(cvss_score)
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            except (ValueError, TypeError):
                pass # Keep original severity if score is not a valid float
        if severity == 'CRITICAL':
            severity_colored = f"[red]{severity}[/red]"
        elif severity == 'HIGH':
            severity_colored = f"[orange1]{severity}[/orange1]"
        elif severity == 'MEDIUM':
            severity_colored = f"[yellow]{severity}[/yellow]"
        else:
            severity_colored = f"[green]{severity}[/green]"
        
        # Build row
        row = [
            vuln.get('cve_id', 'N/A'),
            vuln.get('package_name', 'N/A'),
            vuln.get('ecosystem', 'N/A'),
            package_version or "N/A",
            severity_colored,
            str(vuln.get('cvss_score', 'N/A')),
            vuln.get('publication_date', 'N/A'),
            vuln.get('modified_at', 'N/A'),
            ', '.join(vuln.get('aliases', [])),
            vuln.get('description', 'N/A')
        ]
        
        if include_exploits:
            exploit_count = len(vuln.get('exploit_info', {}).get('exploits', []))
            row.append(str(exploit_count) if exploit_count > 0 else "0")
        
        table.add_row(*row)
    
    return table

def print_vulnerability_details(vuln: Dict, include_exploits: bool = False):
    """Print detailed vulnerability information"""
    console.print(f"\n[bold cyan]Vulnerability Details: {vuln.get('id', 'N/A')}[/bold cyan]")
    
    # Basic info
    info_table = Table(show_header=False, box=None)
    info_table.add_column("Field", style="bold")
    info_table.add_column("Value")
    
    info_table.add_row("Package", vuln.get('package_name') or 'N/A')
    info_table.add_row("Ecosystem", vuln.get('ecosystem') or 'N/A')
    info_table.add_row("Severity", vuln.get('severity') or 'N/A')
    info_table.add_row("CVSS Score", str(vuln.get('cvss_score') or 'N/A'))
    info_table.add_row("Description", (vuln.get('description') or 'N/A')[:100] + "..." if len(vuln.get('description', '')) > 100 else (vuln.get('description') or 'N/A'))
    
    console.print(info_table)
    
    # Malicious package info
    if vuln.get('malicious_info', {}).get('is_malicious'):
        console.print("\n[red]⚠️  MALICIOUS PACKAGE DETECTED[/red]")
        malicious_info = vuln['malicious_info']
        console.print(f"Source: {malicious_info.get('source', 'N/A')}")
        console.print(f"Detected: {malicious_info.get('detection_date', 'N/A')}")
        if malicious_info.get('references'):
            console.print(f"References: {', '.join(malicious_info['references'][:3])}")
    
    # Exploit info
    if include_exploits and vuln.get('exploit_info', {}).get('has_exploits'):
        console.print("\n[orange1]🔓 EXPLOIT INFORMATION[/orange1]")
        exploits = vuln['exploit_info'].get('exploits', [])
        
        exploit_table = Table()
        exploit_table.add_column("Author", style="cyan")
        exploit_table.add_column("Type", style="magenta")
        exploit_table.add_column("Platform", style="blue")
        exploit_table.add_column("Verified", style="green")
        
        for exploit in exploits[:5]:  # Show first 5 exploits
            exploit_table.add_row(
                exploit.get('author', 'N/A'),
                exploit.get('type', 'N/A'),
                exploit.get('platform', 'N/A'),
                "✅" if exploit.get('verified') else "❌"
            )
        
        console.print(exploit_table)
        
        if len(exploits) > 5:
            console.print(f"... and {len(exploits) - 5} more exploits")

@click.group()
@click.option('--api-key', envvar='XYZ_API_KEY', help='API key for XYZ Vulnerability API')
@click.option('--api-url', envvar='XYZ_API_URL', default='http://localhost:8000', help='API base URL')
@click.option('--debug', is_flag=True, help='Enable debug output')
@click.pass_context
def cli(ctx, api_key, api_url, debug):
    """XYZ Vulnerability Scanner - API-based CLI tool"""
    ctx.ensure_object(dict)
    ctx.obj['api_key'] = api_key
    ctx.obj['api_url'] = api_url
    ctx.obj['debug'] = debug
    
    if debug:
        console.print(f"[dim]API URL: {api_url}[/dim]")
        console.print(f"[dim]API Key: {'Set' if api_key else 'Not set'}[/dim]")

@cli.command()
@click.pass_context
def info(ctx):
    """Show API information and capabilities"""
    init_client()
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="Fetching API info...", total=None)
            
            api_info = client.get_api_info()
            health = client.health_check()
        
        # User status
        user_info = client.get_user_info()
        if user_info and 'email' in user_info:
            login_status = f"[green]Logged in as: {user_info['email']}[/green]"
        else:
            login_status = "[yellow]Not logged in[/yellow]"

        console.print(Panel.fit(f"[bold green]XYZ Vulnerability API[/bold green]\nVersion: {api_info.get('api_version', 'N/A')}\nStatus: {health.get('status', 'Unknown')}\nUser: {login_status}"))
        
        # Features
        console.print("\n[bold]Features:[/bold]")
        features = api_info.get('features', {})
        features['apt_zero_day'] = True  # Manually add this feature
        for feature, enabled in features.items():
            status = "✅" if enabled else "❌"
            feature_text = feature.replace('_', ' ').title()
            if feature == 'apt_zero_day':
                feature_text = "APT Zero-Day Vulnerabilities Detection + Exploitatbility"
            console.print(f"  {status} {feature_text}")
        
        # Supported formats
        console.print(f"\n[bold]Supported Vulnerability Types:[/bold]")
        for vuln_type in api_info.get('supported_vulnerabilities', []):
            console.print(f"  • {vuln_type}")
        
        # Rate limits
        console.print(f"\n[bold]Rate Limits:[/bold]")
        for tier, limit in api_info.get('rate_limits', {}).items():
            console.print(f"  • {tier.title()}: {limit}")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.argument('vuln_id')
@click.option('-x', '--exploits', is_flag=True, help='Include exploit information')
@click.option('--affected', is_flag=True, help='Show affected packages')
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
@click.pass_context
def vuln(ctx, vuln_id, exploits, affected, output_json):
    """Search for a specific vulnerability by ID (CVE, GHSA, OSV, etc.)"""
    init_client()
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description=f"Searching for {vuln_id}...", total=None)
            
            result = client.search_vulnerability_by_id(vuln_id, include_exploits=exploits)
        
        if output_json:
            console.print(json.dumps(result, indent=2))
        else:
            vulnerabilities = result.get('vulnerabilities', [])
            if vulnerabilities:
                table = format_vulnerability_table(vulnerabilities, include_exploits=exploits)
                console.print(table)
                
                # Show detailed info for first vulnerability
                if vulnerabilities:
                    print_vulnerability_details(vulnerabilities[0], include_exploits=exploits)
                    
                    # Show affected packages if requested
                    if affected:
                        console.print("\n[bold cyan]🎯 Affected Packages:[/bold cyan]")
                        affected_packages = set()
                        for vuln in vulnerabilities:
                            if vuln.get('package_name'):
                                pkg_name = vuln.get('package_name')
                                ecosystem = vuln.get('ecosystem', 'Unknown')
                                affected_packages.add(f"{pkg_name} ({ecosystem})")
                        
                        if affected_packages:
                            for package in sorted(affected_packages):
                                console.print(f"  • {package}")
                        else:
                            console.print("  [dim]No specific package information available[/dim]")
            else:
                console.print(f"[yellow]No vulnerabilities found for {vuln_id}[/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.argument('package_name')
@click.option('-e', '--ecosystem', help='Filter by ecosystem (npm, pypi, maven, etc.)')
@click.option('-v', '--version', help='Filter by package version')
@click.option('-s', '--severity', help='Filter by severity (critical, high, medium, low)')
@click.option('-x', '--exploits', is_flag=True, help='Include exploit information')
@click.option('--limit', default=50, help='Maximum results to return')
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
@click.pass_context
def package(ctx, package_name, ecosystem, version, severity, exploits, limit, output_json):
    """Search for vulnerabilities affecting a specific package"""
    init_client()
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description=f"Scanning package {package_name}...", total=None)
            
            result = client.search_package_vulnerabilities(
                package_name=package_name,
                ecosystem=ecosystem,
                version=version,
                severity=severity,
                limit=limit,
                include_exploits=exploits,
                machine_name=socket.gethostname(),
                os_type=platform.system(),
                computer_name=get_computer_name(),
                scan_command=f"xyz package {package_name}" + (f" -v {version}" if version else "")
            )
        
        if output_json:
            console.print(json.dumps(result, indent=2))
        else:
            packages = result.get('packages', [])
            if packages:
                # Show summary
                summary = result.get('summary', {})
                console.print(f"\n[bold]Scan Results for '{package_name}'[/bold]")
                console.print(f"Packages found: {summary.get('total_packages', 0)}")
                console.print(f"Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
                
                # Show each package's vulnerabilities
                for pkg in packages:
                    console.print(f"\n[bold cyan]📦 {pkg['package_name']} ({pkg['ecosystem']})[/bold cyan]")
                    console.print(f"Vulnerabilities: {pkg['vulnerability_count']}")
                    
                    # Show severity breakdown
                    severity_summary = pkg.get('severity_summary', {})
                    if severity_summary:
                        console.print("Severity breakdown:")
                        for sev, count in severity_summary.items():
                            console.print(f"  • {sev.title()}: {count}")
                    
                    # Show vulnerability table
                    if pkg['vulnerabilities']:
                        table = format_vulnerability_table(pkg['vulnerabilities'], include_exploits=exploits, package_version=version)
                        console.print(table)
            else:
                console.print(f"[yellow]No vulnerabilities found for package '{package_name}'[/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--python', 'scan_python', is_flag=True, help='Scan Python packages')
@click.option('--npm', 'scan_npm', is_flag=True, help='Scan npm packages')
@click.option('-i', '--system', 'scan_system', is_flag=True, help='Scan system packages')
@click.option('--java', 'scan_java', is_flag=True, help='Scan Java packages')
@click.option('--go', 'scan_go', is_flag=True, help='Scan Go packages')
@click.option('--php', 'scan_php', is_flag=True, help='Scan PHP packages')
@click.option('--microsoft', 'scan_microsoft', is_flag=True, help='Scan Microsoft packages')
@click.option('--all', 'scan_all', is_flag=True, help='Scan all package types')
@click.option('-x', '--exploits', is_flag=True, help='Include exploit information')
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
@click.option('--list-packages', is_flag=True, help='Only list installed packages, do not scan for vulnerabilities')
@click.pass_context
def scan(ctx, scan_python, scan_npm, scan_system, scan_java, scan_go, scan_php, scan_microsoft, scan_all, exploits, output_json, list_packages):
    """Scan installed packages for vulnerabilities"""
    init_client()
    
    if list_packages:
        console.print("[bold]Listing installed packages...[/bold]")
        
        package_types = []
        if scan_python or scan_all:
            package_types.append("python")
        if scan_npm or scan_all:
            package_types.append("npm")
        if scan_system or scan_all:
            package_types.append("system")
        if scan_java or scan_all:
            package_types.append("java")
        if scan_go or scan_all:
            package_types.append("go")
        if scan_php or scan_all:
            package_types.append("php")
        if scan_microsoft or scan_all:
            package_types.append("microsoft")
            
        results = client.list_packages(
            package_types=package_types,
            machine_name=socket.gethostname(),
            os_type=platform.system(),
            computer_name=get_computer_name()
        )
        
        for pkg_type, pkgs in results.items():
            console.print(f"\n[bold cyan]{pkg_type.title()} Packages[/bold cyan]")
            if pkgs:
                for pkg in pkgs:
                    if 'type' in pkg:
                        console.print(f"  - {pkg['name']} ({pkg['version']}) [{pkg['type']}]")
                    else:
                        console.print(f"  - {pkg['name']} ({pkg['version']})")
            else:
                console.print("  [dim]No packages found.[/dim]")
        return

    # Handle scan type selection
    if scan_all:
        scan_python = scan_npm = scan_system = scan_java = scan_go = scan_php = scan_microsoft = True
    elif not any([scan_python, scan_npm, scan_system, scan_java, scan_go, scan_php, scan_microsoft]):
        # Default to Python and npm if none specified (matching legacy behavior)
        scan_python = True
        scan_npm = True
    
    results = {}
    
    try:
        if scan_python:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(description="Scanning Python packages...", total=None)
                
                results['python'] = client.scan_python_packages(include_exploits=exploits, machine_name=socket.gethostname(), os_type=platform.system(), computer_name=get_computer_name())
        
        if scan_npm:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(description="Scanning npm packages...", total=None)
                
                results['npm'] = client.scan_npm_packages(include_exploits=exploits, machine_name=socket.gethostname(), os_type=platform.system(), computer_name=get_computer_name())
        
        if scan_system:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(description="Scanning system packages...", total=None)
                
                try:
                    # For now, system scanning is not implemented in API backend
                    # This is a placeholder that matches the legacy CLI behavior
                    console.print("\n[yellow]⚠️  System package scanning not yet implemented in API backend[/yellow]")
                    console.print("[dim]Use the legacy CLI for system package scanning: ./xyz scan -i[/dim]")
                    results['system'] = {'scan_results': {'vulnerabilities': []}, 'message': 'Not implemented'}
                except Exception as e:
                    console.print(f"[red]Error scanning system packages:[/red] {e}")
                    results['system'] = {'error': str(e)}
        
        if scan_java:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(description="Scanning Java packages...", total=None)
                
                results['java'] = client.scan_java_packages(include_exploits=exploits, machine_name=socket.gethostname(), os_type=platform.system(), computer_name=get_computer_name())
        
        if scan_go:
            console.print("\n[yellow]⚠️  Go package scanning not yet implemented.[/yellow]")
            results['go'] = {'scan_results': {'vulnerabilities': []}, 'message': 'Not implemented'}
        
        if scan_php:
            console.print("\n[yellow]⚠️  PHP package scanning not yet implemented.[/yellow]")
            results['php'] = {'scan_results': {'vulnerabilities': []}, 'message': 'Not implemented'}

        if scan_microsoft:
            console.print("\n[yellow]⚠️  Microsoft package scanning not yet implemented.[/yellow]")
            results['microsoft'] = {'scan_results': {'vulnerabilities': []}, 'message': 'Not implemented'}
        
        if output_json:
            console.print(json.dumps(results, indent=2))
        else:
            # Display results for each scan type
            for scan_type, result in results.items():
                console.print(f"\n[bold]🔍 {scan_type.title()} Package Scan Results[/bold]")
                
                scan_results = result.get('scan_results', {})
                if scan_results.get('vulnerabilities'):
                    console.print(f"Vulnerabilities found: {len(scan_results['vulnerabilities'])}")
                    
                    # Show summary
                    if scan_results.get('summary'):
                        summary = scan_results['summary']
                        console.print(f"Critical: {summary.get('critical', 0)}")
                        console.print(f"High: {summary.get('high', 0)}")
                        console.print(f"Medium: {summary.get('medium', 0)}")
                        console.print(f"Low: {summary.get('low', 0)}")
                    
                    # Show vulnerability table
                    table = format_vulnerability_table(scan_results['vulnerabilities'][:20], include_exploits=exploits)
                    console.print(table)
                    
                    if len(scan_results['vulnerabilities']) > 20:
                        console.print(f"[dim]... and {len(scan_results['vulnerabilities']) - 20} more vulnerabilities[/dim]")
                else:
                    console.print("[green]✅ No vulnerabilities found[/green]")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--days', default=7, help='Number of days to look back')
@click.option('--limit', default=20, help='Maximum results to return')
@click.option('-x', '--exploits', is_flag=True, help='Include exploit information')
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
@click.pass_context
def recent(ctx, days, limit, exploits, output_json):
    """Show recent vulnerabilities"""
    init_client()
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description=f"Fetching recent vulnerabilities ({days} days)...", total=None)
            
            result = client.get_recent_vulnerabilities(days=days, limit=limit, include_exploits=exploits)
        
        if output_json:
            console.print(json.dumps(result, indent=2))
        else:
            vulnerabilities = result.get('vulnerabilities', [])
            if vulnerabilities:
                console.print(f"\n[bold]📅 Recent Vulnerabilities (Last {days} days)[/bold]")
                console.print(f"Total found: {result.get('total_count', 0)}")
                
                table = format_vulnerability_table(vulnerabilities, include_exploits=exploits)
                console.print(table)
            else:
                console.print(f"[yellow]No recent vulnerabilities found in the last {days} days[/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.pass_context
def stats(ctx):
    """Show database and API statistics"""
    init_client()
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="Fetching statistics...", total=None)
            
            db_stats = client.get_database_stats()
            eco_stats = client.get_ecosystem_stats()
        
        console.print("[bold]📊 Database Statistics[/bold]")
        
        # Database stats
        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value", style="cyan")
        
        for key, value in db_stats.get('vulnerability_counts', {}).items():
            stats_table.add_row(key.replace('_', ' ').title(), str(value))
        
        console.print(stats_table)
        
        # Ecosystem stats
        console.print("\n[bold]🌍 Top Ecosystems[/bold]")
        ecosystem_table = Table()
        ecosystem_table.add_column("Ecosystem", style="cyan")
        ecosystem_table.add_column("Packages", style="magenta", justify="right")
        
        for ecosystem, count in sorted(eco_stats.get('ecosystem_stats', {}).items(), key=lambda x: x[1], reverse=True)[:10]:
            ecosystem_table.add_row(ecosystem, str(count))
        
        console.print(ecosystem_table)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--email', prompt=True, help='Your email address')
@click.password_option(help='Your password')
@click.pass_context
def login(ctx, email, password):
    """Login to the XYZ API"""
    init_client()
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="Logging in...", total=None)
            result = client.login(email, password)
            client.session.headers['Authorization'] = f"Bearer {result['access_token']}"
            client.session.headers['Authorization'] = f"Bearer {result['access_token']}"
        
        console.print(f"[green]✅ Login successful![/green]")
        console.print(f"Welcome, {result['user_info']['email']}")
        console.print(f"Organization ID: {result['user_info']['organization_id']}")
        console.print("Your session is now active.")
        
    except ValueError as e:
        console.print(f"[red]Login failed:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]An unexpected error occurred:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.pass_context
def logout(ctx):
    """Logout and clear your session"""
    init_client()
    try:
        client.logout()
        console.print("[green]✅ You have been successfully logged out.[/green]")
    except Exception as e:
        console.print(f"[red]Error during logout:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.pass_context
def status(ctx):
    """Check login status"""
    init_client()
    
    user_info = client.get_user_info()
    
    if user_info and 'email' in user_info:
        console.print(f"[green]✅ Logged in as: {user_info['email']}[/green]")
        console.print(f"Organization ID: {user_info.get('organization_id', 'N/A')}")
    else:
        console.print("[yellow]You are not logged in.[/yellow]")
        console.print("Use [bold]xyz login[/bold] to authenticate.")

@cli.group()
def audit():
    """Audit local development environments."""
    pass

@audit.command()
@click.option('--json', 'output_json', is_flag=True, help='Output audit results as JSON')
def python(output_json):
    """Audit Python environment for vulnerabilities and dependency tree."""
    init_client()
    console.print("🐍 Starting comprehensive Python audit...")

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    script_path = os.path.join(project_root, 'audit_python_deps.py')

    if not os.path.exists(script_path):
        console.print(f"[red]Error:[/red] Audit script not found at {script_path}")
        sys.exit(1)
        
    # Ensure the script is executable
    if not os.access(script_path, os.X_OK):
        st = os.stat(script_path)
        os.chmod(script_path, st.st_mode | stat.S_IEXEC)

    try:
        # Using subprocess.run is simpler and less prone to deadlocks
        result = subprocess.run(
            ['python3', script_path],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=300 # 5 minute timeout
        )

        if result.returncode != 0:
            console.print(f"[red]❌ Python audit script failed.[/red]")
            console.print("[bold]Stderr:[/bold]")
            console.print(result.stderr)
            return

        try:
            report_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            console.print("[red]❌ Error: Failed to parse audit script JSON output.[/red]")
            console.print("[bold]Stdout:[/bold]")
            console.print(result.stdout)
            return

        if output_json:
            console.print(json.dumps(report_data, indent=2))
        else:
            console.print("[green]✅ Comprehensive Python audit complete.[/green]")

        # Now, send the data to the backend
        console.print("Uploading comprehensive Python audit report to the platform...")
        summary = {
            "total_vulnerabilities": len(report_data),
            "severity_distribution": {}
        }
        for vuln in report_data:
            severity = vuln.get("severity", "unknown").lower()
            summary["severity_distribution"][severity] = summary["severity_distribution"].get(severity, 0) + 1
        
        client.send_python_audit({
            "scan_results": {"dependency_tree": report_data},
            "summary": summary,
            "machine_name": socket.gethostname(),
            "os_type": platform.system(),
            "computer_name": get_computer_name(),
            "scan_command": "xyz audit python"
        })
        console.print("[green]✅ Successfully uploaded Python audit report.[/green]")

    except subprocess.TimeoutExpired:
        console.print("[red]❌ Error: The Python audit script timed out after 5 minutes.[/red]")
    except FileNotFoundError:
        console.print(f"[red]❌ Error: Could not find the '{script_path}' script.[/red]")
    except Exception as e:
        console.print(f"[red]An unexpected error occurred during Python audit:[/red] {e}")
        sys.exit(1)

@audit.command()
@click.option('--json', 'output_json', is_flag=True, help='Output audit results as JSON')
def go(output_json):
    """Audit Go modules"""
    init_client()
    console.print("Starting Go module audit...")
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    script_path = os.path.join(project_root, 'audit_go_modules.py')

    if not os.path.exists(script_path):
        console.print(f"[red]Error:[/red] Audit script not found at {script_path}")
        sys.exit(1)

    try:
        result = subprocess.run(
            ['python3', script_path, '--json', '--stdout', '--quiet'],
            capture_output=True, text=True, timeout=120, check=False
        )
        
        if not result.stdout:
            console.print(f"[red]Go audit script failed to produce output.[/red]")
            if result.stderr:
                console.print("[bold]Error details:[/bold]")
                console.print(result.stderr)
            sys.exit(1)
        
        if result.stderr:
            console.print("[bold]Audit script output:[/bold]")
            console.print(result.stderr)

        try:
            audit_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            console.print("[red]Error: Could not parse JSON output from audit script.[/red]")
            console.print("[bold]Script output:[/bold]")
            console.print(result.stdout)
            sys.exit(1)

        if output_json:
            console.print(json.dumps(audit_data, indent=2))
        else:
            console.print("[green]Go module audit complete.[/green]")
            summary = audit_data.get('summary', {})
            console.print(f"  Total modules: {summary.get('total')}")
            console.print(f"  [red]With advisories: {summary.get('with_advisories')}[/red]")
            console.print(f"  [yellow]Unverified: {summary.get('untrusted')}[/yellow]")


        # Now, send the data to the backend
        console.print("Sending audit results to the platform...")
        client.send_go_audit({
            **audit_data,
            "scan_command": "xyz audit go"
        })
        console.print("[green]Successfully uploaded Go audit results.[/green]")

    except Exception as e:
        console.print(f"[red]An error occurred during Go audit:[/red] {e}")
        sys.exit(1)

def main():
    """Main entry point for setuptools console_scripts"""
    cli()
 
if __name__ == '__main__':
    main()
