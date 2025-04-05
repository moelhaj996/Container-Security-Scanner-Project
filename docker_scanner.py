import subprocess
import json
from rich.console import Console
from rich.table import Table
import tempfile
import os

console = Console()

class DockerImageScanner:
    def __init__(self):
        self._check_trivy_installation()

    def _check_trivy_installation(self):
        """Check if Trivy is installed and accessible."""
        try:
            subprocess.run(['trivy', '--version'], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            console.print("[red]Error: Trivy is not installed or not accessible.[/red]")
            console.print("Please install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
            raise
        except FileNotFoundError:
            console.print("[red]Error: Trivy is not installed.[/red]")
            console.print("Please install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
            raise

    def scan_image(self, image_name):
        """Scan a Docker image using Trivy."""
        console.print(f"[blue]Scanning image: {image_name}[/blue]")
        
        # Create a temporary file for JSON output
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            try:
                # Run Trivy scan with JSON output
                subprocess.run([
                    'trivy',
                    'image',
                    '--format', 'json',
                    '--output', temp_file.name,
                    image_name
                ], check=True)
                
                # Read and parse the JSON results
                with open(temp_file.name, 'r') as f:
                    results = json.load(f)
                
                self._display_results(results)
                
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Error scanning image: {str(e)}[/red]")
            finally:
                # Clean up temporary file
                os.unlink(temp_file.name)

    def _display_results(self, results):
        """Display the scan results in a formatted table."""
        if not results.get('Results'):
            console.print("[green]No vulnerabilities found![/green]")
            return

        # Create vulnerability summary table
        summary_table = Table(title="Vulnerability Summary")
        summary_table.add_column("Severity")
        summary_table.add_column("Count")
        
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }

        # Count vulnerabilities by severity
        for target in results['Results']:
            if target.get('Vulnerabilities'):
                for vuln in target['Vulnerabilities']:
                    severity = vuln.get('Severity', 'UNKNOWN').upper()
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Add rows to summary table with appropriate colors
        for severity, count in severity_counts.items():
            if count > 0:
                color = self._get_severity_color(severity)
                summary_table.add_row(f"[{color}]{severity}[/{color}]", str(count))

        console.print(summary_table)

        # Create detailed vulnerability table
        detail_table = Table(title="Detailed Vulnerabilities")
        detail_table.add_column("Severity")
        detail_table.add_column("Package")
        detail_table.add_column("Installed Version")
        detail_table.add_column("Fixed Version")
        detail_table.add_column("Vulnerability ID")

        # Add vulnerabilities to detail table
        for target in results['Results']:
            if target.get('Vulnerabilities'):
                for vuln in target['Vulnerabilities']:
                    severity = vuln.get('Severity', 'UNKNOWN').upper()
                    color = self._get_severity_color(severity)
                    detail_table.add_row(
                        f"[{color}]{severity}[/{color}]",
                        vuln.get('PkgName', 'N/A'),
                        vuln.get('InstalledVersion', 'N/A'),
                        vuln.get('FixedVersion', 'N/A'),
                        vuln.get('VulnerabilityID', 'N/A')
                    )

        console.print(detail_table)

    def _get_severity_color(self, severity):
        """Get the appropriate color for a severity level."""
        return {
            'CRITICAL': 'red1',
            'HIGH': 'red3',
            'MEDIUM': 'yellow',
            'LOW': 'green',
            'UNKNOWN': 'blue'
        }.get(severity.upper(), 'white')

    def scan_dockerfile(self, dockerfile_path):
        """Scan a Dockerfile for security issues."""
        console.print(f"[blue]Scanning Dockerfile: {dockerfile_path}[/blue]")
        
        try:
            # Run Trivy config scan with JSON output
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
                subprocess.run([
                    'trivy',
                    'config',
                    '--format', 'json',
                    '--output', temp_file.name,
                    dockerfile_path
                ], check=True)
                
                # Read and parse the JSON results
                with open(temp_file.name, 'r') as f:
                    results = json.load(f)
                
                self._display_misconfig_results(results)
                
                os.unlink(temp_file.name)
                
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error scanning Dockerfile: {str(e)}[/red]")

    def _display_misconfig_results(self, results):
        """Display misconfigurations found in Dockerfile."""
        if not results.get('Results'):
            console.print("[green]No misconfigurations found![/green]")
            return

        table = Table(title="Dockerfile Misconfigurations")
        table.add_column("Type")
        table.add_column("ID")
        table.add_column("Severity")
        table.add_column("Description")
        table.add_column("Line")

        for result in results['Results']:
            for misc in result.get('Misconfigurations', []):
                severity = misc.get('Severity', 'UNKNOWN').upper()
                color = self._get_severity_color(severity)
                table.add_row(
                    misc.get('Type', 'N/A'),
                    misc.get('ID', 'N/A'),
                    f"[{color}]{severity}[/{color}]",
                    misc.get('Description', 'N/A'),
                    str(misc.get('Line', 'N/A'))
                )

        console.print(table)

    def scan_directory(self, directory_path):
        """Scan a directory for vulnerabilities in container-related files."""
        console.print(f"[blue]Scanning directory: {directory_path}[/blue]")
        
        try:
            # Run Trivy filesystem scan with JSON output
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
                subprocess.run([
                    'trivy',
                    'fs',
                    '--format', 'json',
                    '--output', temp_file.name,
                    directory_path
                ], check=True)
                
                # Read and parse the JSON results
                with open(temp_file.name, 'r') as f:
                    results = json.load(f)
                
                self._display_results(results)
                
                os.unlink(temp_file.name)
                
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error scanning directory: {str(e)}[/red]")

    def scan_image_with_policy(self, image_name, policy_bundle=None):
        """Scan a Docker image using custom security policies."""
        console.print(f"[blue]Scanning image with custom policies: {image_name}[/blue]")
        
        try:
            cmd = ['trivy', 'image']
            
            if policy_bundle:
                cmd.extend(['--policy', policy_bundle])
            
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
                cmd.extend([
                    '--format', 'json',
                    '--output', temp_file.name,
                    image_name
                ])
                
                subprocess.run(cmd, check=True)
                
                with open(temp_file.name, 'r') as f:
                    results = json.load(f)
                
                self._display_results(results)
                
                os.unlink(temp_file.name)
                
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error scanning image with policies: {str(e)}[/red]") 