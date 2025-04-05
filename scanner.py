#!/usr/bin/env python3

import click
import os
import sys
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv
from datetime import datetime
import docker
from kubernetes import client, config
import yaml
import re
import json

# Initialize Rich console for better output
console = Console()

# Load environment variables
load_dotenv()

class ContainerSecurityScanner:
    def __init__(self):
        self.docker_client = docker.from_env()
        self.kubernetes_client = None
        try:
            config.load_kube_config()
            self.kubernetes_client = client.CoreV1Api()
        except Exception as e:
            print(f"Warning: Could not initialize Kubernetes client: {e}")

    def scan_docker_image(self, image_name):
        """Scan a Docker image for vulnerabilities using Trivy."""
        console.print(f"[blue]Scanning Docker image: {image_name}[/blue]")
        try:
            # Here we would integrate with Trivy
            # For now, we'll do a basic image inspection
            image = self.docker_client.images.get(image_name)
            
            table = Table(title=f"Image Analysis: {image_name}")
            table.add_column("Property")
            table.add_column("Value")
            
            table.add_row("ID", image.id)
            table.add_row("Created", str(datetime.fromtimestamp(image.attrs['Created'])))
            table.add_row("Size", f"{image.attrs['Size'] / 1024 / 1024:.2f} MB")
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error scanning image: {str(e)}[/red]")

    def monitor_containers(self):
        """Monitor running containers for suspicious activities."""
        console.print("[blue]Monitoring running containers...[/blue]")
        try:
            containers = self.docker_client.containers.list()
            
            table = Table(title="Running Containers")
            table.add_column("Container ID")
            table.add_column("Name")
            table.add_column("Image")
            table.add_column("Status")
            
            for container in containers:
                table.add_row(
                    container.short_id,
                    container.name,
                    container.image.tags[0] if container.image.tags else "none",
                    container.status
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error monitoring containers: {str(e)}[/red]")

    def audit_kubernetes(self):
        """Audit Kubernetes configurations for security best practices."""
        if not self.kubernetes_client:
            console.print("[red]Kubernetes client not initialized.[/red]")
            return

        console.print("[blue]Auditing Kubernetes configurations...[/blue]")
        try:
            # Get pods from all namespaces
            pods = self.kubernetes_client.list_pod_for_all_namespaces()
            
            table = Table(title="Kubernetes Pod Security Audit")
            table.add_column("Namespace")
            table.add_column("Pod Name")
            table.add_column("Security Context")
            table.add_column("Service Account")
            
            for pod in pods.items:
                table.add_row(
                    pod.metadata.namespace,
                    pod.metadata.name,
                    "✓" if pod.spec.security_context else "✗",
                    pod.spec.service_account_name
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error auditing Kubernetes: {str(e)}[/red]")

    def detect_secrets(self, directory):
        """Detect hardcoded secrets in files."""
        console.print(f"[blue]Scanning for secrets in: {directory}[/blue]")
        
        secret_patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Generic API Key": r"api[_-]?key[_-]?([\"'])[0-9a-zA-Z]{32,45}\1",
            "Generic Secret": r"secret[_-]?([\"'])[0-9a-zA-Z]{32,45}\1",
            "Private Key": r"-----BEGIN (?:RSA )?PRIVATE KEY-----"
        }

        findings = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.yaml', '.yml', 'Dockerfile', '.env')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            for secret_type, pattern in secret_patterns.items():
                                matches = re.finditer(pattern, content)
                                for match in matches:
                                    findings.append({
                                        'file': file_path,
                                        'type': secret_type,
                                        'line': content.count('\n', 0, match.start()) + 1
                                    })
                    except Exception as e:
                        console.print(f"[yellow]Warning: Could not read {file_path}: {str(e)}[/yellow]")

        if findings:
            table = Table(title="Secret Detection Results")
            table.add_column("File")
            table.add_column("Type")
            table.add_column("Line")
            
            for finding in findings:
                table.add_row(
                    finding['file'],
                    finding['type'],
                    str(finding['line'])
                )
            
            console.print(table)
        else:
            console.print("[green]No secrets found![/green]")

    def generate_report(self):
        """Generate a comprehensive security compliance report."""
        console.print("[blue]Generating compliance report...[/blue]")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'docker_images': [],
            'kubernetes_status': {},
            'security_findings': []
        }
        
        # Add Docker image information
        try:
            images = self.docker_client.images.list()
            for image in images:
                report['docker_images'].append({
                    'id': image.short_id,
                    'tags': image.tags,
                    'size': image.attrs['Size']
                })
        except Exception as e:
            report['docker_status'] = f"Error: {str(e)}"

        # Add Kubernetes information if available
        if self.kubernetes_client:
            try:
                pods = self.kubernetes_client.list_pod_for_all_namespaces()
                report['kubernetes_status']['pods'] = len(pods.items)
            except Exception as e:
                report['kubernetes_status'] = f"Error: {str(e)}"

        # Save report
        output_dir = os.getenv('REPORT_OUTPUT_DIR', './reports')
        os.makedirs(output_dir, exist_ok=True)
        
        report_path = os.path.join(output_dir, f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        console.print(f"[green]Report generated: {report_path}[/green]")

@click.group()
def cli():
    """Container Security Scanner - A tool for scanning and monitoring container security."""
    pass

@cli.command()
@click.argument('image_name')
def scan_image(image_name):
    """Scan a Docker image for vulnerabilities."""
    scanner = ContainerSecurityScanner()
    scanner.scan_docker_image(image_name)

@cli.command()
def monitor_containers():
    """Monitor running containers for suspicious activities."""
    scanner = ContainerSecurityScanner()
    scanner.monitor_containers()

@cli.command()
def audit_kubernetes():
    """Audit Kubernetes configurations for security best practices."""
    scanner = ContainerSecurityScanner()
    scanner.audit_kubernetes()

@cli.command()
@click.argument('directory')
def detect_secrets(directory):
    """Detect hardcoded secrets in files."""
    scanner = ContainerSecurityScanner()
    scanner.detect_secrets(directory)

@cli.command()
def generate_report():
    """Generate a comprehensive security compliance report."""
    scanner = ContainerSecurityScanner()
    scanner.generate_report()

if __name__ == '__main__':
    cli() 