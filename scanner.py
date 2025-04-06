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
        """Scan a Docker image for vulnerabilities."""
        try:
            console.print(f"[bold blue]Scanning Docker image:[/bold blue] {image_name}")
            
            # Pull the image if it doesn't exist locally
            try:
                self.docker_client.images.pull(image_name)
            except Exception as e:
                console.print(f"[red]Error pulling image:[/red] {e}")
                return
            
            # Get image details
            image = self.docker_client.images.get(image_name)
            
            # Create a table for image information
            table = Table(title=f"Security Scan Results for {image_name}")
            table.add_column("Category", style="cyan")
            table.add_column("Details", style="green")
            
            # Add basic image information
            table.add_row("Image ID", image.id)
            table.add_row("Created", image.attrs['Created'])
            table.add_row("Size", f"{image.attrs['Size'] / 1024 / 1024:.2f} MB")
            
            # Check for exposed ports
            exposed_ports = image.attrs['Config'].get('ExposedPorts', {})
            table.add_row("Exposed Ports", ", ".join(exposed_ports.keys()) if exposed_ports else "None")
            
            # Check for environment variables
            env_vars = image.attrs['Config'].get('Env', [])
            table.add_row("Environment Variables", "\n".join(env_vars) if env_vars else "None")
            
            # Check for running as root
            user = image.attrs['Config'].get('User', '')
            table.add_row("Running as User", user if user else "root (security risk)")
            
            # Display the results
            console.print(table)
            
            # Save scan results
            results = {
                "timestamp": datetime.now().isoformat(),
                "image_name": image_name,
                "image_id": image.id,
                "vulnerabilities": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "security_issues": []
            }
            
            # Check for common security issues
            if not user:
                results["security_issues"].append({
                    "severity": "high",
                    "description": "Container running as root",
                    "recommendation": "Use a non-root user in the Dockerfile"
                })
            
            if exposed_ports:
                results["security_issues"].append({
                    "severity": "medium",
                    "description": f"Exposed ports: {', '.join(exposed_ports.keys())}",
                    "recommendation": "Review if all exposed ports are necessary"
                })
            
            # Save results to file
            os.makedirs("reports", exist_ok=True)
            report_file = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=4)
            
            console.print(f"\n[green]Scan report saved to:[/green] {report_file}")
            
        except Exception as e:
            console.print(f"[red]Error scanning image:[/red] {str(e)}")

    def monitor_containers(self):
        """Monitor running containers for security issues."""
        try:
            containers = self.docker_client.containers.list()
            
            if not containers:
                console.print("[yellow]No running containers found.[/yellow]")
                return
            
            table = Table(title="Container Security Monitor")
            table.add_column("Container ID", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Image", style="blue")
            table.add_column("Status", style="yellow")
            table.add_column("Security Issues", style="red")
            
            for container in containers:
                security_issues = []
                
                # Check if running as root
                if not container.attrs['Config'].get('User'):
                    security_issues.append("Running as root")
                
                # Check exposed ports
                ports = container.attrs['NetworkSettings']['Ports']
                if ports:
                    security_issues.append(f"Exposed ports: {', '.join(str(p) for p in ports)}")
                
                # Check mount points
                mounts = container.attrs['Mounts']
                if any(m['Type'] == 'bind' for m in mounts):
                    security_issues.append("Has bind mounts")
                
                table.add_row(
                    container.short_id,
                    container.name,
                    container.image.tags[0] if container.image.tags else "none",
                    container.status,
                    "\n".join(security_issues) if security_issues else "None"
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error monitoring containers:[/red] {str(e)}")

    def audit_kubernetes(self):
        """Audit Kubernetes configurations for security best practices."""
        if not self.kubernetes_client:
            console.print("[red]Kubernetes client not initialized.[/red]")
            return
        
        try:
            # Get pods from all namespaces
            pods = self.kubernetes_client.list_pod_for_all_namespaces()
            
            table = Table(title="Kubernetes Pod Security Audit")
            table.add_column("Namespace", style="cyan")
            table.add_column("Pod Name", style="green")
            table.add_column("Security Issues", style="red")
            
            for pod in pods.items:
                security_issues = []
                
                # Check for privileged containers
                for container in pod.spec.containers:
                    if container.security_context and container.security_context.privileged:
                        security_issues.append(f"Container {container.name} is privileged")
                
                # Check for host path volumes
                if pod.spec.volumes:
                    for volume in pod.spec.volumes:
                        if hasattr(volume, 'host_path') and volume.host_path:
                            security_issues.append(f"Uses host path volume: {volume.host_path.path}")
                
                table.add_row(
                    pod.metadata.namespace,
                    pod.metadata.name,
                    "\n".join(security_issues) if security_issues else "None"
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error auditing Kubernetes:[/red] {str(e)}")

    def detect_secrets(self, directory):
        """Scan files for potential hardcoded secrets."""
        try:
            console.print(f"[bold blue]Scanning directory for secrets:[/bold blue] {directory}")
            
            table = Table(title="Secret Detection Results")
            table.add_column("File", style="cyan")
            table.add_column("Line", style="green")
            table.add_column("Secret Type", style="yellow")
            table.add_column("Content", style="red")
            
            patterns = {
                'AWS Key': r'AKIA[0-9A-Z]{16}',
                'Private Key': r'-----BEGIN.*PRIVATE KEY-----',
                'API Key': r'api[_-]?key[_-]?[\w\d]{16,}',
                'Password': r'password[_-]?=[\w\d]{8,}',
                'Token': r'token[_-]?[\w\d]{16,}'
            }
            
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith(('.py', '.yml', '.yaml', '.json', '.env')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                for i, line in enumerate(f, 1):
                                    for secret_type, pattern in patterns.items():
                                        if re.search(pattern, line):
                                            table.add_row(
                                                file_path,
                                                str(i),
                                                secret_type,
                                                line.strip()
                                            )
                        except Exception as e:
                            console.print(f"[yellow]Could not read file {file_path}: {e}[/yellow]")
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error detecting secrets:[/red] {str(e)}")

    def generate_report(self):
        """Generate a comprehensive security report."""
        try:
            report = {
                "timestamp": datetime.now().isoformat(),
                "docker_status": {
                    "images": len(self.docker_client.images.list()),
                    "containers": len(self.docker_client.containers.list()),
                    "security_issues": []
                },
                "kubernetes_status": {
                    "pods": 0,
                    "security_issues": []
                }
            }
            
            # Check Docker security
            for container in self.docker_client.containers.list():
                if not container.attrs['Config'].get('User'):
                    report['docker_status']['security_issues'].append({
                        "container": container.name,
                        "issue": "Running as root"
                    })
            
            # Check Kubernetes security
            if self.kubernetes_client:
                try:
                    pods = self.kubernetes_client.list_pod_for_all_namespaces()
                    report['kubernetes_status']['pods'] = len(pods.items)
                    
                    for pod in pods.items:
                        for container in pod.spec.containers:
                            if container.security_context and container.security_context.privileged:
                                report['kubernetes_status']['security_issues'].append({
                                    "pod": pod.metadata.name,
                                    "namespace": pod.metadata.namespace,
                                    "issue": f"Container {container.name} is privileged"
                                })
                except Exception as e:
                    console.print(f"[yellow]Error checking Kubernetes security: {e}[/yellow]")
            
            # Save report
            os.makedirs("reports", exist_ok=True)
            report_file = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=4)
            
            console.print(f"[green]Security report generated:[/green] {report_file}")
            
            # Display summary
            table = Table(title="Security Report Summary")
            table.add_column("Category", style="cyan")
            table.add_column("Status", style="yellow")
            
            table.add_row(
                "Docker Images",
                str(report['docker_status']['images'])
            )
            table.add_row(
                "Running Containers",
                str(report['docker_status']['containers'])
            )
            table.add_row(
                "Docker Security Issues",
                str(len(report['docker_status']['security_issues']))
            )
            table.add_row(
                "Kubernetes Pods",
                str(report['kubernetes_status']['pods'])
            )
            table.add_row(
                "Kubernetes Security Issues",
                str(len(report['kubernetes_status']['security_issues']))
            )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error generating report:[/red] {str(e)}")

@click.group()
def cli():
    """Container Security Scanner CLI"""
    pass

@cli.command()
@click.argument('image_name')
def scan_image(image_name):
    """Scan a Docker image for vulnerabilities"""
    scanner = ContainerSecurityScanner()
    scanner.scan_docker_image(image_name)

@cli.command()
def monitor_containers():
    """Monitor running containers for security issues"""
    scanner = ContainerSecurityScanner()
    scanner.monitor_containers()

@cli.command()
def audit_kubernetes():
    """Audit Kubernetes configurations"""
    scanner = ContainerSecurityScanner()
    scanner.audit_kubernetes()

@cli.command()
@click.argument('directory', type=click.Path(exists=True))
def detect_secrets(directory):
    """Scan files for potential hardcoded secrets"""
    scanner = ContainerSecurityScanner()
    scanner.detect_secrets(directory)

@cli.command()
def generate_report():
    """Generate a comprehensive security report"""
    scanner = ContainerSecurityScanner()
    scanner.generate_report()

if __name__ == '__main__':
    cli() 