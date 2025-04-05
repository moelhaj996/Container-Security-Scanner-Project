import re
import os
from rich.console import Console
from rich.table import Table
import yaml
import json

console = Console()

class SecretDetector:
    def __init__(self):
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
            'Generic API Key': r'api[_-]?key[_-]?(["\'])[0-9a-zA-Z]{32,45}\1',
            'Generic Secret': r'secret[_-]?(["\'])[0-9a-zA-Z]{32,45}\1',
            'Private Key': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
            'Password Assignment': r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'](?!\s*\$)[^"\']+["\']',
            'Connection String': r'(?i)(?:jdbc|mongodb|postgresql|mysql)://[^<>\s]+',
            'Bearer Token': r'bearer[_-]?(["\'])[0-9a-zA-Z]{32,45}\1',
            'SSH Private Key': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY( BLOCK)?-----',
            'GitHub Token': r'gh[ps]_[0-9a-zA-Z]{36}',
            'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
            'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
            'Stripe API Key': r'(?:r|s)k_live_[0-9a-zA-Z]{24}'
        }

    def scan_file(self, file_path):
        """Scan a single file for secrets."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for secret_type, pattern in self.patterns.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_number = content.count('\n', 0, match.start()) + 1
                        context = self._get_line_context(content, line_number)
                        findings.append({
                            'type': secret_type,
                            'line': line_number,
                            'context': context,
                            'value': match.group()[:20] + '...' if len(match.group()) > 23 else match.group()
                        })
                        
        except Exception as e:
            console.print(f"[yellow]Warning: Could not scan {file_path}: {str(e)}[/yellow]")
            
        return findings

    def _get_line_context(self, content, line_number, context_lines=2):
        """Get the context around a line where a secret was found."""
        lines = content.splitlines()
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        context = []
        for i in range(start, end):
            prefix = '> ' if i == line_number - 1 else '  '
            context.append(f"{prefix}{i + 1}: {lines[i]}")
            
        return '\n'.join(context)

    def scan_directory(self, directory_path, file_patterns=None):
        """Scan a directory for secrets."""
        if file_patterns is None:
            file_patterns = ['.yaml', '.yml', '.json', '.env', '.config', '.xml', 
                           '.properties', '.ini', '.conf', '.sh', '.bash', '.py',
                           'Dockerfile', 'docker-compose.yml']
        
        findings = []
        
        console.print(f"[blue]Scanning directory for secrets: {directory_path}[/blue]")
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                if any(file.endswith(pattern) or file == pattern for pattern in file_patterns):
                    file_path = os.path.join(root, file)
                    file_findings = self.scan_file(file_path)
                    if file_findings:
                        findings.extend([{**f, 'file': file_path} for f in file_findings])

        self._display_findings(findings)
        return findings

    def _display_findings(self, findings):
        """Display the findings in a formatted table."""
        if not findings:
            console.print("[green]No secrets found![/green]")
            return

        # Summary table
        summary_table = Table(title="Secret Detection Summary")
        summary_table.add_column("Secret Type")
        summary_table.add_column("Count")
        
        type_counts = {}
        for finding in findings:
            type_counts[finding['type']] = type_counts.get(finding['type'], 0) + 1
            
        for secret_type, count in type_counts.items():
            summary_table.add_row(secret_type, str(count))
            
        console.print(summary_table)
        
        # Detailed findings table
        detail_table = Table(title="Detailed Findings")
        detail_table.add_column("File")
        detail_table.add_column("Type")
        detail_table.add_column("Line")
        detail_table.add_column("Context")
        
        for finding in findings:
            detail_table.add_row(
                finding['file'],
                finding['type'],
                str(finding['line']),
                finding['context']
            )
            
        console.print(detail_table)

    def scan_kubernetes_secrets(self, manifest_path):
        """Scan Kubernetes manifests for potentially exposed secrets."""
        try:
            with open(manifest_path, 'r') as f:
                if manifest_path.endswith('.json'):
                    manifests = [json.load(f)]
                else:
                    manifests = list(yaml.safe_load_all(f))
                    
            findings = []
            
            for manifest in manifests:
                if not isinstance(manifest, dict):
                    continue
                    
                kind = manifest.get('kind', '').lower()
                
                if kind == 'secret':
                    name = manifest.get('metadata', {}).get('name', 'unnamed')
                    namespace = manifest.get('metadata', {}).get('namespace', 'default')
                    
                    # Check if data is base64 encoded
                    data = manifest.get('data', {})
                    stringData = manifest.get('stringData', {})
                    
                    if stringData:
                        findings.append({
                            'type': 'Unencoded Secret',
                            'name': name,
                            'namespace': namespace,
                            'issue': 'Secret uses stringData (unencoded) field'
                        })
                        
                    for key in data.keys():
                        if key.lower() in ['token', 'password', 'secret', 'key']:
                            findings.append({
                                'type': 'Sensitive Key Name',
                                'name': name,
                                'namespace': namespace,
                                'key': key
                            })
                            
            self._display_kubernetes_findings(findings)
            return findings
            
        except Exception as e:
            console.print(f"[red]Error scanning Kubernetes manifest: {str(e)}[/red]")
            return []

    def _display_kubernetes_findings(self, findings):
        """Display Kubernetes-specific findings."""
        if not findings:
            console.print("[green]No issues found in Kubernetes manifests![/green]")
            return

        table = Table(title="Kubernetes Secrets Analysis")
        table.add_column("Type")
        table.add_column("Name")
        table.add_column("Namespace")
        table.add_column("Issue")
        
        for finding in findings:
            table.add_row(
                finding['type'],
                finding['name'],
                finding['namespace'],
                finding.get('issue', finding.get('key', 'N/A'))
            )
            
        console.print(table)

    def generate_report(self, findings, output_file):
        """Generate a detailed report of findings."""
        report = {
            'summary': {
                'total_findings': len(findings),
                'findings_by_type': {}
            },
            'detailed_findings': findings
        }
        
        # Generate summary statistics
        for finding in findings:
            secret_type = finding['type']
            report['summary']['findings_by_type'][secret_type] = \
                report['summary']['findings_by_type'].get(secret_type, 0) + 1
        
        # Write report to file
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        console.print(f"[green]Report generated: {output_file}[/green]") 