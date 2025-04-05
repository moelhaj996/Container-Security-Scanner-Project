import docker
import psutil
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live
from datetime import datetime
import json
import os

console = Console()

class ContainerMonitor:
    def __init__(self):
        self.docker_client = docker.from_client()
        self.suspicious_patterns = {
            'processes': ['nc', 'ncat', 'nmap', 'wget', 'curl', 'chmod', 'chown', 'sudo'],
            'ports': [22, 23, 3389],  # SSH, Telnet, RDP
            'mounts': ['/etc/shadow', '/etc/passwd', '/etc/ssh']
        }
        self.alerts = []

    def monitor_containers(self, interval=5):
        """Monitor running containers for suspicious activities."""
        try:
            with Live(self._generate_table(), refresh_per_second=1) as live:
                while True:
                    containers = self.docker_client.containers.list()
                    for container in containers:
                        self._check_container(container)
                    
                    live.update(self._generate_table())
                    time.sleep(interval)
                    
        except KeyboardInterrupt:
            console.print("[yellow]Monitoring stopped by user[/yellow]")
            self._save_alerts()

    def _check_container(self, container):
        """Check a single container for suspicious activities."""
        try:
            # Get container stats
            stats = container.stats(stream=False)
            
            # Check for suspicious processes
            try:
                processes = container.top()['Processes']
                for proc in processes:
                    if any(suspicious in proc[-1].lower() for suspicious in self.suspicious_patterns['processes']):
                        self._add_alert(container.name, 'Suspicious Process', f"Process found: {proc[-1]}")
            except Exception as e:
                console.print(f"[yellow]Warning: Could not check processes for {container.name}: {str(e)}[/yellow]")

            # Check exposed ports
            ports = container.ports
            for port in ports:
                port_number = int(port.split('/')[0])
                if port_number in self.suspicious_patterns['ports']:
                    self._add_alert(container.name, 'Suspicious Port', f"Port exposed: {port_number}")

            # Check mounts
            mounts = container.attrs['Mounts']
            for mount in mounts:
                if mount['Type'] == 'bind' and any(path in mount['Source'] for path in self.suspicious_patterns['mounts']):
                    self._add_alert(container.name, 'Suspicious Mount', f"Sensitive path mounted: {mount['Source']}")

            # Check resource usage
            cpu_percent = stats['cpu_stats']['cpu_usage']['total_usage']
            memory_percent = (stats['memory_stats']['usage'] / stats['memory_stats']['limit']) * 100
            
            if cpu_percent > 90:
                self._add_alert(container.name, 'High CPU Usage', f"CPU Usage: {cpu_percent:.2f}%")
            if memory_percent > 90:
                self._add_alert(container.name, 'High Memory Usage', f"Memory Usage: {memory_percent:.2f}%")

            # Check network usage spikes
            if 'networks' in stats:
                for interface, net_stats in stats['networks'].items():
                    rx_bytes = net_stats['rx_bytes']
                    tx_bytes = net_stats['tx_bytes']
                    
                    # Alert on high network usage (example threshold: 100MB/s)
                    if rx_bytes > 100_000_000 or tx_bytes > 100_000_000:
                        self._add_alert(container.name, 'High Network Usage',
                                      f"Network usage spike detected on {interface}")

        except Exception as e:
            console.print(f"[red]Error monitoring container {container.name}: {str(e)}[/red]")

    def _add_alert(self, container_name, alert_type, message):
        """Add a new alert to the alerts list."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'container': container_name,
            'type': alert_type,
            'message': message
        }
        self.alerts.append(alert)

    def _generate_table(self):
        """Generate a table of current container status and alerts."""
        table = Table(title="Container Security Monitor")
        table.add_column("Container")
        table.add_column("Status")
        table.add_column("CPU %")
        table.add_column("Memory %")
        table.add_column("Network I/O")
        table.add_column("Recent Alerts")
        
        try:
            containers = self.docker_client.containers.list()
            for container in containers:
                stats = container.stats(stream=False)
                
                # Calculate metrics
                cpu_percent = stats['cpu_stats']['cpu_usage']['total_usage']
                memory_percent = (stats['memory_stats']['usage'] / stats['memory_stats']['limit']) * 100
                
                # Get network I/O
                net_io = "N/A"
                if 'networks' in stats:
                    rx_bytes = sum(net['rx_bytes'] for net in stats['networks'].values())
                    tx_bytes = sum(net['tx_bytes'] for net in stats['networks'].values())
                    net_io = f"↓{self._format_bytes(rx_bytes)}/s ↑{self._format_bytes(tx_bytes)}/s"
                
                # Get recent alerts
                recent_alerts = [
                    alert for alert in self.alerts
                    if alert['container'] == container.name
                    and (datetime.now() - datetime.fromisoformat(alert['timestamp'])).seconds < 300
                ]
                
                alert_text = "\n".join(f"{alert['type']}: {alert['message']}" 
                                     for alert in recent_alerts[-3:])  # Show last 3 alerts
                
                status_color = 'green' if not recent_alerts else 'red'
                
                table.add_row(
                    container.name,
                    f"[{status_color}]{container.status}[/{status_color}]",
                    f"{cpu_percent:.1f}%",
                    f"{memory_percent:.1f}%",
                    net_io,
                    alert_text or "No recent alerts"
                )
                
        except Exception as e:
            console.print(f"[red]Error generating monitoring table: {str(e)}[/red]")
            
        return table

    def _format_bytes(self, bytes):
        """Format bytes into human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.1f}{unit}"
            bytes /= 1024
        return f"{bytes:.1f}TB"

    def _save_alerts(self):
        """Save alerts to a JSON file."""
        if not self.alerts:
            return
            
        output_dir = 'reports'
        os.makedirs(output_dir, exist_ok=True)
        
        filename = os.path.join(output_dir, 
                              f"container_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        with open(filename, 'w') as f:
            json.dump({
                'alerts': self.alerts,
                'summary': {
                    'total_alerts': len(self.alerts),
                    'alerts_by_type': self._summarize_alerts()
                }
            }, f, indent=2)
            
        console.print(f"[green]Alerts saved to: {filename}[/green]")

    def _summarize_alerts(self):
        """Summarize alerts by type."""
        summary = {}
        for alert in self.alerts:
            alert_type = alert['type']
            if alert_type not in summary:
                summary[alert_type] = 0
            summary[alert_type] += 1
        return summary

    def check_container_security(self, container_name):
        """Perform a detailed security check on a specific container."""
        try:
            container = self.docker_client.containers.get(container_name)
            
            table = Table(title=f"Security Check: {container_name}")
            table.add_column("Check")
            table.add_column("Status")
            table.add_column("Details")
            
            # Check privileged mode
            privileged = container.attrs['HostConfig']['Privileged']
            table.add_row(
                "Privileged Mode",
                "[red]FAIL[/red]" if privileged else "[green]PASS[/green]",
                "Container runs in privileged mode" if privileged else "Container is not privileged"
            )
            
            # Check root user
            try:
                user_info = container.exec_run('id', user='root')
                runs_as_root = user_info.exit_code == 0
                table.add_row(
                    "Root User",
                    "[red]FAIL[/red]" if runs_as_root else "[green]PASS[/green]",
                    "Container runs as root" if runs_as_root else "Container runs as non-root user"
                )
            except:
                table.add_row("Root User", "[yellow]UNKNOWN[/yellow]", "Could not determine user context")
            
            # Check sensitive mounts
            mounts = container.attrs['Mounts']
            sensitive_mounts = [
                mount for mount in mounts
                if mount['Type'] == 'bind' and any(path in mount['Source'] 
                                                 for path in self.suspicious_patterns['mounts'])
            ]
            table.add_row(
                "Sensitive Mounts",
                "[red]FAIL[/red]" if sensitive_mounts else "[green]PASS[/green]",
                "\n".join(mount['Source'] for mount in sensitive_mounts) or "No sensitive mounts found"
            )
            
            # Check network mode
            network_mode = container.attrs['HostConfig']['NetworkMode']
            table.add_row(
                "Network Mode",
                "[red]FAIL[/red]" if network_mode == 'host' else "[green]PASS[/green]",
                f"Network mode: {network_mode}"
            )
            
            # Check capabilities
            caps = container.attrs['HostConfig']['CapAdd'] or []
            table.add_row(
                "Added Capabilities",
                "[red]FAIL[/red]" if caps else "[green]PASS[/green]",
                "\n".join(caps) or "No additional capabilities"
            )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error checking container security: {str(e)}[/red]") 