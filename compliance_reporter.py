import json
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
import docker
from kubernetes import client, config
import yaml

console = Console()

class ComplianceReporter:
    def __init__(self):
        self.docker_client = docker.from_client()
        try:
            config.load_kube_config()
            self.k8s_client = client.CoreV1Api()
            self.rbac_client = client.RbacAuthorizationV1Api()
        except Exception as e:
            console.print("[yellow]Warning: Kubernetes configuration not found. K8s compliance checks will be limited.[/yellow]")
            self.k8s_client = None
            self.rbac_client = None

    def generate_report(self, output_dir='reports'):
        """Generate a comprehensive compliance report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'docker': self._check_docker_compliance(),
            'kubernetes': self._check_kubernetes_compliance() if self.k8s_client else None,
            'summary': {
                'total_checks': 0,
                'passed': 0,
                'failed': 0,
                'warnings': 0
            }
        }

        # Update summary
        for section in ['docker', 'kubernetes']:
            if report[section]:
                report['summary']['total_checks'] += report[section]['summary']['total_checks']
                report['summary']['passed'] += report[section]['summary']['passed']
                report['summary']['failed'] += report[section]['summary']['failed']
                report['summary']['warnings'] += report[section]['summary']['warnings']

        # Save report
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        self._display_report_summary(report)
        console.print(f"\n[green]Full report saved to: {report_path}[/green]")
        
        return report

    def _check_docker_compliance(self):
        """Check Docker configuration and containers for compliance."""
        results = {
            'containers': [],
            'images': [],
            'daemon_config': {},
            'summary': {
                'total_checks': 0,
                'passed': 0,
                'failed': 0,
                'warnings': 0
            }
        }

        # Check containers
        containers = self.docker_client.containers.list(all=True)
        for container in containers:
            container_check = self._check_container_compliance(container)
            results['containers'].append(container_check)
            
            # Update summary
            results['summary']['total_checks'] += container_check['total_checks']
            results['summary']['passed'] += container_check['passed']
            results['summary']['failed'] += container_check['failed']
            results['summary']['warnings'] += container_check['warnings']

        # Check images
        images = self.docker_client.images.list()
        for image in images:
            image_check = self._check_image_compliance(image)
            results['images'].append(image_check)
            
            # Update summary
            results['summary']['total_checks'] += image_check['total_checks']
            results['summary']['passed'] += image_check['passed']
            results['summary']['failed'] += image_check['failed']
            results['summary']['warnings'] += image_check['warnings']

        # Check Docker daemon configuration
        daemon_check = self._check_daemon_compliance()
        results['daemon_config'] = daemon_check
        results['summary']['total_checks'] += daemon_check['total_checks']
        results['summary']['passed'] += daemon_check['passed']
        results['summary']['failed'] += daemon_check['failed']
        results['summary']['warnings'] += daemon_check['warnings']

        return results

    def _check_container_compliance(self, container):
        """Check a single container for compliance with security best practices."""
        results = {
            'container_id': container.short_id,
            'name': container.name,
            'checks': [],
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }

        # Get container details
        config = container.attrs['Config']
        host_config = container.attrs['HostConfig']

        # Check privileged mode
        check = {
            'name': 'Privileged Mode',
            'status': 'FAIL' if host_config['Privileged'] else 'PASS',
            'description': 'Container should not run in privileged mode'
        }
        results['checks'].append(check)

        # Check root user
        check = {
            'name': 'Root User',
            'status': 'FAIL' if not config.get('User') else 'PASS',
            'description': 'Container should not run as root'
        }
        results['checks'].append(check)

        # Check sensitive mounts
        sensitive_paths = ['/etc', '/var/run/docker.sock', '/root']
        sensitive_mounts = [
            mount for mount in host_config['Mounts']
            if any(path in mount['Source'] for path in sensitive_paths)
        ]
        check = {
            'name': 'Sensitive Mounts',
            'status': 'FAIL' if sensitive_mounts else 'PASS',
            'description': 'Container should not mount sensitive host paths'
        }
        results['checks'].append(check)

        # Check network mode
        check = {
            'name': 'Network Mode',
            'status': 'FAIL' if host_config['NetworkMode'] == 'host' else 'PASS',
            'description': 'Container should not use host network mode'
        }
        results['checks'].append(check)

        # Update summary
        for check in results['checks']:
            results['total_checks'] += 1
            if check['status'] == 'PASS':
                results['passed'] += 1
            elif check['status'] == 'FAIL':
                results['failed'] += 1
            else:
                results['warnings'] += 1

        return results

    def _check_image_compliance(self, image):
        """Check a single image for compliance with security best practices."""
        results = {
            'image_id': image.short_id,
            'tags': image.tags,
            'checks': [],
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }

        # Check if image is official
        check = {
            'name': 'Official Image',
            'status': 'PASS' if any('library/' in tag for tag in image.tags) else 'WARNING',
            'description': 'Using official Docker Hub images is recommended'
        }
        results['checks'].append(check)

        # Check if image has a specific tag (not 'latest')
        check = {
            'name': 'Specific Tag',
            'status': 'PASS' if not any(':latest' in tag for tag in image.tags) else 'WARNING',
            'description': 'Using specific version tags instead of "latest" is recommended'
        }
        results['checks'].append(check)

        # Update summary
        for check in results['checks']:
            results['total_checks'] += 1
            if check['status'] == 'PASS':
                results['passed'] += 1
            elif check['status'] == 'FAIL':
                results['failed'] += 1
            else:
                results['warnings'] += 1

        return results

    def _check_daemon_compliance(self):
        """Check Docker daemon configuration for compliance."""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }

        try:
            info = self.docker_client.info()
            
            # Check if live restore is enabled
            check = {
                'name': 'Live Restore',
                'status': 'PASS' if info.get('LiveRestoreEnabled') else 'WARNING',
                'description': 'Live restore capability should be enabled'
            }
            results['checks'].append(check)

            # Check if debug mode is disabled
            check = {
                'name': 'Debug Mode',
                'status': 'PASS' if not info.get('Debug') else 'FAIL',
                'description': 'Debug mode should be disabled in production'
            }
            results['checks'].append(check)

            # Check if user namespace remapping is enabled
            check = {
                'name': 'User Namespace Remapping',
                'status': 'PASS' if info.get('UsersRemapped') else 'WARNING',
                'description': 'User namespace remapping should be enabled'
            }
            results['checks'].append(check)

        except Exception as e:
            console.print(f"[yellow]Warning: Could not check Docker daemon configuration: {str(e)}[/yellow]")

        # Update summary
        for check in results['checks']:
            results['total_checks'] += 1
            if check['status'] == 'PASS':
                results['passed'] += 1
            elif check['status'] == 'FAIL':
                results['failed'] += 1
            else:
                results['warnings'] += 1

        return results

    def _check_kubernetes_compliance(self):
        """Check Kubernetes cluster for compliance with security best practices."""
        if not self.k8s_client:
            return None

        results = {
            'pods': [],
            'rbac': [],
            'network_policies': [],
            'summary': {
                'total_checks': 0,
                'passed': 0,
                'failed': 0,
                'warnings': 0
            }
        }

        # Check pods
        try:
            pods = self.k8s_client.list_pod_for_all_namespaces()
            for pod in pods.items:
                pod_check = self._check_pod_compliance(pod)
                results['pods'].append(pod_check)
                
                # Update summary
                results['summary']['total_checks'] += pod_check['total_checks']
                results['summary']['passed'] += pod_check['passed']
                results['summary']['failed'] += pod_check['failed']
                results['summary']['warnings'] += pod_check['warnings']
        except Exception as e:
            console.print(f"[yellow]Warning: Could not check pod compliance: {str(e)}[/yellow]")

        # Check RBAC
        try:
            rbac_check = self._check_rbac_compliance()
            results['rbac'] = rbac_check
            results['summary']['total_checks'] += rbac_check['total_checks']
            results['summary']['passed'] += rbac_check['passed']
            results['summary']['failed'] += rbac_check['failed']
            results['summary']['warnings'] += rbac_check['warnings']
        except Exception as e:
            console.print(f"[yellow]Warning: Could not check RBAC compliance: {str(e)}[/yellow]")

        return results

    def _check_pod_compliance(self, pod):
        """Check a single pod for compliance with security best practices."""
        results = {
            'name': pod.metadata.name,
            'namespace': pod.metadata.namespace,
            'checks': [],
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }

        # Check security context
        if not pod.spec.security_context:
            check = {
                'name': 'Security Context',
                'status': 'FAIL',
                'description': 'Pod should have a security context defined'
            }
        else:
            check = {
                'name': 'Security Context',
                'status': 'PASS',
                'description': 'Pod has security context defined'
            }
        results['checks'].append(check)

        # Check container security contexts
        for container in pod.spec.containers:
            if not container.security_context:
                check = {
                    'name': f'Container Security Context ({container.name})',
                    'status': 'FAIL',
                    'description': 'Container should have a security context defined'
                }
                results['checks'].append(check)
            else:
                sc = container.security_context
                if sc.privileged:
                    check = {
                        'name': f'Container Privileged Mode ({container.name})',
                        'status': 'FAIL',
                        'description': 'Container should not run in privileged mode'
                    }
                    results['checks'].append(check)

        # Check service account
        if not pod.spec.service_account_name or pod.spec.service_account_name == 'default':
            check = {
                'name': 'Service Account',
                'status': 'WARNING',
                'description': 'Pod should use a dedicated service account'
            }
            results['checks'].append(check)

        # Update summary
        for check in results['checks']:
            results['total_checks'] += 1
            if check['status'] == 'PASS':
                results['passed'] += 1
            elif check['status'] == 'FAIL':
                results['failed'] += 1
            else:
                results['warnings'] += 1

        return results

    def _check_rbac_compliance(self):
        """Check RBAC configuration for compliance."""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }

        try:
            # Check cluster roles
            cluster_roles = self.rbac_client.list_cluster_role()
            for role in cluster_roles.items:
                if any('*' in rule.verbs or '*' in rule.resources for rule in role.rules):
                    check = {
                        'name': f'Cluster Role Wildcards ({role.metadata.name})',
                        'status': 'FAIL',
                        'description': 'Cluster roles should not use wildcard permissions'
                    }
                    results['checks'].append(check)

            # Check role bindings
            role_bindings = self.rbac_client.list_role_binding_for_all_namespaces()
            for binding in role_bindings.items:
                if binding.subjects and any(subject.kind == 'ServiceAccount' and 
                                          subject.name == 'default' for subject in binding.subjects):
                    check = {
                        'name': f'Default ServiceAccount Binding ({binding.metadata.name})',
                        'status': 'WARNING',
                        'description': 'Default service account should not have role bindings'
                    }
                    results['checks'].append(check)

        except Exception as e:
            console.print(f"[yellow]Warning: Could not complete RBAC compliance check: {str(e)}[/yellow]")

        # Update summary
        for check in results['checks']:
            results['total_checks'] += 1
            if check['status'] == 'PASS':
                results['passed'] += 1
            elif check['status'] == 'FAIL':
                results['failed'] += 1
            else:
                results['warnings'] += 1

        return results

    def _display_report_summary(self, report):
        """Display a summary of the compliance report."""
        table = Table(title="Compliance Report Summary")
        table.add_column("Category")
        table.add_column("Total Checks")
        table.add_column("Passed")
        table.add_column("Failed")
        table.add_column("Warnings")
        table.add_column("Compliance Score")

        # Add Docker summary if available
        if report['docker']:
            docker_summary = report['docker']['summary']
            total = docker_summary['total_checks']
            if total > 0:
                score = (docker_summary['passed'] / total) * 100
                table.add_row(
                    "Docker",
                    str(total),
                    str(docker_summary['passed']),
                    str(docker_summary['failed']),
                    str(docker_summary['warnings']),
                    f"{score:.1f}%"
                )

        # Add Kubernetes summary if available
        if report['kubernetes']:
            k8s_summary = report['kubernetes']['summary']
            total = k8s_summary['total_checks']
            if total > 0:
                score = (k8s_summary['passed'] / total) * 100
                table.add_row(
                    "Kubernetes",
                    str(total),
                    str(k8s_summary['passed']),
                    str(k8s_summary['failed']),
                    str(k8s_summary['warnings']),
                    f"{score:.1f}%"
                )

        # Add overall summary
        total = report['summary']['total_checks']
        if total > 0:
            score = (report['summary']['passed'] / total) * 100
            table.add_row(
                "Overall",
                str(total),
                str(report['summary']['passed']),
                str(report['summary']['failed']),
                str(report['summary']['warnings']),
                f"{score:.1f}%"
            )

        console.print(table) 