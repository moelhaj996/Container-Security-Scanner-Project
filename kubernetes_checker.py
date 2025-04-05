from kubernetes import client, config
from rich.console import Console
from rich.table import Table

console = Console()

class KubernetesSecurityChecker:
    def __init__(self):
        try:
            config.load_kube_config()
            self.core_v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
        except Exception as e:
            console.print(f"[red]Error initializing Kubernetes client: {str(e)}[/red]")
            raise

    def check_pod_security_context(self, pod):
        """Check if a pod has proper security context settings."""
        issues = []
        
        # Check pod-level security context
        if not pod.spec.security_context:
            issues.append("No pod-level security context defined")
        else:
            sc = pod.spec.security_context
            if not sc.run_as_non_root:
                issues.append("Pod allows running as root")
            if not sc.run_as_user:
                issues.append("No explicit runAsUser set")

        # Check container-level security contexts
        for container in pod.spec.containers:
            if not container.security_context:
                issues.append(f"Container {container.name} has no security context")
            else:
                c_sc = container.security_context
                if c_sc.privileged:
                    issues.append(f"Container {container.name} runs in privileged mode")
                if not c_sc.read_only_root_filesystem:
                    issues.append(f"Container {container.name} has writable root filesystem")

        return issues

    def check_rbac_permissions(self):
        """Audit RBAC permissions for potential security issues."""
        try:
            roles = self.rbac_v1.list_role_for_all_namespaces()
            cluster_roles = self.rbac_v1.list_cluster_role()
            
            table = Table(title="RBAC Security Audit")
            table.add_column("Type")
            table.add_column("Name")
            table.add_column("Namespace")
            table.add_column("Permissions")
            table.add_column("Risk Level")
            
            # Check roles
            for role in roles.items:
                for rule in role.rules:
                    risk_level = self._assess_permission_risk(rule)
                    if risk_level in ["HIGH", "MEDIUM"]:
                        table.add_row(
                            "Role",
                            role.metadata.name,
                            role.metadata.namespace,
                            ", ".join(rule.verbs) + " on " + ", ".join(rule.resources),
                            risk_level
                        )

            # Check cluster roles
            for role in cluster_roles.items:
                for rule in role.rules:
                    risk_level = self._assess_permission_risk(rule)
                    if risk_level in ["HIGH", "MEDIUM"]:
                        table.add_row(
                            "ClusterRole",
                            role.metadata.name,
                            "cluster-wide",
                            ", ".join(rule.verbs) + " on " + ", ".join(rule.resources),
                            risk_level
                        )

            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error checking RBAC permissions: {str(e)}[/red]")

    def _assess_permission_risk(self, rule):
        """Assess the risk level of RBAC permissions."""
        high_risk_resources = ["secrets", "pods/exec", "pods/attach"]
        high_risk_verbs = ["create", "delete", "update", "patch"]
        
        if "*" in rule.resources or "*" in rule.verbs:
            return "HIGH"
            
        if any(res in rule.resources for res in high_risk_resources):
            if any(verb in rule.verbs for verb in high_risk_verbs):
                return "HIGH"
            return "MEDIUM"
            
        if any(verb in rule.verbs for verb in high_risk_verbs):
            return "MEDIUM"
            
        return "LOW"

    def check_network_policies(self):
        """Check for missing or overly permissive network policies."""
        try:
            networking_v1 = client.NetworkingV1Api()
            namespaces = self.core_v1.list_namespace()
            network_policies = networking_v1.list_network_policy_for_all_namespaces()
            
            table = Table(title="Network Policy Audit")
            table.add_column("Namespace")
            table.add_column("Status")
            table.add_column("Issues")
            
            namespace_policies = {}
            for policy in network_policies.items:
                ns = policy.metadata.namespace
                if ns not in namespace_policies:
                    namespace_policies[ns] = []
                namespace_policies[ns].append(policy)
            
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                if ns_name not in namespace_policies:
                    table.add_row(
                        ns_name,
                        "❌",
                        "No network policies defined"
                    )
                else:
                    policies = namespace_policies[ns_name]
                    issues = []
                    
                    for policy in policies:
                        if self._is_overly_permissive(policy):
                            issues.append(f"Overly permissive policy: {policy.metadata.name}")
                    
                    table.add_row(
                        ns_name,
                        "✓" if not issues else "⚠️",
                        "\n".join(issues) if issues else "No issues found"
                    )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error checking network policies: {str(e)}[/red]")

    def _is_overly_permissive(self, policy):
        """Check if a network policy is too permissive."""
        for ingress in policy.spec.ingress:
            if not ingress.from_:
                return True
        for egress in policy.spec.egress:
            if not egress.to:
                return True
        return False

    def check_secrets_usage(self):
        """Audit how secrets are used in the cluster."""
        try:
            secrets = self.core_v1.list_secret_for_all_namespaces()
            pods = self.core_v1.list_pod_for_all_namespaces()
            
            table = Table(title="Secrets Usage Audit")
            table.add_column("Namespace")
            table.add_column("Pod")
            table.add_column("Secret Name")
            table.add_column("Mount Type")
            table.add_column("Risk Level")
            
            for pod in pods.items:
                # Check volume mounts
                if pod.spec.volumes:
                    for volume in pod.spec.volumes:
                        if volume.secret:
                            table.add_row(
                                pod.metadata.namespace,
                                pod.metadata.name,
                                volume.secret.secret_name,
                                "Volume",
                                "LOW"
                            )
                
                # Check environment variables
                for container in pod.spec.containers:
                    if container.env:
                        for env in container.env:
                            if env.value_from and env.value_from.secret_key_ref:
                                table.add_row(
                                    pod.metadata.namespace,
                                    pod.metadata.name,
                                    env.value_from.secret_key_ref.name,
                                    "Environment",
                                    "MEDIUM"
                                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error checking secrets usage: {str(e)}[/red]")

    def run_all_checks(self):
        """Run all Kubernetes security checks."""
        console.print("[blue]Running comprehensive Kubernetes security audit...[/blue]")
        
        # Check RBAC permissions
        console.print("\n[yellow]Checking RBAC permissions...[/yellow]")
        self.check_rbac_permissions()
        
        # Check network policies
        console.print("\n[yellow]Checking network policies...[/yellow]")
        self.check_network_policies()
        
        # Check secrets usage
        console.print("\n[yellow]Checking secrets usage...[/yellow]")
        self.check_secrets_usage()
        
        # Check pod security contexts
        console.print("\n[yellow]Checking pod security contexts...[/yellow]")
        pods = self.core_v1.list_pod_for_all_namespaces()
        
        table = Table(title="Pod Security Context Audit")
        table.add_column("Namespace")
        table.add_column("Pod")
        table.add_column("Issues")
        
        for pod in pods.items:
            issues = self.check_pod_security_context(pod)
            if issues:
                table.add_row(
                    pod.metadata.namespace,
                    pod.metadata.name,
                    "\n".join(issues)
                )
        
        console.print(table) 