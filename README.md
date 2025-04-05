# Container Security Scanner

A comprehensive security scanning tool for containerized environments that helps identify vulnerabilities, misconfigurations, and security risks in Docker containers and Kubernetes deployments.

## Features

- 🔍 Docker Image Vulnerability Scanning
- 🚦 Container Runtime Monitoring
- ⚙️ Kubernetes Configuration Auditing
- 🔐 Secrets Detection
- 📊 Compliance Reporting

## Prerequisites

- Python 3.8+
- Docker
- Kubernetes cluster (for K8s-related features)
- Trivy (for container scanning)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/container-security-scanner.git
cd container-security-scanner
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan a Docker image
python scanner.py scan-image <image-name>

# Monitor running containers
python scanner.py monitor-containers

# Audit Kubernetes configurations
python scanner.py audit-kubernetes

# Check for hardcoded secrets
python scanner.py detect-secrets <directory>

# Generate compliance report
python scanner.py generate-report
```

## Configuration

Create a `.env` file in the project root with the following variables:
```
KUBERNETES_CONTEXT=your-context
REPORT_OUTPUT_DIR=./reports
LOG_LEVEL=INFO
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 