# mine.py
import hashlib, time

print("[*] Starting dummy crypto miner...")
while True:
    text = str(time.time()).encode()
    hashlib.sha256(text).hexdigest()
