#!/usr/bin/env python3
import threading, socket, json, time, os, base64
import hashlib, random

WALLET = "YOUR_MONERO_WALLET_ADDRESS"
POOL = "pool.supportxmr.com"
PORT = 3333
THREADS = 2
THROTTLE = 0.1  # Delay per hash, lower = more aggressive
DURATION = 120  # seconds

def get_job(sock):
    while True:
        data = sock.recv(4096).decode()
        for line in data.split("\n"):
            if "job" in line:
                return json.loads(line)

def submit_share(sock, job_id, nonce, result):
    sub = {
        "id": "0",
        "method": "submit",
        "params": {
            "id": "worker",
            "job_id": job_id,
            "nonce": nonce,
            "result": result
        }
    }
    sock.send((json.dumps(sub) + "\n").encode())

def connect_stratum():
    s = socket.socket()
    s.connect((POOL, PORT))
    login = {
        "id": "0",
        "method": "login",
        "params": {
            "login": WALLET,
            "pass": "x",
            "agent": "RogueMiner/1.0"
        }
    }
    s.send((json.dumps(login) + "\n").encode())
    return s

def mine(job_data, duration):
    blob = job_data['result']['job']['blob']
    job_id = job_data['result']['job']['job_id']
    target = int(job_data['result']['job']['target'], 16)

    start = time.time()
    hashes = 0

    while time.time() - start < duration:
        nonce = format(random.randint(0, 99999999), '08x')
        base = blob[:78] + nonce + blob[86:]
        hash_result = hashlib.sha256(bytes.fromhex(base)).hexdigest()
        hashes += 1

        if int(hash_result, 16) < target:
            print(f"[+] Found share: {hash_result[:16]}")
            submit_share(sock, job_id, nonce, hash_result)

        time.sleep(THROTTLE)

    print(f"[+] Thread complete – {hashes} hashes attempted.")

if __name__ == "__main__":
    print("👑 Rogue Miner – Connecting to pool...")
    sock = connect_stratum()
    job = get_job(sock)

    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=mine, args=(job, DURATION))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[*] Mining session complete.")
