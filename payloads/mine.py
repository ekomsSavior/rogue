#!/usr/bin/env python3
import threading, socket, json, time, os, base64
import hashlib, random

WALLET = "YOUR_MONERO_WALLET_ADDRESS"
POOL = "pool.supportxmr.com"
PORT = 3333
THREADS = 2
THROTTLE = 0.1  # Delay per hash, lower = more aggressive

def get_job(sock):
    while True:
        try:
            data = sock.recv(4096).decode()
            for line in data.strip().split("\n"):
                if "job" in line:
                    return json.loads(line)
        except Exception as e:
            print(f"[!] Error receiving job: {e}")
            time.sleep(5)

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
    try:
        sock.send((json.dumps(sub) + "\n").encode())
    except:
        pass  # Ignore broken pipe or timeout

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

def mine_loop():
    while True:
        try:
            sock = connect_stratum()
            job_data = get_job(sock)
            job = job_data['result']['job']
            blob = job['blob']
            job_id = job['job_id']
            target = int(job['target'], 16)

            print(f"[+] New job received. Starting mining thread.")
            hashes = 0

            while True:
                nonce = format(random.randint(0, 99999999), '08x')
                base = blob[:78] + nonce + blob[86:]
                hash_result = hashlib.sha256(bytes.fromhex(base)).hexdigest()
                hashes += 1

                if int(hash_result, 16) < target:
                    print(f"[✓] Share accepted: {hash_result[:16]}")
                    submit_share(sock, job_id, nonce, hash_result)
                    break  # get new job after submission

                time.sleep(THROTTLE)

        except Exception as e:
            print(f"[!] Miner thread error: {e}")
            time.sleep(10)  # reconnect delay

if __name__ == "__main__":
    print("👑 RogueMiner: Continuous Mining Enabled")
    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=mine_loop)
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] Mining interrupted by user.")
