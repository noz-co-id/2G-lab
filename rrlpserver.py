#!/usr/bin/env python3

import socket


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 8888))
print("RRLP Server listening on port 8888")

while True:
    data, addr = s.recvfrom(4096)
    print(f"RRLP request from {addr}: {data.hex()}")
    # kirim dummy response
    s.sendto(b"\x01\x02\x03\x04", addr)
