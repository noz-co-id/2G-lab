import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 4729

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"[RRLP Sniffer] Listening on {UDP_IP}:{UDP_PORT}")

def parse_gsmtap(packet):
    if len(packet) < 12:
        return None
    # Versi header minimal
    version = packet[0]
    sub_type = packet[3]
    # payload = sisa packet setelah header
    payload = packet[12:]
    return version, sub_type, payload

def decode_rrlp(payload):
    if len(payload) == 0:
        return
    # RRLP biasanya ASN.1
    if payload[0] == 0x0a:  # tag awal RRLP
        print("🛰️ RRLP message detected!")
        print(f"Raw data: {payload.hex()}")

while True:
    data, addr = sock.recvfrom(2048)
    parsed = parse_gsmtap(data)
    if not parsed:
        continue
    version, sub_type, payload = parsed
    # subtype 6 = RR management messages
    if sub_type == 6:
        decode_rrlp(payload)

