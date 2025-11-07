import asn1tools
import socket
import argparse
import os

# --- Argparse ---
parser = argparse.ArgumentParser()
parser.add_argument('--lat', type=float, required=True)
parser.add_argument('--lon', type=float, required=True)
parser.add_argument('--unc', type=int, default=50)
parser.add_argument('--gsmtap-ip', type=str, default="127.0.0.1")
parser.add_argument('--gsmtap-port', type=int, default=4729)
args = parser.parse_args()

# --- Compile ASN.1 ---
asn_file = os.path.join(os.path.dirname(__file__), "RRLP.asn")
rrlp = asn1tools.compile_files(asn_file, 'uper')

# --- Build RRLP message ---
msg = {
    'msrPositionRsp': {
        'lat': int(args.lat * 1_000_000),
        'lon': int(args.lon * 1_000_000),
        'unc': args.unc
    }
}

# --- Encode menggunakan tipe root RRLP-Message ---
encoded = rrlp.encode('RRLP-Message', msg)

# --- Kirim via GSMTAP ---
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(encoded, (args.gsmtap_ip, args.gsmtap_port))

print(f"[+] Sent RRLP dummy response: lat={args.lat}, lon={args.lon}, unc={args.unc}")
print(f"Hex: {encoded.hex()}")
