#!/usr/bin/env python3
"""
rrlp_sniffer_decode.py
- Listen GSMTAP UDP (default 127.0.0.1:4729)
- Extract RR (subtype 6) payload
- Find RRLP APDU (search for leading 0x0A tag)
- Try to decode with asn1tools using UPER (unaligned PER)
Requirements:
  pip install asn1tools
  place RRLP.asn (ASN.1 module from 3GPP TS 04.31) in same dir or set ASN1_PATH
"""

import socket
import asn1tools
import binascii
import os
import sys
from typing import Optional

# Config
GSMTAP_IP = "127.0.0.1"
GSMTAP_PORT = 4729
ASN1_PATH = "RRLP.asn"   # path ke file ASN.1 yang berisi modul RRLP
ASN1_MODULE_NAME = "RRLP"   # module name di .asn (biasanya 'RRLP' atau 'RRLP-Module')
ASN1_TYPE = "RRLP-Message"  # type top-level yang ingin didecode

# Load ASN.1 module (UPER)
if not os.path.exists(ASN1_PATH):
    print(f"[!] ASN.1 file not found at {ASN1_PATH}. Please download TS 04.31 and extract RRLP ASN.1 as {ASN1_PATH}")
    sys.exit(1)

print(f"[+] Compiling ASN.1 from {ASN1_PATH} (UPER)")
try:
    asn1_spec = asn1tools.compile_files(ASN1_PATH, 'uper')
except Exception as e:
    print("[!] Failed to compile ASN.1:", e)
    sys.exit(1)

# Helper: parse minimal GSMTAP header (flexible)
def parse_gsmtap(packet: bytes):
    # require minimal header of 12 bytes; OpenBTS uses GSMTAP over UDP
    if len(packet) < 12:
        return None
    version = packet[0]
    subtype = packet[3]
    payload = packet[12:]
    return version, subtype, payload

# Helper: find likely RRLP start offset in payload
def find_rrlp_offset(payload: bytes) -> Optional[int]:
    # RRLP uses ASN.1; many RRLP PDUs start with tag 0x0A (context-specific or OCTET STRING)
    # We'll search for 0x0A or for sequence tag 0x30 as heuristic.
    candidates = []
    for t in (b'\x0a', b'\x30'):
        idx = payload.find(t)
        if idx != -1:
            candidates.append(idx)
    if not candidates:
        return None
    return min(candidates)

# Attempt to decode bytes via asn1tools
def try_decode(rrlp_bytes: bytes):
    try:
        # asn1tools expects the raw PER bytes
        decoded = asn1_spec.decode(ASN1_TYPE, rrlp_bytes)
        return decoded
    except Exception as e:
        # decode failed -> return exception
        return e

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GSMTAP_IP, GSMTAP_PORT))
    print(f"[RRLP Sniffer] Listening on {GSMTAP_IP}:{GSMTAP_PORT}")

    while True:
        data, addr = sock.recvfrom(4096)
        parsed = parse_gsmtap(data)
        if not parsed:
            continue
        version, subtype, payload = parsed
        # subtype 6 often corresponds to Radio Resource messages
        if subtype != 6:
            continue

        # find RRLP offset in payload
        off = find_rrlp_offset(payload)
        if off is None:
            # nothing to decode
            continue

        rrlp_apdu = payload[off:]
        print("\n[+] RRLP candidate (hex):", binascii.hexlify(rrlp_apdu).decode())

        # try decode
        result = try_decode(rrlp_apdu)
        if isinstance(result, Exception):
            print("[!] ASN.1 decode failed:", result)
            # Could try alternative slicing heuristics:
            # - try ignore first byte, or try smaller window
            # e.g. for i in range(0, min(20, len(rrlp_apdu))): try decode rrlp_apdu[i:]
            for i in range(1, min(12, len(rrlp_apdu))):
                attempt = rrlp_apdu[i:]
                try:
                    d = asn1_spec.decode(ASN1_TYPE, attempt)
                    print(f"[+] Decoded with offset {i}:")
                    print(d)
                    break
                except Exception:
                    continue
            else:
                print("[!] No alternate decode succeeded. Save hex to file for offline analysis.")
                with open("rrlp_last_hex.txt", "w") as fh:
                    fh.write(binascii.hexlify(rrlp_apdu).decode())
                print("[i] Saved rrlp_last_hex.txt")
        else:
            print("[=] Decoded RRLP message:")
            print(result)

if __name__ == "__main__":
    main()
