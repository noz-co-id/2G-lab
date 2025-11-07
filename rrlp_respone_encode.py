#!/usr/bin/env python3
"""
rrlp_response_encode.py
- Compile RRLP.asn (UPER)
- Encode a MsrPosition-Rsp (RRLP-Message choice)
- PositionEstimate includes latitudeSign, latitude, longitude, uncertainty
- Send to GSMTAP UDP 127.0.0.1:4729
Usage:
  python3 rrlp_response_encode.py --lat -6.2088 --lon 106.8456 --unc 25
"""
import argparse
import os
import sys
import socket
import asn1tools

GSMTAP_IP = "127.0.0.1"
GSMTAP_PORT = 4729
ASN1_FILE = "RRLP.asn"
ASN1_TYPE = "RRLP-Message"

def compile_asn1(asn1_path):
    if not os.path.exists(asn1_path):
        print("[!] ASN.1 file not found:", asn1_path); sys.exit(1)
    try:
        return asn1tools.compile_files(asn1_path, 'uper')
    except Exception as e:
        print("[!] ASN.1 compile error:", e); sys.exit(1)

def latlon_to_int(lat, lon):
    """
    Simple mapping for lab tests:
    - latitude stored as integer 0..8388607 per ASN we defined
    - We'll map degrees * 1e5 and clamp into range.
    This is a lab-only convention to produce integers decodable by our ASN.1
    """
    lat_int = int(round(abs(lat) * 1e5))
    lon_int = int(round(lon * 1e5))  # allow negative for west
    # clamp to our artificial ASN range:
    lat_int = max(0, min(lat_int, 8388607))
    lon_int = max(-8388608, min(lon_int, 8388607))
    return lat_int, lon_int

def make_gsmtap_header(subtype=6):
    version = 0
    hdr_len = 12
    pkt_type = 0
    sub_type = subtype
    header = bytes([version & 0xFF, hdr_len & 0xFF, pkt_type & 0xFF, sub_type & 0xFF]) + b'\x00'*8
    return header

def send_packet(payload_bytes, ip=GSMTAP_IP, port=GSMTAP_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload_bytes, (ip, port))
    sock.close()

def build_response_dict(lat, lon, unc):
    lat_int, lon_int = latlon_to_int(lat, lon)
    pos_est = {
        'latitudeSign': 'north' if lat >= 0 else 'south',
        'latitude': lat_int,
        'longitude': lon_int,
        'uncertainty': int(unc) if unc is not None else None
    }
    rsp = {
        'referenceFrame': None,  # optional; omit for brevity
        'gpsTOW': None,
        'positionEstimate': pos_est,
        'additionalData': None
    }
    # remove None fields (asn1tools prefers not providing absent OPTIONALs)
    rsp_clean = {k:v for k,v in rsp.items() if v is not None}
    # CHOICE top-level
    return ('msrPositionRsp', rsp_clean)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--lat', type=float, required=True)
    p.add_argument('--lon', type=float, required=True)
    p.add_argument('--unc', type=int, default=25)
    p.add_argument('--gsmtap-ip', default=GSMTAP_IP)
    p.add_argument('--gsmtap-port', type=int, default=GSMTAP_PORT)
    args = p.parse_args()

    spec = compile_asn1(ASN1_FILE)
    choice = build_response_dict(args.lat, args.lon, args.unc)

    try:
        encoded = spec.encode(ASN1_TYPE, choice)
    except Exception as e:
        print("[!] ASN.1 encode error:", e); sys.exit(1)

    header = make_gsmtap_header(subtype=6)
    pkt = header + encoded
    send_packet(pkt, ip=args.gsmtap_ip, port=args.gsmtap_port)
    print("[+] Sent MsrPositionRsp (hex):", encoded.hex())

if __name__ == '__main__':
    main()
