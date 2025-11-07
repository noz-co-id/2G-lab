#!/usr/bin/env python3
"""
rrlp_trigger_encode.py
- Compile RRLP.asn (UPER)
- Encode a MsrPosition-Req as RRLP-Message
- Wrap with minimal GSMTAP header (subtype=6 -> RR messages)
- Send UDP to GSMTAP port (default 127.0.0.1:4729)

Usage:
  python3 rrlp_trigger_encode.py            # send default request
  python3 rrlp_trigger_encode.py --method gps --accuracy 50 --resp-time 5
"""
import argparse
import socket
import os
import sys
import asn1tools

# Config
GSMTAP_IP = "127.0.0.1"
GSMTAP_PORT = 4729
ASN1_FILE = "RRLP.asn"
ASN1_TYPE = "RRLP-Message"   # top-level CHOICE in our RRLP.asn

def compile_asn1(asn1_path):
    if not os.path.exists(asn1_path):
        print(f"[!] ASN.1 file not found: {asn1_path}")
        sys.exit(1)
    try:
        spec = asn1tools.compile_files(asn1_path, 'uper')
        return spec
    except Exception as e:
        print("[!] ASN.1 compile error:", e)
        sys.exit(1)

#def build_msrposition_req_dict(method_str, resp_time, accuracy):
#    # Map string to ENUM value as per RRLP.asn
#    method_map = {'eotd': 0, 'gps': 1, 'gpsOrEOTD': 2}
#    method_val = method_map.get(method_str, 1)
#    req = {
#        # asn1tools expects the ENUM as name or int; we use int here
#        'positionMethod': method_val,
#    }
#    if resp_time is not None:
#        req['measureResponseTime'] = int(resp_time)
#    if accuracy is not None:
#        req['accuracy'] = int(accuracy)
#    # environment is optional; omit for now
#    return {'msrPositionReq': req}
def build_msrposition_req_dict(method_str, resp_time, accuracy):
    # ENUM di ASN.1 harus berupa string, bukan integer
    method_str = method_str.lower()
    if method_str not in ['eotd', 'gps', 'gpsorEOTD'.lower()]:
        method_str = 'gps'

    req = {
        'positionMethod': method_str,  # ENUM pakai string
    }
    if resp_time is not None:
        req['measureResponseTime'] = int(resp_time)
    if accuracy is not None:
        req['accuracy'] = int(accuracy)

    # Kembalikan sebagai CHOICE tuple
    return ('msrPositionReq', req)

def make_gsmtap_header(subtype=6):
    """
    Build a minimal GSMTAP header of length 12 bytes:
    [0] version, [1] hdr_len, [2] type, [3] subtype, [4..11] reserved zeros
    We used parse_gsmtap in sniffer which expects payload = packet[12:].
    """
    version = 0
    hdr_len = 12
    pkt_type = 0
    sub_type = subtype
    header = bytes([
        version & 0xFF,
        hdr_len & 0xFF,
        pkt_type & 0xFF,
        sub_type & 0xFF,
        0,0,0,0,  # reserved
        0,0,0,0   # reserved to reach 12 bytes
    ])
    return header

def send_packet(payload_bytes, ip=GSMTAP_IP, port=GSMTAP_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload_bytes, (ip, port))
    sock.close()

def main():
    parser = argparse.ArgumentParser(description="RRLP trigger (encode + send to GSMTAP)")
    parser.add_argument('--method', choices=['eotd','gps','gpsOrEOTD'], default='gps',
                        help='position method (default gps)')
    parser.add_argument('--accuracy', type=int, default=None, help='requested accuracy (0..255)')
    parser.add_argument('--resp-time', type=int, default=None, help='measureResponseTime (0..255)')
    parser.add_argument('--gsmtap-ip', default=GSMTAP_IP)
    parser.add_argument('--gsmtap-port', type=int, default=GSMTAP_PORT)
    args = parser.parse_args()

    spec = compile_asn1(ASN1_FILE)
    rrlp_dict = build_msrposition_req_dict(args.method, args.resp_time, args.accuracy)

    try:
        encoded = spec.encode(ASN1_TYPE, rrlp_dict)
    except Exception as e:
        print("[!] ASN.1 encode error:", e)
        sys.exit(1)

    header = make_gsmtap_header(subtype=6)  # 6 = RR management messages
    packet = header + encoded

    print("[+] Sending RRLP (MsrPosition-Req) via GSMTAP -> %s:%d" % (args.gsmtap_ip, args.gsmtap_port))
    print("    method=%s, resp_time=%s, accuracy=%s" % (args.method, args.resp_time, args.accuracy))
    print("    encoded hex:", encoded.hex())

    send_packet(packet, ip=args.gsmtap_ip, port=args.gsmtap_port)
    print("[+] Done.")

if __name__ == "__main__":
    main()
