#!/usr/bin/env python3
"""
rrlp_auto.py
- Listen GSMTAP UDP (default 127.0.0.1:4729)
- Detect RRLP PDUs (msrPositionReq / msrPositionRsp)
- Decode using RRLP.asn via asn1tools (UPER)
- Log results to CSV and optionally POST to HTTP callback
Usage:
  python3 rrlp_auto.py --gsmtap-ip 127.0.0.1 --gsmtap-port 4729 --asn RRLP.asn
"""
import socket, argparse, os, time, csv, binascii, threading, json
import asn1tools

DEFAULT_GSMTAP_IP = "127.0.0.1"
DEFAULT_GSMTAP_PORT = 4729
DEFAULT_ASN = "RRLP.asn"
LOG_CSV = "rrlp_locations.csv"

def compile_asn1(asn1_path):
    if not os.path.exists(asn1_path):
        raise FileNotFoundError(f"ASN.1 file not found: {asn1_path}")
    return asn1tools.compile_files(asn1_path, 'uper')

def parse_gsmtap(packet: bytes):
    # minimal header: 12 bytes (version, hdr_len, type, subtype, reserved...)
    if len(packet) < 12:
        return None
    version = packet[0]
    hdr_len = packet[1]
    pkt_type = packet[2]
    subtype = packet[3]
    payload = packet[hdr_len:] if hdr_len <= len(packet) else packet[12:]
    return { 'version': version, 'hdr_len': hdr_len, 'type': pkt_type, 'subtype': subtype, 'payload': payload }

def find_rrlp_offset(payload: bytes):
    # heuristic: search for ASN.1 tag 0x0A (context-specific) or CHOICE (0x30) as before
    for t in (b'\x0a', b'\x30'):
        idx = payload.find(t)
        if idx != -1:
            return idx
    return None

def save_csv(row):
    write_header = not os.path.exists(LOG_CSV)
    with open(LOG_CSV, 'a', newline='') as fh:
        w = csv.writer(fh)
        if write_header:
            w.writerow(['timestamp','msg_type','imsi_or_tmsi','lat','lon','unc','raw_hex'])
        w.writerow(row)

def handle_rrlp_decoded(decoded_choice):
    # decoded_choice is ('msrPositionRsp', {...}) or ('msrPositionReq', {...})
    typ, data = decoded_choice
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if typ == 'msrPositionRsp':
        pe = data.get('positionEstimate', {})
        lat_sign = pe.get('latitudeSign','north')
        lat = pe.get('latitude', None)
        lon = pe.get('longitude', None)
        unc = pe.get('uncertainty', None)
        # decode our lab encoding: lat/lon scaled by 1e5 if present
        if lat is not None and lon is not None:
            lat_deg = (lat / 1e5) * (1 if lat_sign == 'north' else -1)
            lon_deg = lon / 1e5
        else:
            lat_deg, lon_deg = None, None
        raw_hex = binascii.hexlify(last_rrlp_bytes).decode() if 'last_rrlp_bytes' in globals() else ''
        save_csv([ts, typ, '', lat_deg, lon_deg, unc, raw_hex])
        print(f"[{ts}] RRLP RSP -> lat={lat_deg}, lon={lon_deg}, unc={unc}")
    else:
        # log request types
        print(f"[{ts}] RRLP REQ -> {data}")
        save_csv([ts, typ, '', '', '', '', binascii.hexlify(last_rrlp_bytes).decode()])

def listen_and_decode(gsmtap_ip, gsmtap_port, asn_spec):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((gsmtap_ip, gsmtap_port))
    print(f"[rrlp_auto] Listening GSMTAP on {gsmtap_ip}:{gsmtap_port}")
    while True:
        pkt, addr = s.recvfrom(8192)
        parsed = parse_gsmtap(pkt)
        if not parsed: 
            continue
        subtype = parsed['subtype']
        payload = parsed['payload']
        # only handle RR messages (subtype 6) as convention
        if subtype != 6:
            continue
        off = find_rrlp_offset(payload)
        if off is None:
            continue
        rrlp_apdu = payload[off:]
        global last_rrlp_bytes
        last_rrlp_bytes = rrlp_apdu
        # try decode
        try:
            decoded = asn_spec.decode('RRLP-Message', rrlp_apdu)
            # decoded is a tuple for CHOICE
            handle_rrlp_decoded(decoded)
        except Exception as e:
            # could not decode: store raw for offline analysis
            print("[rrlp_auto] ASN.1 decode failed:", e)
            with open('rrlp_raw_last.hex','wb') as fh:
                fh.write(rrlp_apdu)
            continue

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gsmtap-ip', default=DEFAULT_GSMTAP_IP)
    parser.add_argument('--gsmtap-port', type=int, default=DEFAULT_GSMTAP_PORT)
    parser.add_argument('--asn', default=DEFAULT_ASN)
    args = parser.parse_args()

    spec = compile_asn1(args.asn)
    listen_and_decode(args.gsmtap_ip, args.gsmtap_port, spec)

if __name__ == '__main__':
    import argparse
    main()
