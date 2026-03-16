#!/usr/bin/env python3
"""TLS 1.3 record layer parser."""
import struct, sys

CONTENT_TYPES = {20:"ChangeCipherSpec",21:"Alert",22:"Handshake",23:"Application"}
HANDSHAKE_TYPES = {1:"ClientHello",2:"ServerHello",4:"NewSessionTicket",
                  8:"EncryptedExtensions",11:"Certificate",13:"CertificateRequest",
                  15:"CertificateVerify",20:"Finished"}

def parse_record(data):
    ctype, ver_major, ver_minor, length = struct.unpack(">BBBH", data[:5])
    return {"type": CONTENT_TYPES.get(ctype, f"Unknown({ctype})"),
            "version": f"{ver_major}.{ver_minor}", "length": length,
            "payload": data[5:5+length]}

def build_record(ctype, payload, version=(3,3)):
    return struct.pack(">BBB", ctype, *version) + struct.pack(">H", len(payload)) + payload

def parse_client_hello(data):
    if data[0] != 1: return None
    length = struct.unpack(">I", b"\x00" + data[1:4])[0]
    ver = struct.unpack(">H", data[4:6])[0]
    random = data[6:38]
    sid_len = data[38]; sid = data[39:39+sid_len]
    offset = 39 + sid_len
    cs_len = struct.unpack(">H", data[offset:offset+2])[0]
    ciphers = [struct.unpack(">H", data[offset+2+i:offset+4+i])[0] for i in range(0, cs_len, 2)]
    return {"version": hex(ver), "random": random.hex()[:32]+"...",
            "session_id_len": sid_len, "cipher_suites": [hex(c) for c in ciphers[:5]]}

if __name__ == "__main__":
    # Build a minimal ClientHello
    random = bytes(range(32)); session_id = b""
    ciphers = struct.pack(">HHH", 0x1301, 0x1302, 0x1303)  # TLS_AES_128_GCM, etc
    ch = bytes([1]) + struct.pack(">I", 0)[1:]  # placeholder length
    ch_body = struct.pack(">H", 0x0303) + random + bytes([0]) + struct.pack(">H", 6) + ciphers + bytes([1, 0])
    ch = bytes([1]) + struct.pack(">I", len(ch_body))[1:] + ch_body
    record = build_record(22, ch)
    parsed = parse_record(record)
    print(f"Record: {parsed['type']}, version={parsed['version']}, len={parsed['length']}")
    hello = parse_client_hello(parsed['payload'])
    print(f"ClientHello: {hello}")
