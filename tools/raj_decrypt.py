#!/usr/bin/env python3
"""RAJ Tunnel VPN `servers` blob decryptor (offline reimplementation).

Recovered pipeline (libovpn3.so, JNI Java_renz_javacodez_vpn_utils_RenzUtils_decrypt):

    myKey    = constant recovered from rodata 0x1ff1f0 (14 bytes) + 0x1ff448 (8 bytes),
               XORed with keystream of ay::obfuscated_data<23, 13484062878387238685>
    K        = SHA256(myKey)
    raw      = base64_decode(input_text)                   # standard alphabet
    aes      = AES-128-CBC(key=K[0:16], iv=00*16, PKCS7)   # EVP_aes_128_cbc
    plain    = xxtea_decrypt(aes, key=K[0:16])             # 4 x uint32 LE words

usage: raj_decrypt.py <file-with-base64-blob> [--dump]
"""
import base64
import hashlib
import struct
import sys

# ---- ay::obfuscated_data keystream -------------------------------------
SEED_MYKEY = 13484062878387238685


def keystream(seed, n):
    b = seed.to_bytes(8, 'little')
    return bytes(b[i % 8] for i in range(n))


def recover_mykey():
    # rodata .data blob: 16 bytes @0x1ff1f0 + 8 bytes @0x1ff448 (23 chars + flag)
    raw = bytes.fromhex('490a3a68da7b1ac0355d332f8b4e14e3') + \
          bytes.fromhex('4703292ac5482101')
    out = bytes(raw[i] ^ keystream(SEED_MYKEY, 24)[i] for i in range(24))
    return out.split(b'\x00')[0]


MYKEY = recover_mykey()
K = hashlib.sha256(MYKEY).digest()
AES_KEY = K[:16]
IV = b'\x00' * 16

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def _mx(sum_, y, z, p, e, key):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z))) & MASK


def xxtea_decrypt(data, key_bytes):
    """Canonical XXTEA (Corrected Block TEA) decrypt, little-endian words.

    key_bytes must be exactly 16 bytes -> 4 words.
    """
    if len(data) < 8:
        return data
    n = len(data) // 4
    v = list(struct.unpack('<%dI' % n, data[:n * 4]))
    key = list(struct.unpack('<4I', key_bytes))
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & MASK
    y = v[0]
    while total:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _mx(total, y, z, p, e, key)) & MASK
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _mx(total, y, z, 0, e, key)) & MASK
        y = v[0]
        total = (total - DELTA) & MASK
    return struct.pack('<%dI' % n, *v)


def aes_decrypt(raw):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV)).decryptor()
    out = dec.update(raw) + dec.finalize()
    # PKCS7
    if out and 1 <= out[-1] <= 16 and out.endswith(bytes([out[-1]]) * out[-1]):
        out = out[:-out[-1]]
    return out


def decrypt_text(text):
    raw = base64.b64decode(text.strip())
    aes = aes_decrypt(raw)
    return aes, xxtea_decrypt(aes, AES_KEY)


B64_MIN = 8
B64_RE = __import__('re').compile(r'[A-Za-z0-9+/=]{%d,}' % B64_MIN)


def decrypt_field(value):
    """Decrypt one config field. Non-encrypted / non-printable values pass through."""
    if not isinstance(value, str) or not B64_RE.fullmatch(value):
        return value
    try:
        _aes, plain = decrypt_text(value)
    except Exception:
        return value
    text = plain.rstrip(b'\x00').decode('utf-8', 'replace')
    # xxtea leaves alignment padding on the tail (<0x20), e.g. b'1194\x04\x00\x00\x00'
    text = text.rstrip('\x00').rstrip(''.join(chr(i) for i in range(32)))
    if text and all(32 <= ord(c) < 127 for c in text):
        return text
    return value


def load_config(blob):
    """Decrypt a servers blob (base64 text) into a dict with all fields decrypted."""
    import json
    _aes, plain = decrypt_text(blob)
    cfg, _end = json.JSONDecoder().raw_decode(plain.decode('utf-8', 'replace'))

    def walk(node):
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        return decrypt_field(node)

    return walk(cfg)


def nodes_from_config(cfg):
    """Flatten a decrypted config into connectable endpoints."""
    out = []
    for s in cfg.get('Servers') or []:
        host = s.get('ServerIPHost') or ''
        out.append({
            'group': 'openvpn',
            'name': s.get('Subname') or s.get('Name') or '',
            'host': host,
            'port': str(s.get('OpenVPNTCPPort') or s.get('OpenVPNSSLPort') or ''),
            'ssl_port': str(s.get('OpenVPNSSLPort') or ''),
            'protocol': s.get('Protocol'),
            'flag': s.get('flag') or '',
            'udp': s.get('UDPMode') or 0,
            'obfs': s.get('Obfs') or '',
        })
    for n in cfg.get('Networks') or []:
        out.append({
            'group': 'network',
            'name': n.get('Info') or n.get('Name') or '',
            'host': n.get('SNIHost') or '',
            'port': '',
            'ssl_port': '',
            'protocol': n.get('TunnelType'),
            'flag': '',
            'udp': 0,
            'obfs': n.get('TLSVersion') or '',
        })
    for n in cfg.get('SSLNetworks') or []:
        out.append({
            'group': 'ssl',
            'name': n.get('Info') or n.get('Name') or '',
            'host': n.get('SNIHost') or '',
            'port': '',
            'ssl_port': '',
            'protocol': n.get('TunnelType'),
            'flag': '',
            'udp': 0,
            'obfs': n.get('TLSVersion') or '',
        })
    return out


if __name__ == '__main__':
    blob = open(sys.argv[1], encoding='utf-8').read()
    print('myKey  =', MYKEY)
    print('sha256 =', K.hex())
    aes, plain = decrypt_text(blob)
    print('aes len=%d head=%r' % (len(aes), aes[:48]))
    print('plain len=%d' % len(plain))
    text = plain.decode('utf-8', 'replace').rstrip('\x00')
    print(text[:2000])
