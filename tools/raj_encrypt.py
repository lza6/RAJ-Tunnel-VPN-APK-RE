#!/usr/bin/env python3
"""Inverse of raj_decrypt.py: pack a JSON config into the app's base64 blob.

    plain  --xxtea_encrypt(key=K[0:16])-->  mid
    mid    --AES-128-CBC(key=K[0:16], iv=0, PKCS7)-->  raw
    raw    --base64-->  text

Round-trip verified against the shipped blob in res/raw/servers (see self-test).
"""
import base64
import json
import struct
import sys

from raj_decrypt import AES_KEY, IV, K, MASK, DELTA, MYKEY, _mx, decrypt_text


def xxtea_encrypt(data, key_bytes):
    n = len(data) // 4
    if n < 2:
        return data
    v = list(struct.unpack('<%dI' % n, data[:n * 4]))
    key = list(struct.unpack('<4I', key_bytes))
    rounds = 6 + 52 // n
    total = 0
    z = v[n - 1]
    while rounds:
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + _mx(total, y, z, p, e, key)) & MASK
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + _mx(total, y, z, n - 1, e, key)) & MASK
        z = v[n - 1]
        rounds -= 1
    return struct.pack('<%dI' % n, *v)


def aes_encrypt(raw):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    pad = 16 - (len(raw) % 16)
    raw = raw + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV)).encryptor()
    return enc.update(raw) + enc.finalize()


def pack_text(plain_text):
    data = plain_text.encode('utf-8')
    if len(data) % 4:
        raise ValueError('xxtea needs a 4-byte aligned payload; pad the JSON')
    return base64.b64encode(aes_encrypt(xxtea_encrypt(data, AES_KEY))).decode()


def self_test():
    blob = open('../apktool_out/res/raw/d.js', encoding='utf-8').read()
    _aes, plain = decrypt_text(blob)
    # re-pack the exact plaintext the app would store
    repacked = pack_text(plain.decode('utf-8'))
    _aes2, plain2 = decrypt_text(repacked)
    return plain == plain2, len(plain)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        ok, n = self_test()
        print('myKey =', MYKEY)
        print('sha256 =', K.hex())
        print('round-trip ok =', ok, 'payload bytes =', n)
        sys.exit(0 if ok else 1)
    src = open(sys.argv[1], encoding='utf-8').read()
    cfg = json.loads(src)
    text = json.dumps(cfg, separators=(',', ':'))
    # xxtea requires 4-byte alignment; whitespace padding keeps JSON valid
    while len(text.encode()) % 4:
        text += ' '
    print(pack_text(text))
