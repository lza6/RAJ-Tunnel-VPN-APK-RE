#!/usr/bin/env python3
"""RAJ Tunnel VPN — xl.a(long) string decryptor.

Reproduces the obfuscated string table decoder found in
defpackage/xl.java (jadx output of classes3.dex).

    public static String a(long j) {
        long j2 = ZIP_64_SIZE_LIMIT & j;
        long j3 = (j2 ^ (j2 >>> 33)) * 7109453100751455733L;
        long Z  = j7.Z(((j3 ^ (j3 >>> 28)) * (-3808689974395783757L)) >>> 32);
        long j4 = (Z >>> 32) & 65535;
        long Z2 = j7.Z(Z);
        int i   = (int) (((j >>> 32) ^ j4) ^ ((Z2 >>> 16) & (-65536)));
        long Z3 = j7.Z(Z2) ^ (strArr[i / 8191].charAt(i % 8191) << 32);
        int i2  = (int) ((Z3 >>> 32) & 65535);
        ...
    }

j7.Z(j) is a 16-bit Feistel-ish mixer implemented on two shorts.
"""
import re
import sys

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
ZIP64 = 4294967295


def s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def Z(j):
    j &= M64
    s = s16(j & 0xFFFF)
    s2 = s16((j >> 16) & 0xFFFF)
    s3 = s16(s + s2)
    s4 = s16(s2 ^ s)
    u4 = s4 & M32
    a = s16((u4 >> 22) | ((u4 << 10) & M32))
    u3 = s3 & M32
    b = s16(s16((u3 >> 23) | ((u3 << 9) & M32)) + s)
    us = s & M32
    c = s16(s16((us << 13 & M32) | (us >> 19)) ^ s4)
    c = s16(c ^ ((s4 << 5) & M32))
    out = (((a & M32) | ((b & M32) << 16)) << 16) | (c & M32)
    # int result widened to long (sign extend), then masked to 64 bits
    out &= M32
    if out & 0x80000000:
        out -= 1 << 32
    return out & M64


def _parse_java_string(src, pos):
    """Parse one double-quoted Java string literal starting at src[pos] == '"'."""
    assert src[pos] == '"'
    pos += 1
    out = []
    while True:
        ch = src[pos]
        if ch == '"':
            return ''.join(out), pos + 1
        if ch == '\\':
            nxt = src[pos + 1]
            if nxt == 'u':
                out.append(chr(int(src[pos + 2:pos + 6], 16)))
                pos += 6
                continue
            esc = {'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f',
                   '0': '\0', '\\': '\\', '"': '"', "'": "'"}.get(nxt, nxt)
            out.append(esc)
            pos += 2
            continue
        out.append(ch)
        pos += 1


def load_table(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    m = re.search(r'String\[\]\s+a\s*=\s*\{', src)
    if not m:
        raise SystemExit('string table not found')
    pos = m.end()
    chunks = []
    while True:
        while src[pos] in ' \t\r\n,':
            pos += 1
        if src[pos] == '}':
            break
        if src[pos] == '"':
            s, pos = _parse_java_string(src, pos)
            chunks.append(s)
        else:
            raise SystemExit(f'unexpected token at {pos}: {src[pos:pos+40]!r}')
    return ''.join(chunks)


def make_decoder(table):
    def dec(j):
        j &= M64
        j2 = ZIP64 & j
        j3 = ((j2 ^ (j2 >> 33)) * 7109453100751455733) & M64
        z = Z((((j3 ^ (j3 >> 28)) * (-3808689974395783757 & M64)) & M64) >> 32)
        j4 = (z >> 32) & 0xFFFF
        z2 = Z(z)
        i = (((j >> 32) ^ j4) ^ ((z2 >> 16) & 0xFFFF0000)) & M32
        if i & 0x80000000:
            i -= 1 << 32
        idx = i
        z3 = Z(z2) ^ (ord(table[idx % len(table)]) << 32)
        n = (z3 >> 32) & 0xFFFF
        chars = []
        for k in range(n):
            idx2 = i + k + 1
            z3 = Z(z3 & M64) ^ (ord(table[idx2 % len(table)]) << 32)
            chars.append(chr((z3 >> 32) & 0xFFFF))
        return ''.join(chars)
    return dec


if __name__ == '__main__':
    tbl = load_table(sys.argv[1])
    dec = make_decoder(tbl)
    print(f'table len = {len(tbl)}')
    for lit in sys.argv[2:]:
        j = int(lit.rstrip('L'))
        print(f'{lit} -> {dec(j)!r}')
