#!/usr/bin/env python3
"""Decode ADVobfuscator `ay::obfuscated_data<N,S,char>` blobs inside libovpn3.so.

Scheme (verified against the inlined decrypt() code in the ELF):
    plain[i] = data[i] ^ (S >> ((i % 8) * 8)) & 0xFF
and the object carries an initialisation flag byte at offset N.
"""
import sys
import lief

SEEDS = {
    15: 17721967249065757669,
    20: 3873561330253515619,
    7: 1951716699498820017,
    19: 8446249956535678409,
    16: 8740322568189054307,
    18: [5324217346868729765, 9881295515925343055],
    11: 3137042308497528243,
    14: 14097700087097695641,
    22: 17829156310495070669,
    23: 13484062878387238685,
    8: 13364409833050597675,
    1849: 13401900446109391757,
}


def keystream(seed, n):
    b = seed.to_bytes(8, 'little')
    return bytes(b[i % 8] for i in range(n))


def decode(data, seed, n):
    ks = keystream(seed, n)
    return bytes(data[i] ^ ks[i] for i in range(n))


def printable(b):
    return all(32 <= c < 127 or c in (9,) for c in b)


def main():
    img = lief.parse(sys.argv[1])
    sections = [(s.name, s.virtual_address, bytes(s.content)) for s in img.sections if s.size]
    hits = []
    pairs = []
    for n, s in SEEDS.items():
        for seed in (s if isinstance(s, list) else [s]):
            pairs.append((n, seed))
    for name, va, content in sections:
        if name not in ('.rodata', '.data', '.data.rel.ro'):
            continue
        for offset in range(len(content)):
            for n, seed in pairs:
                if offset + n + 1 > len(content):
                    continue
                blob = content[offset:offset + n]
                if blob[0] == 0:
                    continue
                out = decode(blob, seed, n)
                if printable(out) and content[offset + n] != 0:
                    hits.append((va + offset, name, n, seed, out))
    seen = set()
    for addr, name, n, seed, out in sorted(hits):
        key = out
        if key in seen:
            continue
        seen.add(key)
        try:
            text = out.decode('ascii')
        except UnicodeDecodeError:
            continue
        print(f'{addr:#010x} {name:<14} N={n:<5} S={seed:<22} {text!r}')


if __name__ == '__main__':
    main()
