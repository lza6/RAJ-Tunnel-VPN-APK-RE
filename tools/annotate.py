#!/usr/bin/env python3
"""Disassemble a function in an AArch64 ELF and resolve call targets / string refs."""
import sys
import bisect
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def build(img):
    rel = {}
    for group in (img.relocations,):
        for r in group:
            if r.has_symbol:
                rel[r.address] = r.symbol.name
    try:
        for r in img.pltgot_relocations:
            if r.has_symbol:
                rel[r.address] = r.symbol.name
    except Exception:
        pass
    try:
        for r in img.dynamic_relocations:
            if r.has_symbol:
                rel[r.address] = r.symbol.name
    except Exception:
        pass
    syms = sorted((s.value, s.name, s.size) for s in img.symbols if s.name and s.value)
    secs = [(s.name, s.virtual_address, bytes(s.content)) for s in img.sections if s.size]
    return rel, syms, secs


def resolve_plt(img, secs, rel, stub):
    """Decode a 3-insn PLT stub, return the symbol it jumps to."""
    data = None
    for name, va, content in secs:
        if va <= stub < va + len(content):
            data = content[stub - va: stub - va + 12]
            break
    if data is None:
        return None
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(md.disasm(data, stub))
    if len(insns) < 2 or insns[0].mnemonic != 'adrp' or not insns[1].mnemonic.startswith('ldr'):
        return None
    try:
        page = int(insns[0].op_str.split(', ')[1].replace('#', ''), 16)
        off = insns[1].op_str.split('#')[-1]
        off = int(off.rstrip(']'), 16)
    except Exception:
        return None
    return rel.get(page + off)


def sym_at(syms, addr):
    values = [s[0] for s in syms]
    i = bisect.bisect_right(values, addr) - 1
    if i >= 0 and addr < syms[i][0] + max(syms[i][2], 1):
        return syms[i][1]
    return None


def readstr(secs, addr, n=64):
    for name, va, content in secs:
        if va <= addr < va + len(content):
            chunk = content[addr - va: addr - va + n]
            out = bytearray()
            for b in chunk:
                if 32 <= b < 127:
                    out.append(b)
                else:
                    break
            return out.decode()
    return ''


def main():
    path, target = sys.argv[1], sys.argv[2]
    length = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
    img = lief.parse(path)
    rel, syms, secs = build(img)
    addr = int(target, 16) if target.startswith('0x') else None
    size = 0
    if addr is None:
        for v, n, s in syms:
            if n == target:
                addr, size = v, s
                break
    if addr is None:
        print('not found')
        return 1
    if not length:
        length = size or 0x200
    data = None
    for name, va, content in secs:
        if va <= addr < va + len(content):
            data = content[addr - va: addr - va + length]
            break
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(md.disasm(data, addr))
    for idx, i in enumerate(insns):
        note = ''
        if i.mnemonic in ('bl', 'b') and i.op_str.startswith('#'):
            tgt = int(i.op_str.replace('#', ''), 16)
            name = resolve_plt(img, secs, rel, tgt)
            if name:
                try:
                    from cxxfilt import demangle
                    name = demangle(name)
                except Exception:
                    pass
                note = '  ; ' + name
            else:
                note = '  ; ' + (sym_at(syms, tgt) or f'sub_{tgt:x}')
        elif i.mnemonic == 'adrp':
            try:
                reg, imm = i.op_str.split(', ')
                base = int(imm.replace('#', ''), 16)
            except Exception:
                base = None
            if base:
                for j in range(idx + 1, min(idx + 4, len(insns))):
                    n = insns[j]
                    if n.mnemonic in ('add', 'ldr', 'ldrb', 'str'):
                        parts = n.op_str.split(', ')
                        if parts[0] == reg and parts[-1].startswith('#'):
                            try:
                                a = base + int(parts[-1].replace('#', ''), 16)
                            except Exception:
                                continue
                            st = readstr(secs, a)
                            if st:
                                note = f'  ; "{st}"'
                            break
        print(f'{i.address:#010x}: {i.mnemonic:<9} {i.op_str}{note}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
