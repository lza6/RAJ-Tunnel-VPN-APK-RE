#!/usr/bin/env python3
"""Minimal AArch64 function disassembler for an ELF .so using lief + capstone.

usage: disasm.py <so> <symbol-or-hex-offset> [length]
"""
import sys
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def main():
    so, target = sys.argv[1], sys.argv[2]
    length = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
    img = lief.parse(so)
    img.imagebase  # touch
    sym = None
    for s in img.symbols:
        if target in (s.name, hex(s.value)):
            sym = s
            break
    if sym is None:
        for s in img.dynamic_symbols:
            if target == s.name:
                sym = s
                break
    if sym is None:
        import re
        for s in img.symbols:
            if s.name and target in s.name:
                sym = s
                break
    if sym is None:
        print('symbol not found:', target)
        return 1
    addr, size = sym.value, sym.size
    if not length:
        length = size if size else 0x400
    print(f'{sym.name} @ {addr:#x} size={size:#x} len={length:#x}')
    data = None
    for sec in img.sections:
        if sec.virtual_address <= addr < sec.virtual_address + max(sec.size, 1):
            off = addr - sec.virtual_address
            data = bytes(sec.content)[off:off + length]
            break
    if data is None:
        print('section not found')
        return 1
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    for insn in md.disasm(data, addr):
        print(f'{insn.address:#010x}: {insn.mnemonic:<10} {insn.op_str}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
