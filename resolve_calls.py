#!/usr/bin/env python3
"""只解析函数内的 bl 调用目标符号名。"""
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile


def main():
    path = sys.argv[1]
    fname = sys.argv[2]
    f = open(path, 'rb')
    elf = ELFFile(f)
    symtab = elf.get_section_by_name('.symtab')
    syms = {}
    order = []
    for s in symtab.iter_symbols():
        if s.name and s['st_shndx'] != 'SHN_UNDEF' and s['st_info']['type'] == 'STT_FUNC':
            if s.name not in syms:
                syms[s.name] = s['st_value']
                order.append(s['st_value'])
    order.sort()
    by_addr = {}
    for n, a in syms.items():
        by_addr.setdefault(a, n)

    if fname not in syms:
        print('NOT IN SYMTAB:', fname)
        return
    addr = syms[fname]
    nxt = None
    for v in order:
        if v > addr:
            nxt = v
            break
    if nxt is None:
        nxt = addr + 0x2000
    size = nxt - addr
    data = None
    for seg in elf.iter_segments():
        if seg['p_type'] != 'PT_LOAD':
            continue
        st = seg['p_vaddr']
        en = st + seg['p_filesz']
        if st <= addr and addr + size <= en:
            f.seek(seg['p_offset'] + (addr - st))
            data = f.read(size)
            break
    print('=== %s @ %#x size=%#x ===' % (fname, addr, size))
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    n = 0
    for i in md.disasm(data, addr):
        if i.mnemonic == 'bl' and i.op_str.startswith('#'):
            tgt = int(i.op_str[1:], 16)
            nm = by_addr.get(tgt, '???')
            print('  %#x  bl  %#x  -> %s' % (i.address, tgt, nm))
            n += 1
    print('total bl =', n)


if __name__ == '__main__':
    main()