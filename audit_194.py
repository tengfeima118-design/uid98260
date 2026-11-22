#!/usr/bin/env python3
"""194 内核三路反汇编判定：
1. core_sys_select  → 43499 pselect 载体的 fd_set 落点（栈 or 堆）
2. exit_itimers / posix_cpu_timers_exit → 98260 修复状态
3. wacom_remove → 99491 漏洞本体（touch_input 是否置 NULL）

输入：vmlinux.elf（带符号）
用法：python3 audit_194.py <vmlinux.elf>
"""
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    sys.exit('need capstone')

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit('need pyelftools')

TARGETS = {
    '43499': ['core_sys_select', 'do_select', 'sys_select', 'sys_pselect6',
              'kern_select', 'do_pselect'],
    '98260': ['exit_itimers', 'posix_cpu_timers_exit', 'timerqueue_del',
              'posix_cpu_timer_del'],
    '99491': ['wacom_remove', 'wacom_wac_event', 'uhid_dev_destroy',
              'wacom_disconnect'],
}


def load(path):
    f = open(path, 'rb')
    elf = ELFFile(f)
    symtab = elf.get_section_by_name('.symtab')
    syms = {}
    order = []
    if symtab is not None:
        for s in symtab.iter_symbols():
            if s.name and s['st_shndx'] != 'SHN_UNDEF' and s['st_info']['type'] == 'STT_FUNC':
                if s.name not in syms:
                    syms[s.name] = s['st_value']
                    order.append(s['st_value'])
    order.sort()
    return f, elf, syms, order


def read_va(f, elf, va, ln):
    for seg in elf.iter_segments():
        if seg['p_type'] != 'PT_LOAD':
            continue
        start = seg['p_vaddr']
        end = start + seg['p_filesz']
        if start <= va and va + ln <= end:
            f.seek(seg['p_offset'] + (va - start))
            return f.read(ln)
    return None


def func_bytes(f, elf, syms, order, name, maxlen=0x2000):
    if name not in syms:
        return None, None, None
    addr = syms[name]
    nxt = None
    for v in order:
        if v > addr:
            nxt = v
            break
    if nxt is None or nxt > addr + maxlen:
        nxt = addr + maxlen
    data = read_va(f, elf, addr, nxt - addr)
    return addr, data, nxt - addr


def dis(data, base):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    out = []
    for i in md.disasm(data, base):
        out.append((i.address, i.mnemonic, i.op_str))
    return out


def analyze(path):
    f, elf, syms, order = load(path)
    print('=== symbols loaded: %d ===' % len(syms))

    # ---------- 1. 43499 pselect ----------
    print('\n' + '=' * 70)
    print('### 1. 43499 / pselect carrier: fd_set 落点')
    print('=' * 70)
    for name in TARGETS['43499']:
        addr, data, size = func_bytes(f, elf, syms, order, name)
        if data is None:
            print('[--] %s : NOT IN SYMTAB' % name)
            continue
        ins = dis(data, addr)
        print('\n[ok] %s @ %#x  size=%#x  insns=%d' % (name, addr, size, len(ins)))
        # 统计关键指令
        heap_calls = []
        stack_alloc = []
        for a, m, o in ins:
            if m == 'bl' or m == 'b':
                if any(k in o for k in ('kmalloc', 'kvmalloc', 'kzalloc',
                                        'alloc_pages', 'vmalloc', 'kvcalloc')):
                    heap_calls.append((a, m, o))
            if m == 'sub' and o.startswith('sp, sp,'):
                stack_alloc.append((a, m, o))
        print('  栈分配(sub sp): %d 处' % len(stack_alloc))
        for a, m, o in stack_alloc[:6]:
            print('    %#x  %s %s' % (a, m, o))
        print('  堆分配调用: %d 处' % len(heap_calls))
        for a, m, o in heap_calls[:8]:
            print('    %#x  %s %s' % (a, m, o))
        # 判定
        if heap_calls and not stack_alloc:
            print('  ==> VERDICT: HEAP  (不受 INIT_STACK_ALL_ZERO 影响)')
        elif stack_alloc and not heap_calls:
            print('  ==> VERDICT: STACK (会被栈清零封死)')
        elif heap_calls and stack_alloc:
            print('  ==> VERDICT: BOTH  (需人看: 都出现了)')
        else:
            print('  ==> VERDICT: UNKNOWN (既无栈分配也无堆调用)')
        # 打印前 25 条指令供人工核对
        print('  --- first 25 insns ---')
        for a, m, o in ins[:25]:
            print('    %#x  %-8s %s' % (a, m, o))

    # ---------- 2. 98260 ----------
    print('\n' + '=' * 70)
    print('### 2. 98260: exit_itimers / posix_cpu_timers_exit 修复状态')
    print('=' * 70)
    for name in TARGETS['98260']:
        addr, data, size = func_bytes(f, elf, syms, order, name)
        if data is None:
            print('[--] %s : NOT IN SYMTAB' % name)
            continue
        ins = dis(data, addr)
        print('\n[ok] %s @ %#x  size=%#x  insns=%d' % (name, addr, size, len(ins)))
        calls = []
        rbclear = []
        for a, m, o in ins:
            if m == 'bl':
                calls.append((a, o))
            # RB_CLEAR_NODE 特征: str xzr / str <reg> 指向 node+0x0
            if m == 'str' and 'xzr' in o:
                rbclear.append((a, m, o))
        print('  bl 调用: %d 处' % len(calls))
        for a, o in calls[:15]:
            print('    %#x  bl %s' % (a, o))
        print('  str xzr 清零操作: %d 处' % len(rbclear))
        for a, m, o in rbclear[:10]:
            print('    %#x  %s %s' % (a, m, o))
        print('  --- first 30 insns ---')
        for a, m, o in ins[:30]:
            print('    %#x  %-8s %s' % (a, m, o))

    # ---------- 3. 99491 ----------
    print('\n' + '=' * 70)
    print('### 3. 99491: wacom_remove 是否把 touch_input 置 NULL')
    print('=' * 70)
    for name in TARGETS['99491']:
        addr, data, size = func_bytes(f, elf, syms, order, name)
        if data is None:
            print('[--] %s : NOT IN SYMTAB' % name)
            continue
        ins = dis(data, addr)
        print('\n[ok] %s @ %#x  size=%#x  insns=%d' % (name, addr, size, len(ins)))
        strs = [(a, m, o) for a, m, o in ins if m in ('str', 'stp') and 'xzr' in o]
        print('  str/stp xzr 清零: %d 处' % len(strs))
        for a, m, o in strs[:15]:
            print('    %#x  %-6s %s' % (a, m, o))
        print('  --- first 40 insns ---')
        for a, m, o in ins[:40]:
            print('    %#x  %-8s %s' % (a, m, o))

    print('\n=== DONE ===')


if __name__ == '__main__':
    analyze(sys.argv[1] if len(sys.argv) > 1 else 'vmlinux.elf')