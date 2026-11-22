#!/usr/bin/env python3
"""ELF 不可用时的兜底：直接从 kernel.bin 找关键字符串与位置。"""
data = open('kernel.bin', 'rb').read()
print('kernel size =', len(data))

pos = data.find(b'Linux version ')
print('Linux version @', pos)
if pos > 0:
    print(data[pos:pos + 130])

# ARM64 Image 头：第一个 0x18 字节是 branch 指令 + 保留
print('first 16 bytes:', data[:16].hex())

# 找 kallsyms 相关标记
for key in [b'kallsyms_token_table', b'kallsyms_names', b'kallsyms_addresses',
            b'kallsyms_offsets', b'kallsyms_relative_base', b'kallsyms_num_syms']:
    p = data.find(key)
    print('%-26s @ %s' % (key.decode(), p))

# 找关键函数名（kallsyms 名字表里有）
for fn in [b'exit_itimers', b'posix_cpu_timers_exit', b'timerqueue_del',
           b'core_sys_select', b'do_select', b'wacom_remove',
           b'wacom_wac_event', b'remove_waiter']:
    p = data.find(fn + b'\x00')
    print('%-24s @ %s' % (fn.decode(), p))