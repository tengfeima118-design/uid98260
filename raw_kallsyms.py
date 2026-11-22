#!/usr/bin/env python3
"""vmlinux-to-elf 失败时的兜底：报告 kernel.bin 的关键信息。
不做完整 kallsyms 解析，只给出足够判断的线索。"""
import sys

data = open('kernel.bin', 'rb').read()
print('kernel size =', len(data))
print('first 32 bytes =', data[:32].hex())

p = data.find(b'Linux version ')
print('\nLinux version @', p)
if p > 0:
    print(' ', data[p:p + 160])

# 若能读 /proc 里的 kallsyms 副本则交叉验证（GHA 上没有）
for fn in [b'exit_itimers', b'posix_cpu_timers_exit', b'timerqueue_del',
           b'core_sys_select', b'do_select', b'wacom_remove',
           b'wacom_wac_event', b'remove_waiter', b'uhid_dev_destroy']:
    idx = data.find(fn + b'\x00')
    print('%-24s name@ %d' % (fn.decode(), idx))

print('\n提示：kallsyms 名字表被剥离符号名，需 vmlinux-to-elf 重建。')