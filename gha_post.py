#!/usr/bin/env python3
"""GHA 侧：修 TLS 对齐；只输出摘要（产物走 artifact 上传）。"""
import struct, sys, hashlib

P = '/tmp/uid0'
b = bytearray(open(P, 'rb').read())
e_phoff = struct.unpack_from('<Q', b, 0x20)[0]
e_phentsize = struct.unpack_from('<H', b, 0x36)[0]
e_phnum = struct.unpack_from('<H', b, 0x38)[0]
done = False
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    if struct.unpack_from('<I', b, off)[0] == 7:      # PT_TLS
        old = struct.unpack_from('<Q', b, off + 48)[0]
        if old < 64:
            struct.pack_into('<Q', b, off + 48, 64)
            print('PT_TLS p_align %d -> 64' % old)
        done = True
        break
open(P, 'wb').write(bytes(b))
print('tls_patched=%s' % done)

data = open(P, 'rb').read()
print('SIZE=%d' % len(data))
print('SHA256=%s' % hashlib.sha256(data).hexdigest())