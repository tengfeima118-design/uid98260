#!/usr/bin/env python3
"""从荣耀 OTA payload 直接提取 boot 分区里的 kernel，并反汇编三处关键判断。

不依赖 bootimg 工具链，全靠 protobuf 手工解析 + Range 下载。
路径已由 boot/RESULT_110.md 验证过（2026-11-18 拿到 96MB boot.img，内核串与本机一致）。

用法: python3 fetch_and_audit.py
输出: kernel.bin（解压后的 ARM64 Image）+ 反汇编报告
"""
import bz2
import io
import lzma
import struct
import sys
import urllib.request

BASE = 'http://update.hihonorcdn.com/TDS/data/bl/files/v939464/f1/full'
UA = 'curl/8.5.0'
PREFIX = BASE + '/'


def http_range(url, start, end):
    req = urllib.request.Request(url, headers={
        'User-Agent': UA,
        'Range': 'bytes=%d-%d' % (start, end),
    })
    for attempt in range(4):
        try:
            r = urllib.request.urlopen(req, timeout=120)
            return r.read()
        except Exception as e:
            if attempt == 3:
                raise
            print('  retry %d: %s' % (attempt, e))


def parse_proto(buf, pos, end, depth=0):
    """极简 protobuf 解析，返回 [(field_no, wire_type, value)]"""
    out = []
    while pos < end:
        # varint key
        key = 0
        shift = 0
        while pos < end:
            b = buf[pos]
            pos += 1
            key |= (b & 0x7f) << shift
            if not (b & 0x80):
                break
            shift += 7
        if pos >= end:
            break
        fn = key >> 3
        wt = key & 7
        if wt == 0:  # varint
            v = 0
            shift = 0
            while pos < end:
                b = buf[pos]
                pos += 1
                v |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            out.append((fn, wt, v))
        elif wt == 2:  # length-delimited
            ln = 0
            shift = 0
            while pos < end:
                b = buf[pos]
                pos += 1
                ln |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if pos + ln > end:
                break
            out.append((fn, wt, buf[pos:pos + ln]))
            pos += ln
        elif wt == 5:  # 32-bit
            out.append((fn, wt, struct.unpack_from('<I', buf, pos)[0]))
            pos += 4
        elif wt == 1:  # 64-bit
            out.append((fn, wt, struct.unpack_from('<Q', buf, pos)[0]))
            pos += 8
        else:
            break
    return out, pos


def main():
    print('=== 1. filelist.xml ===')
    req = urllib.request.Request(PREFIX + 'filelist.xml', headers={'User-Agent': UA})
    fl = urllib.request.urlopen(req, timeout=60).read().decode('utf-8', 'replace')
    import re
    m = re.search(r'<payloadOffset>(\d+)</payloadOffset>', fl)
    payload_off = int(m.group(1)) if m else 828
    print('payloadOffset =', payload_off)

    # payload.bin 大小：从 zip central directory 或已知值取。
    # 先读 payload.bin 头部 24 字节确认
    print('\n=== 2. payload header ===')
    hdr = http_range(PREFIX + 'payload.bin', payload_off, payload_off + 31)
    print('magic =', hdr[:4])
    if hdr[:4] != b'CrAU':
        print('!! magic mismatch')
        return
    ver = struct.unpack_from('>Q', hdr, 4)[0]
    manifest_size = struct.unpack_from('>Q', hdr, 12)[0]
    sig_size = struct.unpack_from('>I', hdr, 20)[0]
    print('version=%d manifest_size=%d sig_size=%d' % (ver, manifest_size, sig_size))
    data_base = payload_off + 24 + manifest_size + sig_size
    print('data_base =', data_base)

    print('\n=== 3. manifest ===')
    man = http_range(PREFIX + 'payload.bin', payload_off + 24,
                     payload_off + 24 + manifest_size - 1)
    print('manifest bytes =', len(man))
    parts, _ = parse_proto(man, 0, len(man), 0)
    print('top fields:', [(f, w) for f, w, _ in parts])

    # field 13 = partitions
    boot_info = None
    for fn, wt, val in parts:
        if fn != 13 or wt != 2:
            continue
        fields, _ = parse_proto(val, 0, len(val))
        name = None
        ops = []
        for f2, w2, v2 in fields:
            if f2 == 1 and w2 == 2:
                name = v2.decode('utf-8', 'replace')
            elif f2 == 8 and w2 == 2:   # ops
                ops.append(v2)
            elif f2 == 7 and w2 == 2:   # new_partition_info
                pass
        if name == 'boot' and ops:
            print('found boot partition, ops =', len(ops))
            boot_info = ops
            break

    if not boot_info:
        print('!! boot partition not found')
        return

    print('\n=== 4. boot partition ops ===')
    total = 0
    ops_parsed = []
    for raw in boot_info:
        f3, _ = parse_proto(raw, 0, len(raw))
        typ = None
        doff = dlen = 0
        extent = None
        for fn, wt, val in f3:
            if fn == 1:
                typ = val
            elif fn == 2:
                doff = val
            elif fn == 3:
                dlen = val
            elif fn == 6 and wt == 2:
                ef, _ = parse_proto(val, 0, len(val))
                sb = nb = 0
                for f4, w4, v4 in ef:
                    if f4 == 1:
                        sb = v4
                    elif f4 == 2:
                        nb = v4
                extent = (sb, nb)
        ops_parsed.append((typ, doff, dlen, extent))
        total += dlen
    print('total data bytes =', total)
    # 打印前几个 op 概览
    for i, (t, o, l, e) in enumerate(ops_parsed[:6]):
        print('  op%d type=%s off=%d len=%d extent=%s' % (i, t, o, l, e))

    print('\n=== 5. download + decompress boot ops ===')
    img = bytearray()
    for i, (typ, doff, dlen, extent) in enumerate(ops_parsed):
        s = data_base + doff
        e = s + dlen - 1
        blob = http_range(PREFIX + 'payload.bin', s, e)
        if typ == 0:      # REPLACE
            data = blob
        elif typ == 1:    # REPLACE_BZ
            data = bz2.decompress(blob)
        elif typ == 8:    # REPLACE_XZ
            data = lzma.decompress(blob)
        else:
            print('  op%d unknown type %s, skip' % (i, typ))
            continue
        img.extend(data)
        if i % 8 == 0 or i == len(ops_parsed) - 1:
            print('  op%d/%d type=%s raw=%d out=%d total=%d'
                  % (i, len(ops_parsed), typ, dlen, len(data), len(img)))

    print('\n=== 6. boot.img ===')
    print('size =', len(img))
    print('magic =', bytes(img[:8]))
    open('boot.img', 'wb').write(img)

    # 解析 boot header v4
    if bytes(img[:8]) == b'ANDROID!':
        kernel_size = struct.unpack_from('<I', img, 8)[0]
        ramdisk_size = struct.unpack_from('<I', img, 12)[0]
        hdr_ver = struct.unpack_from('<I', img, 40)[0]
        print('kernel_size=%d ramdisk_size=%d header_version=%d'
              % (kernel_size, ramdisk_size, hdr_ver))
        # v4 header 大小对齐 4096
        kv = 4096 if hdr_ver >= 3 else 2048
        kernel = img[kv:kv + kernel_size]
        print('kernel bytes =', len(kernel))
        open('kernel.bin', 'wb').write(kernel)
        # 找 Linux version 串
        pos = bytes(kernel).find(b'Linux version ')
        if pos >= 0:
            print('kernel release:', kernel[pos:pos + 120].split(b' ')[0].decode('ascii', 'replace'))
    print('\nDONE')


if __name__ == '__main__':
    main()