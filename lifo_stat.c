/*
 * lifo_stat: 定量测 L3 命中率
 *
 * 关键：每轮独立做 create -> destroy -> spray，统计样本数
 * 需要的样本量 >= 30 个 free 才有统计意义（0/2 无意义）
 *
 * 用法: lifo_stat <cpu> <rounds> <pairs> <payload>
 *
 * 输出每轮：free 触发次数、spray 条数、耗时
 * 判据由外部 trace 给出真实地址命中
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/uhid.h>

#define WACOM_VID   0x056a
#define PHYS_COMMON "statpair/77"

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
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n <= 0) usleep(500);
    }
    fcntl(fd, F_SETFL, fc);
}

int main(int argc, char **argv) {
    int cpu    = argc > 1 ? atoi(argv[1]) : 0;
    int rounds = argc > 2 ? atoi(argv[2]) : 30;
    int pairs  = argc > 3 ? atoi(argv[3]) : 300;
    int payload= argc > 4 ? atoi(argv[4]) : 1728;

    printf("=== lifo_stat === cpu=%d rounds=%d pairs=%d payload=%d pid=%d\n",
           cpu, rounds, pairs, payload, getpid());

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        printf("pin fail: %s\n", strerror(errno));
        return 2;
    }
    printf("pinned cpu=%d running=%d\n", cpu, sched_getcpu());

    /* 预建 socketpair（复用，每轮只 send/recv） */
    char *buf = malloc(payload);
    memset(buf, 0x53, payload);
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

    int total_sent = 0;
    for (int r = 0; r < rounds; r++) {
        int fdt = open("/dev/uhid", O_RDWR | O_CLOEXEC);
        if (fdt < 0) { printf("uhid open fail\n"); break; }
        if (uhid_create(fdt, "stat-touch", PHYS_COMMON, 0x1101,
                        rdesc_touch, sizeof(rdesc_touch)) < 0) {
            printf("create fail\n"); close(fdt); break;
        }
        pump(fdt, 150);
        usleep(150000);          /* 等 wacom 绑定 + input_dev 注册 */

        /* destroy -> 立即 spray */
        long t1 = now_us();
        uhid_destroy(fdt);
        close(fdt);
        int sent = 0;
        for (int i = 0; i < made; i++) {
            if (send(sp[i][0], buf, payload, MSG_DONTWAIT) >= 0) sent++;
        }
        long t2 = now_us();
        total_sent += sent;

        printf("round %2d: sent=%d  spray=%ldus\n", r, sent, t2 - t1);
        fflush(stdout);

        /* 清空接收队列，释放 skb */
        char tmp[4096];
        for (int i = 0; i < made; i++)
            while (recv(sp[i][1], tmp, sizeof(tmp), MSG_DONTWAIT) > 0) ;
        usleep(30000);
    }

    printf("=== done: total_sent=%d pid=%d ===\n", total_sent, getpid());
    fflush(stdout);
    return 0;
}