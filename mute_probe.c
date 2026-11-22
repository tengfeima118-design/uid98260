/*
 * 99491 MUTE 转发专项测试：试多种 report 值，找出哪种能触发 shared->touch_input 转发
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

int main(void) {
    printf("=== 99491 MUTE 转发专项测试 ===\n");
    char d0[MAXEV][16];
    int n0 = list_events(d0);

    int fdt = uhid_open(), fdp = uhid_open();
    if (fdt < 0 || fdp < 0) { printf("open uhid fail\n"); return 2; }

    uhid_create(fdt, "t-touch", PHYS_COMMON, 0x1101, rdesc_touch, sizeof(rdesc_touch));
    pump(fdt, 600);
    uhid_create(fdp, "t-pad", PHYS_COMMON, 0x1102, rdesc_pad, sizeof(rdesc_pad));
    pump(fdp, 600);
    usleep(1500000);

    /* 收集新增节点 */
    char cur[MAXEV][16];
    int n = list_events(cur);
    int fd_touch = -1, fd_pad = -1;
    printf("[nodes]\n");
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
        if (strstr(nm, "Finger") || strstr(nm, "touch")) { fd_touch = fd; }
        else if (strstr(nm, "Pad")) { fd_pad = fd; }
        else close(fd);
    }
    printf("touch_fd=%d pad_fd=%d\n", fd_touch, fd_pad);

    /* 对每个候选 report 值试一遍 */
    struct { unsigned char id, v; const char *desc; } trials[] = {
        {0x02, 0x01, "MUTE=1 (bit0)"},
        {0x02, 0x02, "MUTE=2 (bit1)"},
        {0x02, 0x00, "MUTE=0"},
        {0x02, 0x03, "MUTE=3 (bit0+1)"},
        {0x02, 0x01, "MUTE=1 again"},
    };
    int ntr = sizeof(trials) / sizeof(trials[0]);
    for (int t = 0; t < ntr; t++) {
        if (fd_touch >= 0) { struct input_event e; while (read(fd_touch, &e, sizeof(e)) == sizeof(e)); }
        if (fd_pad >= 0) { struct input_event e; while (read(fd_pad, &e, sizeof(e)) == sizeof(e)); }
        unsigned char rep[2] = { trials[t].id, trials[t].v };
        uhid_input(fdp, rep, 2);
        pump(fdp, 250);
        pump(fdt, 250);
        int ct = 0;
        long dl = now_ms() + 400;
        while (now_ms() < dl) {
            struct input_event e;
            if (fd_touch >= 0) while (read(fd_touch, &e, sizeof(e)) == sizeof(e)) {
                ct++;
                printf("    [touch] type=0x%x code=0x%x value=%d\n", e.type, e.code, e.value);
            }
            if (fd_pad >= 0) while (read(fd_pad, &e, sizeof(e)) == sizeof(e))
                printf("    [pad]   type=0x%x code=0x%x value=%d\n", e.type, e.code, e.value);
            usleep(10000);
        }
        printf("  trial[%d] %-20s -> touch 事件数=%d\n", t, trials[t].desc, ct);
    }

    if (fd_touch >= 0) close(fd_touch);
    if (fd_pad >= 0) close(fd_pad);
    struct uhid_event ev; memset(&ev, 0, sizeof(ev)); ev.type = UHID_DESTROY;
    write(fdp, &ev, sizeof(ev)); write(fdt, &ev, sizeof(ev));
    close(fdp); close(fdt);
    printf("[done]\n");
    return 0;
}