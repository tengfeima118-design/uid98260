/*
 * uhid → wacom 绑定可达性探测（零风险：不触发 UAF）
 *
 * 目的：验证 CVE-2026-99491 的 L2 可达性最后一环
 *       —— 能否用 uhid 造出 wacom 驱动接受并 probe 的虚拟 HID 设备。
 *
 * 做法：
 *   1. 打开 /dev/uhid
 *   2. UHID_CREATE2 创建 bus=BUS_USB vendor=0x056a product=0x1101 的 touch 设备
 *      （与 woshigenm 在 5.15.178 成功时使用的参数一致）
 *   3. UHID_START 后持续 pump 事件
 *   4. 观察 /dev/input/ 是否新生 evdev 节点、/sys/bus/hid/devices 是否出现设备、
 *      /sys/bus/hid/drivers/wacom/ 是否挂上设备
 *   5. 打印结论后 UHID_DESTROY 清理
 *
 * 不发送任何能被 pad 上报的 input 事件，不触发 wacom_wac_pad_event，
 * 因而不涉及 UAF 路径。
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

#define WACOM_VID 0x056a
#define PHYS_COMMON "uhidpair/99"
#define NAME_TOUCH "wacom-pair-touch"

/* 最小 HID report descriptor：模拟 wacom touch 接口。
 * 关键是要让 hid-wacom 的 probe 走到 wacom_probe() 并创建 input 设备。
 * 这里用 woshigenm 在 5.15.178 上验证过的 touch 描述符形态（精简版）：
 * Generic Desktop / Digitizer，带 InRange + TipSwitch + X/Y + ContactCount。 */
static const unsigned char rdesc_touch[] = {
    0x05, 0x0d,                    /* Usage Page (Digitizers) */
    0x09, 0x04,                    /* Usage (Touch Screen) */
    0xa1, 0x01,                    /* Collection (Application) */
    0x85, 0x01,                    /*   Report ID (1) */
    0x09, 0x22,                    /*   Usage (Finger) */
    0xa1, 0x02,                    /*   Collection (Logical) */
    0x09, 0x42,                    /*     Usage (Tip Switch) */
    0x15, 0x00,                    /*     Logical Minimum (0) */
    0x25, 0x01,                    /*     Logical Maximum (1) */
    0x75, 0x01,                    /*     Report Size (1) */
    0x95, 0x01,                    /*     Report Count (1) */
    0x81, 0x02,                    /*     Input (Data,Var,Abs) */
    0x09, 0x32,                    /*     Usage (In Range) */
    0x81, 0x02,                    /*     Input (Data,Var,Abs) */
    0x95, 0x06,                    /*     Report Count (6) */
    0x81, 0x03,                    /*     Input (Const,Var,Abs) */
    0x75, 0x10,                    /*     Report Size (16) */
    0x95, 0x01,                    /*     Report Count (1) */
    0x09, 0x30,                    /*     Usage (Tip Pressure) */
    0x26, 0xff, 0x0f,              /*     Logical Maximum (4095) */
    0x81, 0x02,                    /*     Input (Data,Var,Abs) */
    0x05, 0x01,                    /*     Usage Page (Generic Desktop) */
    0x09, 0x30,                    /*     Usage (X) */
    0x09, 0x31,                    /*     Usage (Y) */
    0x16, 0x00, 0x00,              /*     Logical Minimum (0) */
    0x26, 0xff, 0x7f,              /*     Logical Maximum (32767) */
    0x36, 0x00, 0x00,              /*     Physical Minimum (0) */
    0x46, 0xff, 0x7f,              /*     Physical Maximum (32767) */
    0x75, 0x10,                    /*     Report Size (16) */
    0x95, 0x02,                    /*     Report Count (2) */
    0x81, 0x02,                    /*     Input (Data,Var,Abs) */
    0x05, 0x0d,                    /*     Usage Page (Digitizers) */
    0x09, 0x48,                    /*     Usage (Contact Count) */
    0x75, 0x08,                    /*     Report Size (8) */
    0x95, 0x01,                    /*     Report Count (1) */
    0x15, 0x00,                    /*     Logical Minimum (0) */
    0x25, 0x0a,                    /*     Logical Maximum (10) */
    0x81, 0x02,                    /*     Input (Data,Var,Abs) */
    0xc0,                          /*   End Collection */
    0xc0,                          /* End Collection */
};

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int list_dir(const char *path, char *out, size_t outsz) {
    DIR *d = opendir(path);
    struct dirent *de;
    size_t used = 0;
    out[0] = 0;
    if (!d) return -1;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        int n = snprintf(out + used, outsz - used, "%s ", de->d_name);
        if (n < 0 || (size_t)n >= outsz - used) break;
        used += n;
    }
    closedir(d);
    return 0;
}

static int count_evdev(void) {
    DIR *d = opendir("/dev/input");
    struct dirent *de;
    int n = 0;
    if (!d) return -1;
    while ((de = readdir(d))) {
        if (!strncmp(de->d_name, "event", 5)) n++;
    }
    closedir(d);
    return n;
}

static int uhid_open(void) {
    int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (fd < 0) fprintf(stderr, "[-] open /dev/uhid: %s\n", strerror(errno));
    return fd;
}

static int uhid_create(int fd, const char *name, const char *phys,
                       unsigned pid, const unsigned char *rdesc, size_t rlen,
                       unsigned short bus) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    strncpy((char *)ev.u.create2.name, name, sizeof(ev.u.create2.name) - 1);
    if (phys) strncpy((char *)ev.u.create2.phys, phys, sizeof(ev.u.create2.phys) - 1);
    strncpy((char *)ev.u.create2.uniq, name, sizeof(ev.u.create2.uniq) - 1);
    memcpy(ev.u.create2.rd_data, rdesc, rlen);
    ev.u.create2.rd_size = rlen;
    ev.u.create2.bus = bus;
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    if (write(fd, &ev, sizeof(ev)) < 0) {
        fprintf(stderr, "[-] UHID_CREATE2: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* 读 uhid 事件并回应 START/OPEN，避免内核等待 */
static void pump(int fd, long until_ms) {
    struct uhid_event ev;
    while (now_ms() < until_ms) {
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n > 0) {
            if (ev.type == UHID_START || ev.type == UHID_OPEN) {
                fprintf(stderr, "[*] uhid event type=%u\n", ev.type);
            }
        } else {
            usleep(20000);
        }
    }
}

int main(int argc, char **argv) {
    unsigned short bus = BUS_USB;
    unsigned pid = 0x1101;
    long wait_ms = 4000;

    if (argc > 1) bus = (unsigned short)strtoul(argv[1], NULL, 0);
    if (argc > 2) pid = (unsigned)strtoul(argv[2], NULL, 0);
    if (argc > 3) wait_ms = strtol(argv[3], NULL, 0);

    printf("=== uhid->wacom 绑定探测 ===\n");
    printf("bus=0x%02x vendor=0x%04x product=0x%04x phys=%s wait=%ldms\n",
           bus, WACOM_VID, pid, PHYS_COMMON, wait_ms);

    int ev0 = count_evdev();
    char d0[2048], w0[1024];
    list_dir("/sys/bus/hid/devices", d0, sizeof(d0));
    list_dir("/sys/bus/hid/drivers/wacom", w0, sizeof(w0));
    printf("[before] evdev count=%d\n", ev0);
    printf("[before] hid devices: %s\n", d0[0] ? d0 : "(none)");
    printf("[before] wacom driver dir: %s\n", w0[0] ? w0 : "(empty)");

    int fd = uhid_open();
    if (fd < 0) return 2;

    if (uhid_create(fd, NAME_TOUCH, PHYS_COMMON, pid, rdesc_touch,
                    sizeof(rdesc_touch), bus) < 0) {
        close(fd);
        return 3;
    }
    printf("[+] UHID_CREATE2 sent\n");

    pump(fd, now_ms() + wait_ms);

    int ev1 = count_evdev();
    char d1[4096], w1[2048];
    list_dir("/sys/bus/hid/devices", d1, sizeof(d1));
    list_dir("/sys/bus/hid/drivers/wacom", w1, sizeof(w1));
    printf("[after ] evdev count=%d (delta %+d)\n", ev1, ev1 - ev0);
    printf("[after ] hid devices: %s\n", d1[0] ? d1 : "(none)");
    printf("[after ] wacom driver dir: %s\n", w1[0] ? w1 : "(empty)");

    /* 判定 */
    printf("\n=== VERDICT ===\n");
    int bound = 0;
    /* /sys/bus/hid/drivers/wacom/ 下若出现 0003:056A:xxxx.xxxx 形式即为已绑定 */
    if (strstr(w1, "0003:056A") || strstr(w1, "0003:056a")) bound = 1;
    if (bound) {
        printf("BOUND: wacom 驱动已接受该 uhid 设备（bus=0x%02x product=0x%04x）\n", bus, pid);
    } else if (ev1 > ev0) {
        printf("PROBED_OTHER: 有新 evdev 节点，但不是 wacom 绑定（被 hid-generic 或其它驱动接管）\n");
    } else if (strstr(d1, "0003:056A") || strstr(d1, "0003:056a")) {
        printf("DEVICE_ONLY: HID 设备已创建但无驱动绑定、无 evdev\n");
    } else {
        printf("NOT_BOUND: 未见 HID 设备（可能被拒绝或 bus 不匹配）\n");
    }

    /* 清理 */
    {
        struct uhid_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.type = UHID_DESTROY;
        write(fd, &ev, sizeof(ev));
    }
    close(fd);
    printf("[+] destroyed\n");
    return bound ? 0 : (ev1 > ev0 ? 10 : 11);
}