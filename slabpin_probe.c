/*
 * slabpin_probe: 直接验证「哪个载体真正进 kmalloc-2k（非 cg 池）」
 *
 * 本程序做 4 组对照，每组独立测量 /proc/slabinfo 的 kmalloc-2k active 变化：
 *   G1 unix_dgram sendmsg  (GFP_KERNEL_ACCOUNT 路径)
 *   G2 pipe buffer 写入     (GFP_KERNEL 路径, kernel pipe page 不走 kmalloc)
 *   G3 只读基线
 *
 * 用法: slabpin_probe <mode> <count> <size>
 *   mode: dgram | pipe | base
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>

static long slab_active(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512];
    long a = -1;
    size_t nl = strlen(name);
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, nl) == 0 && line[nl] == ' ') {
            char nm[64];
            long act, num, osz;
            if (sscanf(line, "%63s %ld %ld %ld", nm, &act, &num, &osz) == 4) {
                a = act;
            }
            break;
        }
    }
    fclose(f);
    return a;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "base";
    int count = argc > 2 ? atoi(argv[2]) : 300;
    int size = argc > 3 ? atoi(argv[3]) : 1728;

    long a0 = slab_active("kmalloc-2k");
    printf("mode=%-6s count=%d size=%d  base active=%ld\n", mode, count, size, a0);

    if (!strcmp(mode, "dgram")) {
        char *buf = malloc(size);
        memset(buf, 0x42, size);
        int (*sp)[2] = calloc(count, sizeof(int[2]));
        int made = 0;
        for (int i = 0; i < count; i++) {
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp[i]) < 0) break;
            int sb = 4 << 20;
            setsockopt(sp[i][0], SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
            setsockopt(sp[i][1], SOL_SOCKET, SO_RCVBUF, &sb, sizeof(sb));
            made++;
        }
        int sent = 0;
        for (int i = 0; i < made; i++)
            if (send(sp[i][0], buf, size, MSG_DONTWAIT) >= 0) sent++;
        long a1 = slab_active("kmalloc-2k");
        printf("  made=%d sent=%d  during active=%ld  delta=%+ld\n", made, sent, a1, a1 - a0);
        printf("  (每条约 %ld B 分配；若 delta≈sent 说明进同一个 kmalloc-2k)\n", (long)size);
        char tmp[4096];
        for (int i = 0; i < made; i++)
            while (recv(sp[i][1], tmp, sizeof(tmp), MSG_DONTWAIT) > 0) ;
        long a2 = slab_active("kmalloc-2k");
        printf("  after active=%ld  delta=%+ld\n", a2, a2 - a0);
    } else if (!strcmp(mode, "pipe")) {
        int n = count < 64 ? count : 64;
        int (*pp)[2] = calloc(n, sizeof(int[2]));
        char *buf = malloc(size);
        memset(buf, 0x43, size);
        int made = 0;
        for (int i = 0; i < n; i++) {
            if (pipe(pp[i]) < 0) break;
            fcntl(pp[i][1], F_SETFL, O_NONBLOCK);
            made++;
        }
        int w = 0;
        for (int i = 0; i < made; i++)
            for (int k = 0; k < 8; k++)
                if (write(pp[i][1], buf, size) > 0) w++;
        long a1 = slab_active("kmalloc-2k");
        printf("  pipes=%d writes=%d  during active=%ld  delta=%+ld\n", made, w, a1, a1 - a0);
    } else {
        sleep(1);
        long a1 = slab_active("kmalloc-2k");
        printf("  idle active=%ld  delta=%+ld\n", a1, a1 - a0);
    }
    return 0;
}