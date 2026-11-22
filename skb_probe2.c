/*
 * skb 回收能力探测 v2（修正 slabinfo 解析）
 *
 * slabinfo 格式（version 2.1）：
 *   name active_objs num_objs objsize objperslab pagesperslab : tunables limit batch shared : slabdata active_slabs num_slabs sharedavail
 *   字段: $1     $2         $3      $4      $5        $6            $8    $9    $10     $12      $13        $14        $15
 *
 * 正确解析：active=$2, num=$3, objsize=$4, active_slabs=$14, num_slabs=$15
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

struct slab { unsigned long active, num, objsize, aslabs, nslabs; };

static int read_slab(const char *name, struct slab *s) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512];
    size_t nl = strlen(name);
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, nl) == 0 && line[nl] == ' ') {
            /* 逐字段解析，避免 sscanf 跳过 tunables 出错 */
            char *p = line;
            char field[64];
            int idx = 0;
            unsigned long v[20];
            int nv = 0;
            while (*p && nv < 20) {
                while (*p == ' ') p++;
                if (*p == ':' || *p == '\n' || *p == 0) {
                    /* 跳过 tunables/slabdata 段的标记 */
                    while (*p && *p != ' ') p++;
                    continue;
                }
                int k = 0;
                while (*p && *p != ' ' && *p != '\n' && k < 63) field[k++] = *p++;
                field[k] = 0;
                if (idx == 0) { idx++; continue; }  /* name */
                v[nv++] = strtoul(field, NULL, 10);
                idx++;
            }
            /* v[0]=active v[1]=num_objs v[2]=objsize v[3]=objperslab v[4]=pagesperslab
               v[5]=limit v[6]=batch v[7]=shared v[8]=active_slabs v[9]=num_slabs v[10]=sharedavail */
            if (nv >= 10) {
                s->active = v[0];
                s->num = v[1];
                s->objsize = v[2];
                s->aslabs = v[8];
                s->nslabs = v[9];
                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1;
}

static void show(const char *tag, struct slab *s) {
    printf("  %-10s active=%-7lu num=%-7lu objsize=%-5lu slabs=%lu/%lu\n",
           tag, s->active, s->num, s->objsize, s->aslabs, s->nslabs);
}

int main(int argc, char **argv) {
    int npair = argc > 1 ? atoi(argv[1]) : 300;
    int persend = argc > 2 ? atoi(argv[2]) : 6;
    int payload = argc > 3 ? atoi(argv[3]) : 1400;

    printf("=== skb 回收探测 v2 ===\n");
    printf("npair=%d persend=%d payload=%d\n\n", npair, persend, payload);

    struct slab base, d1, d2, after;
    if (read_slab("kmalloc-2k", &base) < 0) { printf("slabinfo 读失败\n"); return 2; }
    printf("=== 基线 ===\n");
    show("base", &base);

    char *buf = malloc(payload);
    memset(buf, 'B', payload);

    int (*p1)[2] = calloc(npair, sizeof(int[2]));
    int (*p2)[2] = calloc(npair, sizeof(int[2]));
    if (!p1 || !p2) return 3;

    /* 第一轮 */
    int ok1 = 0;
    for (int i = 0; i < npair; i++) {
        p1[i][0] = p1[i][1] = -1;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, p1[i]) < 0) continue;
        int sb = 1 << 20;
        setsockopt(p1[i][0], SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
        setsockopt(p1[i][1], SOL_SOCKET, SO_RCVBUF, &sb, sizeof(sb));
        for (int j = 0; j < persend; j++)
            if (send(p1[i][0], buf, payload, MSG_DONTWAIT) < 0) break;
        ok1++;
    }
    usleep(500000);
    read_slab("kmalloc-2k", &d1);
    printf("\n第一轮 %d 对\n", ok1);
    show("during1", &d1);
    printf("  delta active=%+ld num=%+ld\n",
           (long)d1.active - (long)base.active, (long)d1.num - (long)base.num);

    /* 第二轮 */
    int ok2 = 0;
    for (int i = 0; i < npair; i++) {
        p2[i][0] = p2[i][1] = -1;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, p2[i]) < 0) continue;
        int sb = 1 << 20;
        setsockopt(p2[i][0], SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
        setsockopt(p2[i][1], SOL_SOCKET, SO_RCVBUF, &sb, sizeof(sb));
        for (int j = 0; j < persend; j++)
            if (send(p2[i][0], buf, payload, MSG_DONTWAIT) < 0) break;
        ok2++;
    }
    usleep(500000);
    read_slab("kmalloc-2k", &d2);
    printf("\n第二轮 %d 对\n", ok2);
    show("during2", &d2);
    printf("  delta active=%+ld num=%+ld\n",
           (long)d2.active - (long)base.active, (long)d2.num - (long)base.num);

    /* 释放 */
    for (int i = 0; i < npair; i++) {
        if (p1[i][0] >= 0) { close(p1[i][0]); close(p1[i][1]); }
        if (p2[i][0] >= 0) { close(p2[i][0]); close(p2[i][1]); }
    }
    free(p1); free(p2);
    usleep(1000000);
    read_slab("kmalloc-2k", &after);
    printf("\n释放后\n");
    show("after", &after);
    printf("  delta active=%+ld num=%+ld\n",
           (long)after.active - (long)base.active, (long)after.num - (long)base.num);

    printf("\n=== 结论 ===\n");
    long grow1 = (long)d1.active - (long)base.active;
    long grow2 = (long)d2.active - (long)base.active;
    long best = grow1 > grow2 ? grow1 : grow2;
    printf("  最大 active 增量 = %+ld\n", best);
    if (best > 100) {
        printf("  PASS: skb 占用 kmalloc-2k\n");
        printf("  => 回收 input_dev 槽位技术可行\n");
    } else if (best > 0) {
        printf("  PARTIAL: 增量 %+ld，需调参\n", best);
    } else {
        printf("  FAIL: 无增长\n");
    }
    free(buf);
    return 0;
}