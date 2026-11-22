/*
 * msgspray: 用 SysV msg_msg 做 kmalloc-2k spray，可绑 CPU
 *
 * 用法: msgspray <count> <bodylen> [cpu]
 *   count   : 消息条数
 *   bodylen : 消息体长度（msg_msg 总分配 = 48 + bodylen，落 2048 需 bodylen<=2000）
 *   cpu     : 可选，绑定的 CPU 编号
 *
 * 输出：分配成功的条数 + msg_msg 实际占用的地址（由外部 trace 观测）
 *
 * 为什么用 msg_msg：
 *   - 内容完全可控（body 从 48 字节偏移开始）
 *   - 分配/释放节奏可控（msgsnd / msgrcv 显式驱动）
 *   - 走 load_msg -> kmalloc，落 kmalloc-2k
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#define MAXQ 512

struct msgbuf_s {
    long mtype;
    char mtext[4096];
};

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <count> <bodylen> [cpu]\n", argv[0]);
        return 2;
    }
    int count = atoi(argv[1]);
    int bodylen = atoi(argv[2]);
    if (bodylen <= 0 || bodylen > 4000) {
        fprintf(stderr, "bodylen out of range\n");
        return 2;
    }

    /* CPU 亲和 */
    if (argc > 3) {
        int cpu = atoi(argv[3]);
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) {
            fprintf(stderr, "sched_setaffinity(%d) failed: %s\n", cpu, strerror(errno));
        } else {
            printf("pinned to cpu%d\n", cpu);
        }
    }
    int cur = sched_getcpu();
    printf("running on cpu%d, pid=%d\n", cur, getpid());

    static struct msgbuf_s mb;
    mb.mtype = 1;
    /* 填充可识别 pattern：便于在堆里辨认 */
    for (int i = 0; i < bodylen; i++)
        mb.mtext[i] = (char)(0x41 + (i % 26));

    int nq = count < MAXQ ? count : MAXQ;
    int qids[MAXQ];
    int made = 0;
    for (int i = 0; i < nq; i++) {
        qids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (qids[i] < 0) {
            fprintf(stderr, "msgget[%d] failed: %s\n", i, strerror(errno));
            break;
        }
        made++;
    }
    printf("created %d queues\n", made);

    int sent = 0;
    for (int i = 0; i < count; i++) {
        int q = qids[i % made];
        if (msgsnd(q, &mb, bodylen, IPC_NOWAIT) != 0) {
            if (errno != EAGAIN)
                fprintf(stderr, "msgsnd[%d] failed: %s\n", i, strerror(errno));
            continue;
        }
        sent++;
    }
    printf("sent %d messages of bodylen=%d (total alloc ~= %d)\n",
           sent, bodylen, 48 + bodylen);
    printf("hold 1s then release\n");
    fflush(stdout);
    sleep(1);

    /* 释放：msgrcv 掉所有消息 */
    int got = 0;
    for (int i = 0; i < count; i++) {
        int q = qids[i % made];
        ssize_t r = msgrcv(q, &mb, bodylen, 0, IPC_NOWAIT);
        if (r >= 0) got++;
    }
    printf("received %d messages\n", got);

    for (int i = 0; i < made; i++)
        msgctl(qids[i], IPC_RMID, NULL);

    printf("done\n");
    return 0;
}