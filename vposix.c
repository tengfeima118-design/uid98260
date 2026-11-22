/* 独立验证：posix_timers_cache 的 free 是否进入 trace。
 * 完全不依赖 ExtractKit payload，避免它的 trace_stop() 干扰。
 *
 * 用法: ./vposix <N>
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

#define TR "/sys/kernel/tracing"

static int wr(const char *p, const char *v)
{
	int fd = open(p, O_WRONLY);
	int r;

	if (fd < 0)
		return -errno;
	r = (int)write(fd, v, strlen(v));
	close(fd);
	return r < 0 ? -errno : 0;
}

static void slab_posix(const char *tag)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char ln[512];

	if (!f) {
		printf("[%s] slabinfo unreadable errno=%d\n", tag, errno);
		return;
	}
	while (fgets(ln, sizeof(ln), f)) {
		if (!strncmp(ln, "posix_timers_cache", 18)) {
			printf("[%s] %s", tag, ln);
			break;
		}
	}
	fclose(f);
}

static int count_in(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char ln[2048];
	int n = 0;

	if (!f)
		return -1;
	while (fgets(ln, sizeof(ln), f))
		if (strstr(ln, needle))
			n++;
	fclose(f);
	return n;
}

static int read_int(const char *path)
{
	FILE *f = fopen(path, "r");
	int v = -1;

	if (f) {
		if (fscanf(f, "%d", &v) != 1)
			v = -1;
		fclose(f);
	}
	return v;
}

int main(int argc, char **argv)
{
	int N = argc > 1 ? atoi(argv[1]) : 3000;
	timer_t *ids;
	struct sigevent ev;
	int made = 0, i;
	size_t sz = 16u << 20;
	char *m;

	ids = calloc((size_t)N, sizeof(timer_t));
	if (!ids) {
		printf("calloc fail\n");
		return 1;
	}
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;

	printf("=== before ===\n");
	slab_posix("slab-pre");
	printf("[trace] tracing_on=%d rss_enable=%d\n",
	       read_int(TR "/tracing_on"),
	       read_int(TR "/events/kmem/rss_stat/enable"));

	printf("wr rss_enable = %d\n", wr(TR "/events/kmem/rss_stat/enable", "1"));
	printf("wr tracing_on = %d\n", wr(TR "/tracing_on", "1"));
	printf("wr clear      = %d\n", wr(TR "/trace", ""));

	/* 触发一次 rss 变化，让 trigger 里的 enable_event 真正执行 */
	m = malloc(sz);
	if (m) {
		for (size_t k = 0; k < sz; k += 4096)
			m[k] = 1;
		free(m);
	}
	usleep(200000);
	printf("[after rss] rss_enable=%d tracing_on=%d\n",
	       read_int(TR "/events/kmem/rss_stat/enable"),
	       read_int(TR "/tracing_on"));

	printf("=== create %d timers ===\n", N);
	for (i = 0; i < N; i++) {
		if (timer_create(CLOCK_MONOTONIC, &ev, &ids[i])) {
			printf("timer_create fail at %d errno=%d\n", i, errno);
			break;
		}
		made++;
	}
	printf("made=%d\n", made);
	slab_posix("slab-post-create");

	printf("=== delete all ===\n");
	for (i = 0; i < made; i++)
		timer_delete(ids[i]);
	printf("deleted\n");
	usleep(200000);
	slab_posix("slab-del-200ms");
	usleep(1600000);
	slab_posix("slab-del-1.8s");

	printf("=== trace 统计 ===\n");
	printf("kfree_lines = %d\n", count_in(TR "/trace", "kmem_cache_free"));
	printf("posix_lines = %d\n", count_in(TR "/trace", "posix_timers"));
	printf("entries     = %d (buffer lines)\n", count_in(TR "/trace", ":"));
	fflush(stdout);

	/* 打印前 3 条 posix 行 */
	{
		FILE *f = fopen(TR "/trace", "r");
		char ln[2048];
		int shown = 0;

		if (f) {
			while (fgets(ln, sizeof(ln), f) && shown < 3) {
				if (strstr(ln, "posix_timers")) {
					printf("[posix] %s", ln);
					shown++;
				}
			}
			fclose(f);
		}
		if (!shown)
			printf("[posix] 无记录\n");
	}
	/* 顺便打印前 3 条 free 行，确认事件在工作 */
	{
		FILE *f = fopen(TR "/trace", "r");
		char ln[2048];
		int shown = 0;

		if (f) {
			while (fgets(ln, sizeof(ln), f) && shown < 3) {
				if (strstr(ln, "kmem_cache_free")) {
					printf("[kfree] %s", ln);
					shown++;
				}
			}
			fclose(f);
		}
		if (!shown)
			printf("[kfree] 无记录\n");
	}
	free(ids);
	return 0;
}