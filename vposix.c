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
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

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
	char ln[1024];
	int n = 0;

	if (!f)
		return -1;
	while (fgets(ln, sizeof(ln), f))
		if (strstr(ln, needle))
			n++;
	fclose(f);
	return n;
}

int main(int argc, char **argv)
{
	const char *TR = "/sys/kernel/tracing";
	int N = argc > 1 ? atoi(argv[1]) : 3000;
	timer_t *ids = calloc(N, sizeof(timer_t));
	struct sigevent ev;
	int made = 0, i;
	char p[256];

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;

	printf("=== before ===\n");
	slab_posix("slab-pre");
	printf("[trace] tracing_on=%d rss_enable=%d\n",
	       count_in(TR "/tracing_on", "1") >= 0 ? -2 : -3, -3);

	/* 读状态 */
	{
		FILE *f = fopen(TR "/tracing_on", "r");
		int v = -1;

		if (f) {
			if (fscanf(f, "%d", &v) != 1)
				v = -1;
			fclose(f);
		}
		printf("[trace] tracing_on=%d\n", v);
	}

	/* 打开 holder 和 tracing（顺序：先 holder 再 tracing） */
	printf("wr rss_stat/enable = %d\n", wr(TR "/events/kmem/rss_stat/enable", "1"));
	printf("wr tracing_on      = %d\n", wr(TR "/tracing_on", "1"));
	printf("wr trace(clear)    = %d\n", wr(TR "/trace", ""));

	/* 触发一次 rss 变化，让 trigger 里的 enable_event 真正执行 */
	{
		size_t sz = 16u << 20;
		char *m = malloc(sz);

		if (m) {
			for (size_t k = 0; k < sz; k += 4096)
				m[k] = 1;
			free(m);
		}
	}
	usleep(200000);

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
	slab_posix("slab-post-del-200ms");
	usleep(1600000);
	slab_posix("slab-post-del-1.8s");

	printf("=== trace 统计 ===\n");
	printf("kfree lines  = %d\n", count_in(TR "/trace", "kmem_cache_free"));
	printf("posix lines  = %d\n", count_in(TR "/trace", "posix_timers"));
	printf("entries      = ");
	fflush(stdout);
	snprintf(p, sizeof(p), "grep -m1 entries-in-buffer %s/trace", TR);
	{
		FILE *f = popen(p, "r");
		char b[256];

		if (f) {
			if (fgets(b, sizeof(b), f))
				printf("%s", b);
			pclose(f);
		}
	}
	return 0;
}