// smoke.bpf.c 로더 (libbpf 스켈레톤). 스파이크 코드 — 제품 로더는 Go(agent/internal/loader).

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>          // va_list — stdio.h 가 항상 주지는 않는다
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>         // bpf_map_lookup_elem 은 여기 있다. libbpf.h 가 아니다
#include "smoke.skel.h"

enum { ST_OPEN_TOTAL = 0, ST_OPEN_WRITE = 1, ST_FORK = 2, ST_MAX };

struct smoke_sample {
    unsigned long long cgroup_id, boot_ns, ino;
    unsigned int dev, pid;
    unsigned char write, _pad[7];
};

static volatile sig_atomic_t stop;
static void on_sig(int sig) { (void)sig; stop = 1; }

static int quiet_libbpf(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

int main(void)
{
    libbpf_set_print(quiet_libbpf);

    struct smoke_bpf *skel = smoke_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr,
            "\n로드 실패.\n"
            "  · 'Operation not permitted'  → sudo 로 실행할 것\n"
            "  · lsm/file_open 관련 에러     → cat /sys/kernel/security/lsm 에 bpf 가 있는지 확인\n"
            "     없으면: sudo ./deploy/enable-bpf-lsm.sh (재부팅 필요)\n");
        return 1;
    }
    if (smoke_bpf__attach(skel)) {
        fprintf(stderr, "attach 실패: %s\n", strerror(errno));
        smoke_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    printf("붙었다. LSM file_open + tp_btf sched_process_fork.\n");
    printf("Ctrl-C 로 종료. 다른 터미널에서 파일을 좀 만져보라.\n\n");

    int sfd = bpf_map__fd(skel->maps.stats);
    int lfd = bpf_map__fd(skel->maps.last);
    unsigned long long prev_open = 0;

    while (!stop) {
        sleep(1);

        unsigned long long v[ST_MAX] = {0};
        for (unsigned int k = 0; k < ST_MAX; k++)
            bpf_map_lookup_elem(sfd, &k, &v[k]);

        unsigned int z = 0;
        struct smoke_sample s = {0};
        bpf_map_lookup_elem(lfd, &z, &s);

        printf("open %-10llu (+%-6llu)  write %-8llu  fork %-6llu | "
               "cgroup=%llu pid=%u dev=%u:%u ino=%llu w=%u boot=%.1fs\n",
               v[ST_OPEN_TOTAL], v[ST_OPEN_TOTAL] - prev_open,
               v[ST_OPEN_WRITE], v[ST_FORK],
               s.cgroup_id, s.pid,
               s.dev >> 20, s.dev & 0xfffff, s.ino, s.write,
               s.boot_ns / 1e9);
        prev_open = v[ST_OPEN_TOTAL];
    }

    printf("\n종료. 프로그램을 떼어낸다.\n");
    smoke_bpf__destroy(skel);
    return 0;
}
