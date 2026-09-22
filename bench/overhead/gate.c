// S1 로더 — gate.bpf.o 를 열어 붙이고, SIGINT 에 통계를 JSON 으로 뱉는다.
//
//   sudo ./gate --obj gate_c.bpf.o [--tag-cgroup N] [--watch PATH]... [--out stats.json]
//
// 스켈레톤을 안 쓴다. 티어 × PROBE 조합의 오브젝트 여럿을 바이너리 하나가
// 다뤄야 하는데, 스켈레톤은 오브젝트마다 헤더가 생겨서 전부 링크하게 된다.

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define OH_CNT_MAX 8
#define OH_WATCH_MAX 64
#define OH_LAT_MAX 64
#define OH_DEV_MAX 8192

// gate.bpf.c 의 OH_R_* 순서와 같아야 한다. 마지막 칸이 총계다.
static const char *cnt_name[OH_CNT_MAX] = {
    "pass", "read", "tag_miss", "tag_hit", "revoked", "expired", "watch_hit", "total"
};

struct oh_ino_key {
    __u32 dev;
    __u32 _pad;
    __u64 ino;
};

struct oh_warrant {
    __u64 expires_ns;
    __u8  revoked;
    __u8  _pad[7];
};

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int quiet_libbpf(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

static int ncpu;

static __u64 sum_percpu(int fd, __u32 key)
{
    __u64 vals[1024];
    if (ncpu > (int)(sizeof(vals) / sizeof(vals[0])))
        return 0;
    memset(vals, 0, sizeof(__u64) * ncpu);
    if (bpf_map_lookup_elem(fd, &key, vals))
        return 0;
    __u64 t = 0;
    for (int i = 0; i < ncpu; i++)
        t += vals[i];
    return t;
}

static int map_fd(struct bpf_object *obj, const char *name)
{
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    return m ? bpf_map__fd(m) : -1;
}

static void dump(struct bpf_object *obj, FILE *f, const char *objpath, double secs)
{
    fprintf(f, "{\n  \"object\": \"%s\",\n  \"seconds\": %.3f,\n", objpath, secs);

    int fd = map_fd(obj, "oh_counters");
    fprintf(f, "  \"counters\": {");
    for (int i = 0; i < OH_CNT_MAX; i++)
        fprintf(f, "%s\n    \"%s\": %llu", i ? "," : "", cnt_name[i],
                fd < 0 ? 0ULL : (unsigned long long)sum_percpu(fd, i));
    fprintf(f, "\n  },\n");

    // 지연 히스토그램 — log2(ns) 버킷. p99 는 report.py 가 여기서 뽑는다.
    fd = map_fd(obj, "oh_lat");
    fprintf(f, "  \"lat_log2_ns\": {");
    int first = 1;
    for (int i = 0; i < OH_LAT_MAX; i++) {
        __u64 v = fd < 0 ? 0 : sum_percpu(fd, i);
        if (!v) continue;
        fprintf(f, "%s\n    \"%d\": %llu", first ? "" : ",", i, (unsigned long long)v);
        first = 0;
    }
    fprintf(f, "\n  },\n");

    // dev major × 읽기/쓰기
    fd = map_fd(obj, "oh_dev");
    fprintf(f, "  \"dev_major\": {");
    first = 1;
    for (int mj = 0; mj < OH_DEV_MAX / 2; mj++) {
        __u64 r = fd < 0 ? 0 : sum_percpu(fd, mj * 2);
        __u64 w = fd < 0 ? 0 : sum_percpu(fd, mj * 2 + 1);
        if (!r && !w) continue;
        fprintf(f, "%s\n    \"%d\": {\"read\": %llu, \"write\": %llu}",
                first ? "" : ",", mj, (unsigned long long)r, (unsigned long long)w);
        first = 0;
    }
    fprintf(f, "\n  }\n}\n");
}

int main(int argc, char **argv)
{
    const char *objpath = NULL, *outpath = NULL;
    unsigned long long tag_cgroup = 0;
    unsigned ttl_sec = 3600;
    const char *watch[OH_WATCH_MAX];
    int nwatch = 0;

    static struct option opts[] = {
        {"obj",        required_argument, 0, 'o'},
        {"out",        required_argument, 0, 'w'},
        {"tag-cgroup", required_argument, 0, 'c'},
        {"ttl",        required_argument, 0, 't'},
        {"watch",      required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "o:w:c:t:r:", opts, NULL)) != -1) {
        switch (c) {
        case 'o': objpath = optarg; break;
        case 'w': outpath = optarg; break;
        case 'c': tag_cgroup = strtoull(optarg, NULL, 10); break;
        case 't': ttl_sec = strtoul(optarg, NULL, 10); break;
        case 'r':
            if (nwatch < OH_WATCH_MAX)
                watch[nwatch++] = optarg;
            break;
        default:
            fprintf(stderr, "usage: %s --obj X.bpf.o [--tag-cgroup N] [--ttl S] "
                            "[--watch PATH]... [--out F]\n", argv[0]);
            return 2;
        }
    }
    if (!objpath) {
        fprintf(stderr, "ERROR: --obj 가 필요하다\n");
        return 2;
    }

    libbpf_set_print(quiet_libbpf);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) {
        fprintf(stderr, "ERROR: libbpf_num_possible_cpus: %d\n", ncpu);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: open %s: %s\n", objpath, strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: load %s: %s\n", objpath, strerror(errno));
        fprintf(stderr, "       lsm/ 프로그램이면 /sys/kernel/security/lsm 에 bpf 가 있는지 확인:\n");
        fprintf(stderr, "       cat /sys/kernel/security/lsm   (없으면 sudo ./deploy/enable-bpf-lsm.sh)\n");
        return 1;
    }

    // 태그를 심는다. 안 심으면 티어 D 가 전부 tag_miss 로 빠져서
    // 해시 조회 두 번 중 한 번만 재고는 "D 가 싸다"는 틀린 답이 나온다.
    if (tag_cgroup) {
        int tfd = map_fd(obj, "oh_tag"), wfd = map_fd(obj, "oh_warrants");
        __u64 wid = 1;
        struct oh_warrant w = { .expires_ns = 0, .revoked = 0 };

        FILE *up = fopen("/proc/uptime", "r");
        double upt = 0;
        if (up) { if (fscanf(up, "%lf", &upt) != 1) upt = 0; fclose(up); }
        w.expires_ns = (__u64)((upt + ttl_sec) * 1e9);

        if (tfd < 0 || wfd < 0 ||
            bpf_map_update_elem(tfd, &tag_cgroup, &wid, BPF_ANY) ||
            bpf_map_update_elem(wfd, &wid, &w, BPF_ANY)) {
            fprintf(stderr, "ERROR: 태그 주입 실패 (cgroup=%llu)\n", tag_cgroup);
            return 1;
        }
        fprintf(stderr, "tag: cgroup=%llu -> warrant=1, expires=+%us\n", tag_cgroup, ttl_sec);
    } else {
        fprintf(stderr, "tag: 없음 — 티어 D 는 tag_miss 경로만 잰다\n");
    }

    // 읽기 감시 목록 (티어 R · I). 다른 티어에는 oh_watch 맵이 없으니 조용히 넘어간다.
    int watch_fd = map_fd(obj, "oh_watch");
    if (watch_fd >= 0) {
        int added = 0;
        for (int i = 0; i < nwatch; i++) {
            struct stat st;
            if (stat(watch[i], &st)) {
                fprintf(stderr, "watch: %s 없음 — 건너뛴다\n", watch[i]);
                continue;
            }
            // st_dev 는 유저 공간 인코딩이다. 커널 s_dev 는 (major << 20) | minor.
            // 그대로 넣으면 조용히 전건 miss 가 나고 "I 가 싸다"는 틀린 답이 된다.
            struct oh_ino_key k = {
                .dev = (__u32)((major(st.st_dev) << 20) | minor(st.st_dev)),
                .ino = st.st_ino,
            };
            __u8 one = 1;
            if (bpf_map_update_elem(watch_fd, &k, &one, BPF_ANY)) {
                fprintf(stderr, "ERROR: watch 주입 실패 (%s)\n", watch[i]);
                return 1;
            }
            added++;
        }
        fprintf(stderr, "watch: %d / %d 경로\n", added, nwatch);
    }

    struct bpf_program *prog;
    int n = 0;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            fprintf(stderr, "ERROR: attach %s: %s\n",
                    bpf_program__name(prog), strerror(errno));
            return 1;
        }
        n++;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    // run.sh 가 이 줄을 기다린다. 이게 나오기 전에 워크로드를 돌리면
    // 훅이 안 붙은 구간이 측정에 섞인다.
    printf("READY %s progs=%d\n", objpath, n);
    fflush(stdout);

    while (!stop)
        pause();

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    FILE *f = stdout;
    if (outpath && !(f = fopen(outpath, "w"))) {
        fprintf(stderr, "ERROR: out %s\n", outpath);
        return 1;
    }
    dump(obj, f, objpath, secs);
    if (f != stdout)
        fclose(f);
    return 0;
}
