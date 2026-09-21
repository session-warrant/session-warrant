// S2 로더 — 태그 두 겹을 붙이고, pid 로 조회할 수 있게 bpffs 에 pin 한다.
//
//   sudo ./tagprobe daemon --tag-cgroup <id>   붙이고 pin 하고 대기
//   sudo ./tagprobe tag <cgroup-id>            추가 cgroup 태그 주입
//   sudo ./tagprobe query <pid>                한 줄로 결과 출력
//   sudo ./tagprobe dump                       기록된 전부
//
// 맵을 pin 하는 이유는 bats 케이스가 별도 프로세스이기 때문이다.

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PIN_DIR "/sys/fs/bpf/warrant_bypass"
#define OBJ     "tagprobe.bpf.o"

struct wb_rec {
    __u64 cgroup_id;
    __u64 warrant_cg;
    __u64 warrant_task;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 _pad;
    __u8  comm[16];
};

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int quiet(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

static int pinned_fd(const char *name)
{
    char p[256];
    snprintf(p, sizeof(p), PIN_DIR "/%s", name);
    int fd = bpf_obj_get(p);
    if (fd < 0)
        fprintf(stderr, "ERROR: %s 를 열 수 없다 — daemon 이 안 떠 있다\n", p);
    return fd;
}

// wb_rec 한 건을 bats 가 파싱하기 쉬운 key=value 로 찍는다.
static void print_rec(const struct wb_rec *r)
{
    printf("pid=%u ppid=%u uid=%u comm=%s cgroup=%llu cg_tag=%llu task_tag=%llu"
           " via=%s%s tagged=%s\n",
           r->pid, r->ppid, r->uid, (const char *)r->comm,
           (unsigned long long)r->cgroup_id,
           (unsigned long long)r->warrant_cg,
           (unsigned long long)r->warrant_task,
           r->warrant_cg ? "cgroup" : "-",
           r->warrant_task ? "+task" : "",
           (r->warrant_cg || r->warrant_task) ? "yes" : "no");
}

static int cmd_query(int argc, char **argv)
{
    if (argc < 1) { fprintf(stderr, "usage: tagprobe query <pid>\n"); return 2; }
    __u32 pid = strtoul(argv[0], NULL, 10);
    int fd = pinned_fd("wb_pid_tag");
    if (fd < 0) return 1;
    struct wb_rec r;
    if (bpf_map_lookup_elem(fd, &pid, &r)) {
        // exec 을 한 번도 안 한 프로세스는 기록이 없다.
        printf("pid=%u tagged=unknown\n", pid);
        return 3;
    }
    print_rec(&r);
    return 0;
}

static int cmd_dump(void)
{
    int fd = pinned_fd("wb_pid_tag");
    if (fd < 0) return 1;
    __u32 k = 0, next;
    struct wb_rec r;
    int n = 0;
    while (!bpf_map_get_next_key(fd, n ? &k : NULL, &next)) {
        k = next; n++;
        if (!bpf_map_lookup_elem(fd, &k, &r))
            print_rec(&r);
    }
    return 0;
}

static int cmd_tag(int argc, char **argv)
{
    if (argc < 1) { fprintf(stderr, "usage: tagprobe tag <cgroup-id>\n"); return 2; }
    __u64 cg = strtoull(argv[0], NULL, 10), wid = 1;
    int fd = pinned_fd("wb_cg_tag");
    if (fd < 0) return 1;
    if (bpf_map_update_elem(fd, &cg, &wid, BPF_ANY)) {
        fprintf(stderr, "ERROR: 태그 주입 실패\n");
        return 1;
    }
    printf("tagged cgroup=%llu warrant=1\n", (unsigned long long)cg);
    return 0;
}

static int cmd_daemon(int argc, char **argv)
{
    __u64 tag_cg = 0;
    for (int i = 0; i < argc - 1; i++)
        if (!strcmp(argv[i], "--tag-cgroup"))
            tag_cg = strtoull(argv[i + 1], NULL, 10);

    libbpf_set_print(quiet);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    struct bpf_object *obj = bpf_object__open_file(OBJ, NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: %s 를 열 수 없다: %s\n", OBJ, strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: load: %s\n", strerror(errno));
        fprintf(stderr, "       cat /sys/kernel/security/lsm 에 bpf 가 있는지 확인.\n");
        return 1;
    }

    // 이전 실행이 남긴 pin 을 먼저 치운다. 남아 있으면 bpf_object__pin 이 EEXIST.
    mkdir("/sys/fs/bpf", 0700);
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj) {
        char p[256];
        snprintf(p, sizeof(p), PIN_DIR "/%s", bpf_map__name(m));
        unlink(p);
    }
    rmdir(PIN_DIR);
    if (mkdir(PIN_DIR, 0700) && errno != EEXIST) {
        fprintf(stderr, "ERROR: %s 생성 실패 — bpffs 가 마운트돼 있나?\n", PIN_DIR);
        return 1;
    }
    bpf_object__for_each_map(m, obj) {
        char p[256];
        snprintf(p, sizeof(p), PIN_DIR "/%s", bpf_map__name(m));
        if (bpf_map__pin(m, p)) {
            fprintf(stderr, "ERROR: pin %s: %s\n", p, strerror(errno));
            return 1;
        }
    }

    if (tag_cg) {
        __u64 wid = 1;
        struct bpf_map *cgm = bpf_object__find_map_by_name(obj, "wb_cg_tag");
        if (!cgm || bpf_map_update_elem(bpf_map__fd(cgm), &tag_cg, &wid, BPF_ANY)) {
            fprintf(stderr, "ERROR: 태그 주입 실패 (cgroup=%llu)\n",
                    (unsigned long long)tag_cg);
            return 1;
        }
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

    // bats 의 setup_file 이 이 줄을 기다린다.
    printf("READY progs=%d tag_cgroup=%llu pin=%s\n",
           n, (unsigned long long)tag_cg, PIN_DIR);
    fflush(stdout);

    while (!stop)
        pause();

    bpf_object__for_each_map(m, obj) {
        char p[256];
        snprintf(p, sizeof(p), PIN_DIR "/%s", bpf_map__name(m));
        unlink(p);
    }
    rmdir(PIN_DIR);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  tagprobe daemon --tag-cgroup <id>\n"
            "  tagprobe tag <cgroup-id>\n"
            "  tagprobe query <pid>\n"
            "  tagprobe dump\n");
        return 2;
    }
    if (!strcmp(argv[1], "daemon")) return cmd_daemon(argc - 2, argv + 2);
    if (!strcmp(argv[1], "tag"))    return cmd_tag(argc - 2, argv + 2);
    if (!strcmp(argv[1], "query"))  return cmd_query(argc - 2, argv + 2);
    if (!strcmp(argv[1], "dump"))   return cmd_dump();
    fprintf(stderr, "알 수 없는 명령: %s\n", argv[1]);
    return 2;
}
