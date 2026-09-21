// S0 툴체인 스모크 — clang · libbpf · CO-RE · lsm=bpf 가 이 커널에서 같이 도는지만 본다.
// 감사 모드: 절대 -EPERM 을 리턴하지 않는다. 자기보호 6종(§16) 전에 차단을 켜면 자기 박스에서 잠긴다.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// vmlinux.h 에는 BTF 타입만 들어 있다. 매크로는 직접 적는다.
#define FMODE_WRITE 0x2

enum {
    ST_OPEN_TOTAL = 0,
    ST_OPEN_WRITE = 1,   // 그중 f_mode & FMODE_WRITE
    ST_FORK       = 2,
    ST_MAX
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ST_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// 마지막으로 본 값 하나. 로더가 읽어서 "정말 읽혔는지" 눈으로 확인하는 용도다.
// 접두사 필수: vmlinux.h 에 struct sample 등 흔한 이름이 이미 있다. 제품 코드는 warrant_*.
struct smoke_sample {
    __u64 cgroup_id;
    __u64 boot_ns;
    __u64 ino;
    __u32 dev;
    __u32 pid;
    __u8  write;
    __u8  _pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct smoke_sample);
} last SEC(".maps");

static __always_inline void bump(__u32 k)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &k);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("lsm/file_open")
int BPF_PROG(smoke_file_open, struct file *file)
{
    bump(ST_OPEN_TOTAL);

    // 경로가 아니라 (dev, ino) 로 식별한다 — 경로는 mv 로 흔들린다
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u32 dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    __u32 mode = BPF_CORE_READ(file, f_mode);
    __u8  w = (mode & FMODE_WRITE) ? 1 : 0;

    if (w)
        bump(ST_OPEN_WRITE);

    __u32 z = 0;
    struct smoke_sample *s = bpf_map_lookup_elem(&last, &z);
    if (s) {
        s->cgroup_id = bpf_get_current_cgroup_id();
        s->boot_ns   = bpf_ktime_get_boot_ns();
        s->ino   = ino;
        s->dev   = dev;
        s->pid   = bpf_get_current_pid_tgid() >> 32;
        s->write = w;
    }

    return 0;   // 언제나 허용. 여기를 -EPERM 으로 바꾸지 말 것
}

// 태그 2차 방어선(fork 전파)이 붙을 자리. 지금은 세기만 한다.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(smoke_fork, struct task_struct *parent, struct task_struct *child)
{
    bump(ST_FORK);
    return 0;
}
