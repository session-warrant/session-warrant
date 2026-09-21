// S2 — 태그 두 겹이 sudo · su · nohup · 백그라운드를 거쳐도 떨어지지 않는가 (§04)
//
// 두 겹을 각각 따로 기록한다. "태그가 붙었다"만 보면
// systemd-run --scope(cgroup 은 바뀌었지만 fork 체인이 살아 2차 방어선에
// 걸린 경우)와 nohup(1차에 걸린 경우)이 구분되지 않는다.
// §04 표의 세 열 — cgroup · fork 체인 · 태그 — 이 그대로 나와야 한다.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct wb_rec {
    __u64 cgroup_id;
    __u64 warrant_cg;      // 1차(cgroup)로 찾은 영장. 0 이면 cgroup 이 바뀐 것
    __u64 warrant_task;    // 2차(fork 전파)로 찾은 영장. 0 이면 fork 체인이 끊긴 것
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 _pad;
    __u8  comm[16];
};

// 1차 태그: session-N.scope 의 cgroup id → warrant id.
// systemd-logind 가 SSH 로그인마다 만들어 주므로 uid 변경과 무관하다.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} wb_cg_tag SEC(".maps");

// 2차 태그: fork 시 부모의 유효 태그를 자식 task_storage 로 복사한다.
// systemd 가 없는 환경과 cgroup 을 벗어나는 경우를 메운다.
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} wb_task_tag SEC(".maps");

// exec 시점의 판정 결과. 유저 공간이 pid 로 조회한다.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct wb_rec);
} wb_pid_tag SEC(".maps");

static __always_inline __u64 wb_cgroup_of(struct task_struct *t)
{
    // bpf_get_current_cgroup_id() 와 같은 값이다 — cgrp->kn->id.
    // 여기서는 current 가 아니라 임의의 task 를 봐야 하므로 직접 읽는다.
    return BPF_CORE_READ(t, cgroups, dfl_cgrp, kn, id);
}

static __always_inline __u64 wb_tag_by_cgroup(struct task_struct *t)
{
    __u64 cg = wb_cgroup_of(t);
    __u64 *w = bpf_map_lookup_elem(&wb_cg_tag, &cg);
    return w ? *w : 0;
}

static __always_inline __u64 wb_tag_by_task(struct task_struct *t)
{
    __u64 *w = bpf_task_storage_get(&wb_task_tag, t, 0, 0);
    return w ? *w : 0;
}

// 2차 방어선: fork 전파
SEC("tp_btf/sched_process_fork")
int BPF_PROG(wb_fork, struct task_struct *parent, struct task_struct *child)
{
    // 부모의 유효 태그 = 2차 우선, 없으면 1차.
    // 부모가 cgroup 으로만 태그돼 있어도 자식에게는 task_storage 로 심는다 —
    // 그래야 자식이 나중에 cgroup 을 벗어나도 표식이 남는다.
    __u64 w = wb_tag_by_task(parent);
    if (!w)
        w = wb_tag_by_cgroup(parent);
    if (!w)
        return 0;

    __u64 *slot = bpf_task_storage_get(&wb_task_tag, child, &w,
                                       BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (slot)
        *slot = w;
    return 0;
}

// §04 의 첫 겹(실행 화이트리스트)이 놓이는 자리이기도 하다.
// 스파이크 전 구간 감사 모드 — 여기는 언제나 return 0 이다.
SEC("lsm/bprm_check_security")
int BPF_PROG(wb_exec, struct linux_binprm *bprm)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    struct wb_rec r = {};

    r.pid          = bpf_get_current_pid_tgid() >> 32;
    r.uid          = bpf_get_current_uid_gid();
    r.cgroup_id    = bpf_get_current_cgroup_id();
    r.warrant_cg   = wb_tag_by_cgroup(t);
    r.warrant_task = wb_tag_by_task(t);
    r.ppid         = BPF_CORE_READ(t, real_parent, tgid);
    bpf_get_current_comm(&r.comm, sizeof(r.comm));

    bpf_map_update_elem(&wb_pid_tag, &r.pid, &r, BPF_ANY);
    return 0;
}
