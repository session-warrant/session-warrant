/* warrant.bpf.c — 영장 집행. 판정은 전부 여기서 끝난다.
 *
 * 레이아웃은 warrant.bpf.h 에 있고 그건 proto 스키마에서 나온다.
 * 감사 모드와 강제 모드가 같은 판정 함수를 공유한다 (§15) —
 * mode 는 영장의 필드이고, 훅 코드에는 분기가 없다.
 * "감사에서는 안 걸렸는데 강제로 켜니 막히더라"가 구조적으로 생기지 않는다.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "warrant.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define FMODE_WRITE_ 0x2

#define AF_UNIX_  1
#define AF_INET_  2
#define AF_INET6_ 10

#ifndef BPF_LOCAL_STORAGE_GET_F_CREATE
#define BPF_LOCAL_STORAGE_GET_F_CREATE 1
#endif

/* ── 맵 ──────────────────────────────────────────────────────────── */

/* 노드에 활성 영장이 하나도 없으면 모든 훅이 여기서 끝난다.
 * PERCPU 라서 조회에 캐시 라인 경합이 없다. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} active_flag SEC(".maps");

/* 1차 태그 — session-N.scope 의 cgroup id → warrant_id.
 * sudo·su 로 uid 가 바뀌어도 cgroup 은 그대로라 표식이 유지된다 (§04). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} cgroup_warrant SEC(".maps");

/* 2차 태그 — fork 로 전파된다. systemd-run --scope 처럼 cgroup 을 갈아타는
 * 경로를 여기서 잡는다. S2 에서 cg_tag=0 task_tag=1 로 실측됐다. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} task_warrant SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct warrant);
} warrants SEC(".maps");

/* 실행 화이트리스트. 값은 쓰지 않는다 — 존재 자체가 허용이다. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct warrant_rule_key);
	__type(value, __u8);
} rule_exec SEC(".maps");

/* 쓰기 규칙. ALLOW 와 DENY 가 같이 들어간다 — 최장 일치가 이긴다. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct warrant_rule_key);
	__type(value, struct warrant_write_val);
} rule_write SEC(".maps");

/* 아웃바운드 허용 대역. 비어 있으면 전면 차단이다 (§15). */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 8192);
	__type(key, struct warrant_net_key);
	__type(value, struct warrant_net_val);
} rule_net SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* (cpu, cpu_seq) 가 건너뛰면 유실이다. consumer 가 Gap 으로 드러낸다 (§13). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} cpu_seq SEC(".maps");

/* 자기보호 이벤트 억제.
 * bpftool prog list 한 번에 bpf() 가 수백 번 불린다. 그대로 기록하면
 * ringbuf 가 즉시 차고 정작 중요한 이벤트가 밀려난다.
 * 같은 (pid, hook) 은 1초에 한 번만 기록한다 — 차단은 전건 그대로 한다. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   /* pid << 16 | hook */
	__type(value, __u64); /* 마지막 기록 시각 */
} sp_seen SEC(".maps");

/* ── (dev, ino) 추출 ─────────────────────────────────────────────── */

/* LSM 훅의 인자는 trusted pointer 라 직접 따라가도 된다.
 * BPF_CORE_READ 는 포인터 한 단계마다 헬퍼를 부른다 — S1 에서 I 비용의
 * 70%(58/82ns)가 그것이었다. 제품 판정 함수는 직접 따라간다. */
static __always_inline void get_dev_ino(struct file *f, __u32 *dev, __u64 *ino)
{
	struct inode *in = f->f_inode;
	*ino = in->i_ino;
	*dev = in->i_sb->s_dev;
}

/* kprobe 는 인자가 scalar 로 들어와 직접 접근이 막힌다 (R6 invalid mem access).
 * dev_t 는 4바이트다 — 8바이트로 읽으면 옆 필드가 딸려 들어와 키가 깨진다. */
static __always_inline void get_dev_ino_probe(struct file *f, __u32 *dev, __u64 *ino)
{
	struct inode *in = NULL;
	struct super_block *sb = NULL;

	bpf_probe_read_kernel(&in, sizeof(in), &f->f_inode);
	if (!in)
		return;
	bpf_probe_read_kernel(ino, sizeof(*ino), &in->i_ino);
	bpf_probe_read_kernel(&sb, sizeof(sb), &in->i_sb);
	if (!sb)
		return;
	bpf_probe_read_kernel(dev, sizeof(*dev), &sb->s_dev);
}

/* ── 영장 조회 ───────────────────────────────────────────────────── */

static __always_inline struct warrant *lookup_warrant(__u64 *out_wid, __u8 *out_tag)
{
	__u32 zero = 0;
	__u8 *on = bpf_map_lookup_elem(&active_flag, &zero);
	if (!on || !*on)
		return NULL;                                  /* 조기 탈출 */

	__u8 tag = WARRANT_TAG_CGROUP;
	__u64 cg = bpf_get_current_cgroup_id();
	__u64 *wid = bpf_map_lookup_elem(&cgroup_warrant, &cg);
	if (!wid) {
		struct task_struct *t = bpf_get_current_task_btf();
		wid = bpf_task_storage_get(&task_warrant, t, NULL, 0);
		if (!wid)
			return NULL;
		tag = WARRANT_TAG_TASK;
	}
	if (out_wid)
		*out_wid = *wid;
	if (out_tag)
		*out_tag = tag;
	return bpf_map_lookup_elem(&warrants, wid);
}

/* 0 = 유효 · 1 = 취소됨 · 2 = 만료됨.
 *
 * 만료의 의미는 on_expiry 가 정한다. DEMOTE(기본)는 "세션은 살고 쓰기·
 * 아웃바운드만 죽는다" 이므로 커널은 쓰기·inode·네트워크만 막고 exec 은
 * 통과시킨다. KILL·GRACE 에서 실제로 죽이는 건 warrantd 몫이고, 커널이
 * 하는 일은 여기까지 같다. */
static __always_inline __u8 validity(struct warrant *w)
{
	if (w->revoked)
		return 1;
	__u64 now = bpf_ktime_get_boot_ns();
	if (w->expires_ns && now > w->expires_ns)
		return 2;
	return 0;
}

/* mode 를 proto 의 Verdict 로 옮긴다. 판정 자체는 이미 끝나 있다. */
static __always_inline __u8 verdict_of(struct warrant *w, __u8 denied)
{
	if (!denied)
		return WARRANT_VERDICT_ALLOW;
	return w->mode == WARRANT_MODE_ENFORCE ? WARRANT_VERDICT_DENY
					       : WARRANT_VERDICT_WOULD_DENY;
}

static __always_inline int ret_of(struct warrant *w, __u8 denied)
{
	return (denied && w->mode == WARRANT_MODE_ENFORCE) ? -EPERM : 0;
}

/* ── 감사 레코드 ─────────────────────────────────────────────────── */

static __always_inline void fill_proc(struct warrant_proc *p)
{
	struct task_struct *t = bpf_get_current_task_btf();
	__u64 pt = bpf_get_current_pid_tgid();

	p->pid  = (__u32)pt;
	p->tgid = (__u32)(pt >> 32);
	p->cgroup_id = bpf_get_current_cgroup_id();
	p->start_time_ns = t->start_time;
	p->ppid = t->real_parent->tgid;

	const struct cred *c = t->cred;
	p->uid  = c->uid.val;
	p->euid = c->euid.val;
	p->gid  = c->gid.val;

	struct nsproxy *ns = t->nsproxy;   /* exit 중이면 NULL 이다 */
	p->pid_ns_inum = ns ? ns->pid_ns_for_children->ns.inum : 0;

	p->_pad = 0;
	bpf_get_current_comm(p->comm, sizeof(p->comm));
}

/* payload 는 호출부가 스택에 만들어 넘긴다.
 * verifier 가 상수 크기를 요구하므로 예약은 최대 크기로 고정한다. */
static __always_inline void emit(__u16 hook, __u8 verdict, __u8 tag_source,
				 __u64 wid, struct warrant *w,
				 const void *payload, __u16 plen)
{
	struct warrant_evt *e = bpf_ringbuf_reserve(&events, WARRANT_EVT_MAX, 0);
	if (!e)
		return;

	__u32 zero = 0;
	__u64 *seq = bpf_map_lookup_elem(&cpu_seq, &zero);
	if (seq) {
		*seq += 1;
		e->cpu_seq = *seq;
	} else {
		e->cpu_seq = 0;
	}

	e->boot_ts_ns  = bpf_ktime_get_boot_ns();
	e->warrant_id  = wid;
	e->cpu         = bpf_get_smp_processor_id();
	e->subject_id  = w ? w->subject_id : 0;
	e->policy_id   = w ? w->policy_id : 0;
	e->hook        = hook;
	e->verdict     = verdict;
	e->mode        = w ? w->mode : WARRANT_MODE_OBSERVE;
	e->origin      = WARRANT_ORIGIN_LSM;
	e->tag_source  = tag_source;
	e->payload_len = plen;
	__builtin_memset(e->_pad, 0, sizeof(e->_pad));

	fill_proc(&e->proc);

	__u8 *tail = (__u8 *)e + sizeof(*e);
	__builtin_memset(tail, 0, 40);
	if (payload && plen > 0 && plen <= 40)
		bpf_probe_read_kernel(tail, plen, payload);

	bpf_ringbuf_submit(e, 0);
}

/* ── 쓰기 규칙 : 최장 일치 → 같은 깊이면 DENY → 안 걸리면 금지 ───────
 *
 * dentry 에서 부모를 거슬러 올라가며 조회한다. 먼저 걸리는 쪽이 더 긴
 * 일치다. 상한을 넘으면 「안 걸림」 = 금지다 (proto/README 3).
 *
 * recursive=0 인 디렉터리 규칙은 직계 자식까지만 적용된다. 그보다 깊으면
 * 못 본 걸로 하고 계속 올라간다.
 *
 * 금지를 파일 inode 에 걸면 mv 후 재생성으로 뚫린다 — 그래서 DENY 는
 * 반드시 디렉터리여야 하고, 그 검사는 warrantd 의 policy 가 한다 (§15).
 */
static __always_inline __u8 dentry_write_allowed(struct dentry *d, __u32 policy_id,
						 __u32 *out_dev, __u64 *out_ino)
{
	struct warrant_rule_key k = {};
	k.policy_id = policy_id;

#pragma unroll
	for (int depth = 0; depth < WARRANT_WALK_MAX; depth++) {
		if (!d)
			break;

		struct inode *in = NULL;
		bpf_probe_read_kernel(&in, sizeof(in), &d->d_inode);
		if (in) {
			struct super_block *sb = NULL;
			bpf_probe_read_kernel(&k.ino, sizeof(k.ino), &in->i_ino);
			bpf_probe_read_kernel(&sb, sizeof(sb), &in->i_sb);
			if (sb) {
				bpf_probe_read_kernel(&k.dev, sizeof(k.dev), &sb->s_dev);

				if (depth == 0 && out_dev && out_ino) {
					*out_dev = k.dev;
					*out_ino = k.ino;
				}

				struct warrant_write_val *v =
					bpf_map_lookup_elem(&rule_write, &k);
				if (v && (depth == 0 || v->recursive || depth == 1))
					return v->effect == WARRANT_EFFECT_ALLOW;
			}
		}

		struct dentry *parent = NULL;
		bpf_probe_read_kernel(&parent, sizeof(parent), &d->d_parent);
		if (!parent || parent == d)
			break;   /* 루트 도달 */
		d = parent;
	}
	return 0;
}

/* ── file_open ───────────────────────────────────────────────────── */

/* 앞문은 f_mode & FMODE_WRITE 한 줄이다. S0 에서 쓰기 의도는 전체
 * file_open 의 4.7% 였다 — 나머지 95%가 여기서 끝난다. S1 의 읽기 지배
 * 워크로드에서 C·E·D 가 전부 같았던 게 그 직접 증거다. */
static __always_inline int file_verdict(struct file *file, __u8 is_probe, __u8 origin)
{
	__u64 wid = 0;
	__u8 tag = WARRANT_TAG_NONE;
	struct warrant *w = lookup_warrant(&wid, &tag);
	if (!w || !file)
		return 0;

	unsigned int fmode = 0;
	bpf_probe_read_kernel(&fmode, sizeof(fmode), &file->f_mode);
	if (!(fmode & FMODE_WRITE_))
		return 0;

	__u8 val = validity(w);
	__u8 denied;

	struct warrant_pl_write pl = {};
	__u32 dev = 0;
	__u64 ino = 0;

	if (val != 0) {
		denied = 1;   /* 취소 · 만료 — 쓰기는 양쪽 다 죽는다 */
		if (is_probe)
			get_dev_ino_probe(file, &dev, &ino);
		else
			get_dev_ino(file, &dev, &ino);
	} else {
		struct dentry *d = NULL;
		bpf_probe_read_kernel(&d, sizeof(d), &file->f_path.dentry);
		denied = !dentry_write_allowed(d, w->policy_id, &dev, &ino);
	}

	/* 허용된 쓰기는 기록하지 않는다. 전건 남기면 ringbuf 가 넘친다 (§13). */
	if (denied) {
		pl.file.dev = dev;
		pl.file.ino = ino;
		bpf_probe_read_kernel(&pl.f_flags, sizeof(pl.f_flags), &file->f_flags);
		emit(WARRANT_HOOK_FILE_OPEN, verdict_of(w, denied), tag, wid, w,
		     &pl, sizeof(pl));
	}

	if (origin == WARRANT_ORIGIN_KPROBE)
		return 0;   /* 미러는 판정을 되돌리지 않는다 */
	return ret_of(w, denied);
}

SEC("lsm/file_open")
int BPF_PROG(warrant_file_open, struct file *file, int ret)
{
	if (ret != 0)
		return ret;
	return file_verdict(file, 0, WARRANT_ORIGIN_LSM);
}

/* 감사 미러. 같은 판정 함수를 부르고 반환값만 버린다 —
 * LSM 과 판정이 갈리면 그건 버그다 (proto AuditEvent.origin). */
SEC("kprobe/security_file_open")
int BPF_KPROBE(warrant_file_open_mirror, struct file *file)
{
	file_verdict(file, 1, WARRANT_ORIGIN_KPROBE);
	return 0;
}

/* ── inode_{create,unlink,rename,link,symlink} ───────────────────── */

static __always_inline int inode_verdict(struct dentry *d, __u16 hook, __u8 op)
{
	__u64 wid = 0;
	__u8 tag = WARRANT_TAG_NONE;
	struct warrant *w = lookup_warrant(&wid, &tag);
	if (!w)
		return 0;

	__u32 dev = 0;
	__u64 ino = 0;
	__u8 val = validity(w);
	__u8 denied = val != 0 ? 1
			       : !dentry_write_allowed(d, w->policy_id, &dev, &ino);

	if (denied) {
		struct warrant_pl_inode pl = {};
		pl.target.dev = dev;
		pl.target.ino = ino;
		pl.op = op;
		emit(hook, verdict_of(w, denied), tag, wid, w, &pl, sizeof(pl));
	}
	return ret_of(w, denied);
}

SEC("lsm/inode_create")
int BPF_PROG(warrant_inode_create, struct inode *dir, struct dentry *dentry,
	     umode_t mode, int ret)
{
	if (ret != 0)
		return ret;
	return inode_verdict(dentry, WARRANT_HOOK_INODE_CREATE, WARRANT_OP_CREATE);
}

SEC("lsm/inode_unlink")
int BPF_PROG(warrant_inode_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
	if (ret != 0)
		return ret;
	return inode_verdict(dentry, WARRANT_HOOK_INODE_UNLINK, WARRANT_OP_UNLINK);
}

/* 출발지와 도착지 양쪽이 허용이어야 한다.
 * 한쪽만 보면 허용 디렉터리에서 금지 디렉터리로 옮기는 게 통과한다. */
SEC("lsm/inode_rename")
int BPF_PROG(warrant_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, int ret)
{
	if (ret != 0)
		return ret;
	int v = inode_verdict(old_dentry, WARRANT_HOOK_INODE_RENAME, WARRANT_OP_RENAME);
	if (v != 0)
		return v;
	return inode_verdict(new_dentry, WARRANT_HOOK_INODE_RENAME, WARRANT_OP_RENAME);
}

SEC("lsm/inode_link")
int BPF_PROG(warrant_inode_link, struct dentry *old_dentry, struct inode *dir,
	     struct dentry *new_dentry, int ret)
{
	if (ret != 0)
		return ret;
	return inode_verdict(new_dentry, WARRANT_HOOK_INODE_LINK, WARRANT_OP_LINK);
}

SEC("lsm/inode_symlink")
int BPF_PROG(warrant_inode_symlink, struct inode *dir, struct dentry *dentry,
	     const char *old_name, int ret)
{
	if (ret != 0)
		return ret;
	return inode_verdict(dentry, WARRANT_HOOK_INODE_SYMLINK, WARRANT_OP_SYMLINK);
}

/* ── bprm_check_security ─────────────────────────────────────────── */

/* argv 는 1급 증거가 아니다 (exec -a 로 위조 가능 + 스택 제약으로 잘림).
 * 신뢰 근거는 커널이 실제로 연 바이너리의 inode 다 (§14). */
SEC("lsm/bprm_check_security")
int BPF_PROG(warrant_bprm, struct linux_binprm *bprm, int ret)
{
	if (ret != 0)
		return ret;

	__u64 wid = 0;
	__u8 tag = WARRANT_TAG_NONE;
	struct warrant *w = lookup_warrant(&wid, &tag);
	if (!w)
		return 0;

	__u32 dev = 0;
	__u64 ino = 0;
	get_dev_ino(bprm->file, &dev, &ino);

	__u8 val = validity(w);
	__u8 denied;

	if (val == 1) {
		denied = 1;          /* 취소 */
	} else if (val == 2) {
		denied = 0;          /* 만료 — DEMOTE 는 쓰기·아웃바운드만 죽인다 */
	} else {
		struct warrant_rule_key k = {};
		k.policy_id = w->policy_id;
		k.dev = dev;
		k.ino = ino;
		denied = bpf_map_lookup_elem(&rule_exec, &k) ? 0 : 1;
	}

	/* exec 은 빈도가 낮아 허용도 기록한다 (§13). */
	struct warrant_pl_exec pl = {};
	pl.file.dev = dev;
	pl.file.ino = ino;
	pl.i_mode = bprm->file->f_inode->i_mode;   /* setuid 탐지 */
	emit(WARRANT_HOOK_BPRM_CHECK_SECURITY, verdict_of(w, denied), tag, wid, w,
	     &pl, sizeof(pl));

	return ret_of(w, denied);
}

/* ── socket_connect ──────────────────────────────────────────────── */

/* IPv4 는 IPv4-mapped IPv6 (::ffff:a.b.c.d) 로 펴서 한 trie 에 넣는다.
 * family 바이트를 키에 넣지 않아도 주소 공간이 겹치지 않는다. */
static __always_inline void v4_mapped(__u8 addr[16], __u32 be_addr)
{
	__builtin_memset(addr, 0, 16);
	addr[10] = 0xff;
	addr[11] = 0xff;
	__builtin_memcpy(&addr[12], &be_addr, 4);
}

static __always_inline __u8 net_allowed(__u32 policy_id, const __u8 addr[16],
					__u16 port, __u8 proto)
{
	struct warrant_net_key k = {};
	k.prefixlen = 32 + 128;
	k.policy_id_be = bpf_htonl(policy_id);   /* LPM 은 MSB 부터 맞춘다 */
	__builtin_memcpy(k.addr, addr, 16);

	struct warrant_net_val *v = bpf_map_lookup_elem(&rule_net, &k);
	if (!v)
		return 0;
	if (v->proto != 0 && v->proto != proto)
		return 0;
	if (v->nports == 0)
		return 1;

#pragma unroll
	for (int i = 0; i < 7; i++) {
		if (i >= v->nports)
			break;
		if (v->ports[i] == port)
			return 1;
	}
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(warrant_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	if (ret != 0)
		return ret;

	__u64 wid = 0;
	__u8 tag = WARRANT_TAG_NONE;
	struct warrant *w = lookup_warrant(&wid, &tag);
	if (!w)
		return 0;

	__u8 val = validity(w);
	__u16 family = address->sa_family;

	struct warrant_pl_connect pl = {};
	__u8 denied = 0;

	if (family == AF_INET_) {
		struct sockaddr_in *sin = (struct sockaddr_in *)address;
		__u32 daddr = sin->sin_addr.s_addr;      /* network order */
		__u16 dport = bpf_ntohs(sin->sin_port);

		v4_mapped(pl.addr, daddr);
		pl.family = AF_INET_;
		pl.proto = 1;
		pl.port = dport;

		denied = val != 0 ? 1
				  : !net_allowed(w->policy_id, pl.addr, dport, 1);

	} else if (family == AF_INET6_) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
		__u16 dport = bpf_ntohs(sin6->sin6_port);

		bpf_probe_read_kernel(pl.addr, 16, &sin6->sin6_addr);
		pl.family = AF_INET6_;
		pl.proto = 1;
		pl.port = dport;

		denied = val != 0 ? 1
				  : !net_allowed(w->policy_id, pl.addr, dport, 1);

	} else if (family == AF_UNIX_) {
		/* AF_UNIX 은 화이트리스트가 아니라 위임 경로만 끊는다.
		 * systemd · D-Bus · docker.sock — 셋 다 세션 밖으로
		 * 일을 넘기는 통로다 (§04, §18). */
		struct sockaddr_un *sun = (struct sockaddr_un *)address;
		char p[32] = {};
		bpf_probe_read_kernel_str(p, sizeof(p), sun->sun_path);

		if (p[0] == '/' && p[1] == 'r' && p[2] == 'u' && p[3] == 'n' &&
		    p[4] == '/') {
			if (p[5] == 'd' && p[6] == 'b' && p[7] == 'u' && p[8] == 's')
				denied = 1;                      /* /run/dbus/ */
			else if (p[5] == 'd' && p[6] == 'o' && p[7] == 'c')
				denied = 1;                      /* /run/docker.sock */
			else if (p[5] == 'c' && p[6] == 'o' && p[7] == 'n')
				denied = 1;                      /* /run/containerd/ */
			else if (p[5] == 's' && p[6] == 'y' && p[7] == 's' &&
				 p[13] == '/' && p[14] == 'p' && p[15] == 'r')
				denied = 1;                      /* /run/systemd/private */
		}
		if (!denied)
			return 0;

		pl.family = AF_UNIX_;
		__builtin_memcpy(pl.addr, p, 16);
	} else {
		return 0;
	}

	/* connect 는 빈도가 낮아 허용도 기록한다 (§13). */
	emit(WARRANT_HOOK_SOCKET_CONNECT, verdict_of(w, denied), tag, wid, w,
	     &pl, sizeof(pl));
	return ret_of(w, denied);
}

/* ── sched_process_fork : 2차 태그 전파 ──────────────────────────── */

SEC("tp_btf/sched_process_fork")
int BPF_PROG(warrant_fork, struct task_struct *parent, struct task_struct *child)
{
	__u64 cg = bpf_get_current_cgroup_id();
	__u8 tag;
	__u64 *wid = bpf_task_storage_get(&task_warrant, parent, NULL, 0);

	if (wid) {
		tag = WARRANT_TAG_TASK;
	} else {
		wid = bpf_map_lookup_elem(&cgroup_warrant, &cg);
		if (!wid)
			return 0;
		tag = WARRANT_TAG_CGROUP;
	}

	bpf_task_storage_get(&task_warrant, child, wid,
			     BPF_LOCAL_STORAGE_GET_F_CREATE);

	struct warrant *w = bpf_map_lookup_elem(&warrants, wid);
	struct warrant_pl_fork pl = {};
	pl.parent_tgid = parent->tgid;
	pl.child_tgid = child->tgid;
	pl.child_cgroup_id = cg;

	emit(WARRANT_HOOK_SCHED_PROCESS_FORK, WARRANT_VERDICT_ALLOW, tag, *wid, w,
	     &pl, sizeof(pl));
	return 0;
}

/* ── 자기보호 5종 ────────────────────────────────────────────────────
 *
 * 규칙 조회가 없다. 영장 세션이면 무조건 거부한다.
 * 이건 정책이 아니라 제품이 강제로 삽입하는 기본 규칙이고, 영장 작성자가
 * 실수로도 열 수 없어야 한다. 하나라도 열려 있으면 나머지가 무의미하다 (§16).
 *
 * 여섯 번째(warrantd 자기 파일 쓰기 금지)는 훅이 아니라 rule_write 의
 * DENY 엔트리다 — policy 가 모든 정책에 강제로 끼워 넣는다.
 *
 * break_glass 영장만 이걸 통과한다. 일반 발급 경로로는 켤 수 없다.
 */
static __always_inline int selfprotect(__u16 hook)
{
	__u64 wid = 0;
	__u8 tag = WARRANT_TAG_NONE;
	struct warrant *w = lookup_warrant(&wid, &tag);
	if (!w || w->break_glass)
		return 0;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 now = bpf_ktime_get_boot_ns();
	__u64 k = ((__u64)pid << 16) | hook;

	__u64 *last = bpf_map_lookup_elem(&sp_seen, &k);
	__u8 quiet = (last && now - *last < 1000000000ULL) ? 1 : 0;
	if (!quiet) {
		bpf_map_update_elem(&sp_seen, &k, &now, BPF_ANY);
		emit(hook, verdict_of(w, 1), tag, wid, w, NULL, 0);
	}

	return ret_of(w, 1);
}

SEC("lsm/bpf")
int BPF_PROG(warrant_sp_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
	if (ret != 0)
		return -EPERM;   /* 앞선 LSM 이 이미 거부했다 */
	return selfprotect(WARRANT_HOOK_BPF);
}

SEC("lsm/task_kill")
int BPF_PROG(warrant_sp_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred, int ret)
{
	if (ret != 0)
		return -EPERM;
	return selfprotect(WARRANT_HOOK_TASK_KILL);
}

SEC("lsm/sb_umount")
int BPF_PROG(warrant_sp_umount, struct vfsmount *mnt, int flags, int ret)
{
	if (ret != 0)
		return -EPERM;
	return selfprotect(WARRANT_HOOK_SB_UMOUNT);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(warrant_sp_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
	if (ret != 0)
		return -EPERM;
	return selfprotect(WARRANT_HOOK_PTRACE_ACCESS_CHECK);
}

SEC("lsm/kernel_module_request")
int BPF_PROG(warrant_sp_modreq, char *kmod_name, int ret)
{
	if (ret != 0)
		return -EPERM;
	return selfprotect(WARRANT_HOOK_KERNEL_MODULE_REQUEST);
}
