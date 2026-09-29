/* warrant.bpf.h — 커널 ↔ warrantd 공유 레이아웃.
 *
 * 이 파일의 모든 구조체는 proto/warrant.proto · proto/audit.proto 에서 나온다.
 * 필드를 고칠 일이 생기면 .proto 를 먼저 고친다 (CLAUDE.md 「작업 규칙」).
 *
 * Go 쪽 대응물은 agent/internal/bpfmap · agent/internal/ringbuf 다.
 * 크기가 어긋나면 맵 조회가 조용히 빗나간다 — 파일 끝의 _Static_assert 가 그걸 막는다.
 *
 * 타입 이름은 예외 없이 warrant_ 로 시작한다. vmlinux.h 가 커널 타입을 통째로
 * 들여오므로 event · task · config · sample 같은 이름은 전부 이미 존재한다.
 */

#ifndef __WARRANT_BPF_H
#define __WARRANT_BPF_H

/* ── proto 와 값이 같아야 하는 상수 ─────────────────────────────── */

/* proto/warrant.proto enum Mode */
#define WARRANT_MODE_OBSERVE 0
#define WARRANT_MODE_DRYRUN  1
#define WARRANT_MODE_ENFORCE 2

/* proto/warrant.proto enum OnExpiry */
#define WARRANT_ON_EXPIRY_DEMOTE             0
#define WARRANT_ON_EXPIRY_KILL               1
#define WARRANT_ON_EXPIRY_SESSION_ONLY_GRACE 2

/* proto/audit.proto enum Verdict */
#define WARRANT_VERDICT_ALLOW      0
#define WARRANT_VERDICT_DENY       1
#define WARRANT_VERDICT_WOULD_DENY 2

/* proto/audit.proto enum Origin */
#define WARRANT_ORIGIN_LSM    1
#define WARRANT_ORIGIN_KPROBE 2

/* proto/audit.proto enum TagSource */
#define WARRANT_TAG_NONE   0
#define WARRANT_TAG_CGROUP 1
#define WARRANT_TAG_TASK   2

/* proto/audit.proto enum Hook — 훅 부착 순서와 같다 */
#define WARRANT_HOOK_SCHED_PROCESS_FORK    1
#define WARRANT_HOOK_BPRM_CHECK_SECURITY   2
#define WARRANT_HOOK_SOCKET_CONNECT        3
#define WARRANT_HOOK_FILE_OPEN             4
#define WARRANT_HOOK_INODE_CREATE          5
#define WARRANT_HOOK_INODE_UNLINK          6
#define WARRANT_HOOK_INODE_RENAME          7
#define WARRANT_HOOK_INODE_LINK            8
#define WARRANT_HOOK_INODE_SYMLINK         9
#define WARRANT_HOOK_BPF                   10
#define WARRANT_HOOK_TASK_KILL             11
#define WARRANT_HOOK_SB_UMOUNT             12
#define WARRANT_HOOK_PTRACE_ACCESS_CHECK   13
#define WARRANT_HOOK_KERNEL_MODULE_REQUEST 14
#define WARRANT_HOOK_SOCKET_SENDMSG        15

/* proto/audit.proto InodeMutateEvent.Op */
#define WARRANT_OP_CREATE  1
#define WARRANT_OP_UNLINK  2
#define WARRANT_OP_RENAME  3
#define WARRANT_OP_LINK    4
#define WARRANT_OP_SYMLINK 5

/* proto/warrant.proto WriteRule.Effect — 0 은 컴파일러가 거부한다 */
#define WARRANT_EFFECT_ALLOW 1
#define WARRANT_EFFECT_DENY  2

/* 쓰기 규칙 조상 순회 상한. 넘으면 「안 걸림」 = 금지 (proto/README 3).
 * 커널이 정하는 값이고, warrantd 는 이 값을 넘는 깊이의 규칙을 거부해야 한다. */
#define WARRANT_WALK_MAX 16

/* ── 맵 값 ──────────────────────────────────────────────────────── */

/* warrants 맵의 값. 키는 warrant_id (__u64).
 * expires_ns 는 boot 기준이다 — 절대시각 → boot 변환은 warrantd 만 한다. */
struct warrant {
	__u64 expires_ns;
	__u64 grace_ns;
	__u32 subject_id;
	__u32 policy_id;
	__u8  revoked;
	__u8  mode;         /* WARRANT_MODE_* */
	__u8  on_expiry;    /* WARRANT_ON_EXPIRY_* */
	__u8  break_glass;  /* 자기보호를 푸는 유일한 영장. 일반 발급 경로로는 못 켠다 */
	__u8  _pad[4];
};

/* rule_exec · rule_write 의 키.
 * inode 번호는 파일시스템 안에서만 유일하므로 dev 를 빼면 안 된다.
 * dev 는 커널 s_dev (__u32, 12bit major : 20bit minor) 다 — 유저 공간 st_dev 와
 * 인코딩이 다르므로 warrantd 가 major<<20 | minor 로 만들어 넣는다. */
struct warrant_rule_key {
	__u32 policy_id;
	__u32 dev;
	__u64 ino;
};

/* rule_write 의 값. 최장 일치 → 같은 깊이면 DENY → 안 걸리면 금지.
 * 같은 inode 에 ALLOW 와 DENY 가 겹치면 warrantd 가 DENY 만 넣는다. */
struct warrant_write_val {
	__u8 effect;     /* WARRANT_EFFECT_* */
	__u8 recursive;
	__u8 _pad[6];
};

/* rule_net (LPM_TRIE) 의 키. policy_id 는 big-endian — LPM 이 MSB 부터 맞춘다.
 * prefixlen = 32 + CIDR 비트수. IPv4 는 addr 앞 4바이트만 쓴다. */
struct warrant_net_key {
	__u32 prefixlen;
	__u32 policy_id_be;
	__u8  addr[16];
};

/* rule_net 의 값. nports = 0 이면 모든 포트. */
struct warrant_net_val {
	__u8  proto;      /* 0 ANY · 1 TCP · 2 UDP */
	__u8  nports;
	__u16 ports[7];   /* host byte order */
};

/* ── 감사 레코드 ────────────────────────────────────────────────── */

/* 경로가 아니라 (dev, ino) 가 증거다 (§14). */
struct warrant_fileref {
	__u32 dev;
	__u32 _pad;
	__u64 ino;
};

/* proto/audit.proto ProcessIdentity. 전건에 실린다. */
struct warrant_proc {
	__u64 start_time_ns;   /* (pid, start_time) 이 유일 키 */
	__u64 cgroup_id;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 euid;
	__u32 gid;
	__u32 pid_ns_inum;     /* exit 중이면 0 */
	__u32 _pad;
	char  comm[16];        /* 잘리고 위조 가능하다. 1급 증거가 아니다 */
};

/* ringbuf 레코드의 고정 머리. 뒤에 payload_len 바이트의 payload 가 붙는다.
 * (cpu, cpu_seq) 가 건너뛰면 유실이다 — ringbuf consumer 가 Gap 으로 드러낸다. */
struct warrant_evt {
	__u64 cpu_seq;
	__u64 boot_ts_ns;      /* bpf_ktime_get_boot_ns(). 벽시계 변환은 warrantd */
	__u64 warrant_id;      /* 0 = 무영장 */
	__u32 cpu;
	__u32 subject_id;
	__u32 policy_id;
	__u16 hook;            /* WARRANT_HOOK_* */
	__u8  verdict;         /* WARRANT_VERDICT_* */
	__u8  mode;            /* WARRANT_MODE_* */
	__u8  origin;          /* WARRANT_ORIGIN_* — lsm 과 kprobe 판정이 다르면 버그 */
	__u8  tag_source;      /* WARRANT_TAG_* */
	__u16 payload_len;
	__u8  _pad[4];
	struct warrant_proc proc;
};

/* ringbuf 예약 크기. verifier 가 상수를 요구하므로 가장 큰 payload 로 고정한다.
 * 실제 유효 길이는 warrant_evt.payload_len 이다. */
#define WARRANT_EVT_MAX (sizeof(struct warrant_evt) + 40)

/* payload — hook 값이 어느 것인지 정한다 */

struct warrant_pl_exec {          /* BPRM_CHECK_SECURITY */
	struct warrant_fileref file;
	__u32 i_mode;                 /* setuid 탐지 */
	__u32 new_uid;
	__u32 new_euid;
	__u32 _pad;
};

struct warrant_pl_write {         /* FILE_OPEN */
	struct warrant_fileref file;
	struct warrant_fileref parent;
	__u32 f_flags;                /* O_TRUNC · O_APPEND · O_CREAT */
	__u32 _pad;
};

struct warrant_pl_inode {         /* INODE_{CREATE,UNLINK,RENAME,LINK,SYMLINK} */
	struct warrant_fileref dir;
	struct warrant_fileref target;
	__u8  op;                     /* WARRANT_OP_* */
	__u8  _pad[7];
};

struct warrant_pl_connect {       /* SOCKET_CONNECT · SOCKET_SENDMSG */
	__u8  family;                 /* 1 UNIX · 2 INET · 10 INET6 */
	__u8  proto;
	__u16 port;                   /* host byte order */
	__u32 _pad;
	__u8  addr[16];               /* 네트워크 바이트 오더 */
};

struct warrant_pl_fork {          /* SCHED_PROCESS_FORK */
	__u32 parent_tgid;
	__u32 child_tgid;
	__u64 child_cgroup_id;
};

/* ── 크기 계약 ──────────────────────────────────────────────────────
 * Go 쪽 구조체와 바이트 단위로 같아야 한다. 어긋나면 여기서 빌드가 선다.
 * agent 쪽에도 같은 숫자를 검사하는 테스트를 둔다.
 */
_Static_assert(sizeof(struct warrant)            == 32, "struct warrant");
_Static_assert(sizeof(struct warrant_rule_key)   == 16, "warrant_rule_key");
_Static_assert(sizeof(struct warrant_write_val)  ==  8, "warrant_write_val");
_Static_assert(sizeof(struct warrant_net_key)    == 24, "warrant_net_key");
_Static_assert(sizeof(struct warrant_net_val)    == 16, "warrant_net_val");
_Static_assert(sizeof(struct warrant_fileref)    == 16, "warrant_fileref");
_Static_assert(sizeof(struct warrant_proc)       == 64, "warrant_proc");
_Static_assert(sizeof(struct warrant_evt)        == 112, "warrant_evt");
_Static_assert(sizeof(struct warrant_pl_exec)    == 32, "warrant_pl_exec");
_Static_assert(sizeof(struct warrant_pl_write)   == 40, "warrant_pl_write");
_Static_assert(sizeof(struct warrant_pl_inode)   == 40, "warrant_pl_inode");
_Static_assert(sizeof(struct warrant_pl_connect) == 24, "warrant_pl_connect");
_Static_assert(sizeof(struct warrant_pl_fork)    == 16, "warrant_pl_fork");

#endif /* __WARRANT_BPF_H */
