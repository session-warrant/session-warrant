// S1 — file_open 오버헤드 4단 측정
//
// 티어는 파일이 아니라 컴파일 타임 상수다. C 는 B 에 한 줄 더한 것이고
// D 는 C 에 조회를 더한 것이라는 관계가 소스에 그대로 보여야 한다.
// 파일 넷으로 쪼개면 티어끼리 슬금슬금 달라져도 아무도 모른다.
//
//   TIER=1  (B) 훅만 붙이고 return 0
//   TIER=2  (C) + f_mode & FMODE_WRITE 앞문      ← S0 실측 95% 가 여기서 끝난다
//   TIER=3  (D) + cgroup 조회 · 맵 2회 · 시간 비교
//   (A 는 훅이 없는 상태 = 로더를 안 띄운다. 오브젝트가 없다)
//
//   READ_WATCH=1  (R) D + 읽기 감시, cgroup 먼저 — 읽기 열기마다 태그·영장을 본 뒤 감시 목록
//   READ_WATCH=2  (I) D + 읽기 감시, inode 먼저 — 감시 목록에 있을 때만 cgroup 을 본다
//   READ_WATCH=3  (I2) I 와 같은 순서, (dev, ino) 를 BPF_CORE_READ 가 아니라 직접 load
//   Policy.read_watch_paths(§15) 를 넣을 수 있는가를 잰다. 앞문을 지나는 읽기가
//   cgroup 조회(S1 에서 비용의 대부분)까지 가느냐 마느냐가 R 과 I 의 차이다.
//
//   PROBE=0  계측 없음. 매크로(워크로드 벽시계) 측정용
//   PROBE=1  + 지연 히스토그램 · dev major 히스토그램 · 카운터
//
// PROBE=1 은 훅마다 bpf_ktime_get_ns() 를 두 번 부른다. 그 비용이 티어 B 가
// 내는 비용과 자릿수가 비슷하다. 그래서 매크로 숫자와 마이크로 숫자는
// 반드시 다른 빌드에서 뽑는다. 같은 실행에서 둘 다 얻으려 하면 둘 다 틀린다.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// vmlinux.h 에는 BTF 타입만 들어 있다. 매크로는 직접 적는다.
#define FMODE_WRITE 0x2
#define OH_MAJOR(dev) ((dev) >> 20)

#ifndef TIER
#define TIER 1
#endif
#ifndef PROBE
#define PROBE 0
#endif
#ifndef READ_WATCH
#define READ_WATCH 0
#endif
#if READ_WATCH && TIER < 3
#error "READ_WATCH 는 TIER=3 (D) 위에 얹는다"
#endif

struct oh_warrant {
    __u64 expires_ns;      // boot 기준. 유저 공간 시각이 아니다
    __u8  revoked;
    __u8  _pad[7];
};

// 판정 결과 코드. oh_decide 는 세지 않고 이것만 돌려준다 —
// 계측을 판정 안에 두면 티어마다 계측 비용이 달라진다(B 0회, C 1회, D 2회).
// 그러면 B→C 점프가 앞문 비용이 아니라 계측 비용이 되어버린다.
enum {
    OH_R_PASS = 0,         // 앞문을 통과. 티어 B 는 언제나 여기
    OH_R_READ,             // 쓰기 아님 — 95% 가 여기서 끝난다
    OH_R_TAG_MISS,         // 무영장 세션
    OH_R_TAG_HIT,          // 유효한 영장
    OH_R_REVOKED,          // 강제 모드였다면 -EPERM
    OH_R_EXPIRED,          // 강제 모드였다면 -EPERM
    OH_R_WATCH_HIT,        // 영장 세션이 감시 대상 inode 를 읽음 (R · I 만)
    OH_R_MAX
};
#define OH_C_TOTAL OH_R_MAX
#define OH_CNT_MAX (OH_R_MAX + 1)

// 카운터는 전부 PERCPU 다. ARRAY + __sync_fetch_and_add 는 한 캐시라인을 모든 CPU 가
// 두들기는 구조라, -P8 병렬 워크로드에서는 그 경합 자체가 측정값이 되어버린다.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, OH_CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} oh_counters SEC(".maps");

// 판정 함수 자체의 소요 시간, log2(ns) 버킷. p99 는 여기서 나온다.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} oh_lat SEC(".maps");

// dev major 별 · 읽기/쓰기별 분포. index = major * 2 + write
// "왜 95% 를 안 걸렀나" 를 나중에 설명하려면 이 표가 있어야 한다.
// 4096 major 를 다 담는다. 512 칸(major 255)으로 잡았더니 259(nvme/blkext)가
// 255 로 접혀 들어가서 "major 255 가 98.9%" 라는 거짓 표가 나왔다.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} oh_dev SEC(".maps");

// 1차 태그: cgroup id → warrant id (§04)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} oh_tag SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct oh_warrant);
} oh_warrants SEC(".maps");

#if READ_WATCH
// 읽기 감시 목록. 키는 경로가 아니라 (dev, ino) 다 (§15). dev 는 커널 s_dev 인코딩.
struct oh_ino_key {
    __u32 dev;
    __u32 _pad;
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct oh_ino_key);
    __type(value, __u8);
} oh_watch SEC(".maps");

static __always_inline int oh_watched(struct file *file)
{
    struct oh_ino_key k = {};   // 패딩까지 0 이어야 해시가 맞는다
#if READ_WATCH == 3
    // I2. BPF_CORE_READ 는 포인터 한 단계마다 bpf_probe_read_kernel 헬퍼를 부른다
    // (아래 두 줄이면 5회). lsm 인자는 BTF 포인터라 직접 따라갈 수 있다 — 헬퍼가
    // 아니라 예외 테이블 달린 load 다. f_inode 도 한 번만 읽는다.
    // 4차에서 I 가 읽기 열기마다 ~150ns 를 낸 원인이 이것인지를 가른다.
    struct inode *inode = file->f_inode;
    k.dev = inode->i_sb->s_dev;
    k.ino = inode->i_ino;
#else
    k.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    k.ino = BPF_CORE_READ(file, f_inode, i_ino);
#endif
    return bpf_map_lookup_elem(&oh_watch, &k) != NULL;
}

// 영장 세션인가. 감시는 영장에 딸린 정책이라 무영장 세션의 읽기는 기록하지 않는다.
static __always_inline int oh_in_warrant(void)
{
    __u64 cg = bpf_get_current_cgroup_id();
    __u64 *wid = bpf_map_lookup_elem(&oh_tag, &cg);
    return wid && bpf_map_lookup_elem(&oh_warrants, wid);
}
#endif /* READ_WATCH */

#if PROBE
static __always_inline void oh_bump(__u32 k)
{
    __u64 *v = bpf_map_lookup_elem(&oh_counters, &k);
    if (v)
        (*v)++;            // PERCPU 라 원자연산이 필요 없다
}

static __always_inline __u32 oh_log2(__u64 v)
{
    __u32 r = 0, s;
#pragma unroll
    for (int i = 5; i >= 0; i--) {
        s = 1u << i;
        if (v >> s) { v >>= s; r += s; }
    }
    return r;
}

static __always_inline void oh_record(__u64 ns)
{
    __u32 k = oh_log2(ns);
    if (k >= 64)
        k = 63;
    __u64 *v = bpf_map_lookup_elem(&oh_lat, &k);
    if (v)
        (*v)++;
}
#endif /* PROBE */

// 감사 모드와 강제 모드가 공유하게 될 판정 함수의 자리다 (§15).
static __always_inline int oh_decide(struct file *file)
{
#if TIER >= 2
    // 앞문. 쓰기 의도는 전체 file_open 의 5% 남짓이라(S0) 대부분 여기서 끝난다.
    __u32 mode = BPF_CORE_READ(file, f_mode);
    if (!(mode & FMODE_WRITE)) {
#if READ_WATCH == 1
        // R: 읽기 열기 전부가 cgroup 조회까지 간다. 앞문이 읽기에는 없는 것과 같다.
        if (oh_in_warrant() && oh_watched(file))
            return OH_R_WATCH_HIT;
#elif READ_WATCH >= 2
        // I · I2: 해시 1회로 대부분 끝난다. 감시 대상일 때만 cgroup 을 탄다.
        if (oh_watched(file) && oh_in_warrant())
            return OH_R_WATCH_HIT;
#endif
        return OH_R_READ;
    }
#endif /* TIER >= 2 */

#if TIER >= 3
    // 나머지 5% 가 내는 비용: cgroup 조회 1 + 해시 조회 2 + 시간 비교 1
    __u64 cg = bpf_get_current_cgroup_id();
    __u64 *wid = bpf_map_lookup_elem(&oh_tag, &cg);
    if (!wid)
        return OH_R_TAG_MISS;              // 무영장 세션 — 감사 모드에서는 통과
    struct oh_warrant *w = bpf_map_lookup_elem(&oh_warrants, wid);
    if (!w)
        return OH_R_TAG_MISS;
    if (w->revoked)
        return OH_R_REVOKED;
    if (bpf_ktime_get_boot_ns() > w->expires_ns)
        return OH_R_EXPIRED;
    return OH_R_TAG_HIT;
#endif /* TIER >= 3 */

    (void)file;
    return OH_R_PASS;
}

SEC("lsm/file_open")
int BPF_PROG(oh_file_open, struct file *file)
{
#if PROBE
    __u64 t0 = bpf_ktime_get_ns();
#endif

    int code = oh_decide(file);

#if PROBE
    // 여기부터는 계측이다. 타이머를 먼저 닫는다.
    oh_record(bpf_ktime_get_ns() - t0);
    oh_bump(OH_C_TOTAL);
    if (code >= 0 && code < OH_R_MAX)
        oh_bump(code);

    // dev major × 읽기/쓰기. 모든 티어가 똑같이 센다 —
    // 쓰기 비중을 판정 경로에서 뽑으면 티어 B 는 그 코드가 없어서
    // 구조적 0 이 측정된 0 처럼 보인다.
    __u32 dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    __u32 mj  = OH_MAJOR(dev);
    if (mj > 4095)
        mj = 4095;
    __u32 mode = BPF_CORE_READ(file, f_mode);
    __u32 k = mj * 2 + ((mode & FMODE_WRITE) ? 1 : 0);
    __u64 *v = bpf_map_lookup_elem(&oh_dev, &k);
    if (v)
        (*v)++;
#else
    // PROBE=0 에서는 code 를 아무도 안 쓴다. 그대로 두면 clang 이
    // 판정 자체를 지워버릴 수 있다 — 그러면 티어 C·D 가 B 와 같아진다.
    asm volatile("" : : "r"(code) : "memory");
#endif

    // 스파이크 전 구간 감사 모드. 여기를 -EPERM 으로 바꾸지 말 것 (§16).
    return 0;
}
