// S3 — PAM 스택에서 session scope 가 확정되는 타이밍 (§11 T1)
//
// "pam_systemd.so 뒤에 놓으면 session-N.scope 가 이미 있다"는 가정을 잰다.
// 아무것도 안 막고, 아무것도 안 바꾸고, 한 줄 기록하고 PAM_SUCCESS 로 끝난다.
//
// sshd 주소 공간에서 도는 코드의 규칙 (pam/README.md):
//   - 모든 실패 경로가 PAM_SUCCESS 로 끝난다. 로그인을 막지 않는다.
//   - malloc 을 쓰지 않는다. 고정 버퍼 + snprintf 만.
//   - 블로킹 금지. 폴링에 상한을 두고, 넘으면 그냥 통과.
//   - 200줄 이내.

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>   // pam_getenv 는 여기 선언돼 있다 (pam_modules.h 아님)

#define WP_LOG      "/run/warrant-pamprobe.log"
#define WP_CGROOT   "/sys/fs/cgroup"
#define WP_WAIT_MS  200      // 상한. 넘으면 포기하고 통과시킨다
#define WP_STEP_US  500

// 한 번의 write() 로 끝낸다. PIPE_BUF(4096) 아래면 append 가 섞이지 않는다.
static void wp_emit(const char *line)
{
    int fd = open(WP_LOG, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    (void)!write(fd, line, strlen(line));
    close(fd);
}

static unsigned long wp_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (unsigned long)ts.tv_sec * 1000000UL + (unsigned long)(ts.tv_nsec / 1000);
}

// /proc/self/cgroup 의 "0::/..." 줄. PAM 모듈은 sshd 프로세스 안에서 돈다 —
// logind 가 CreateSession 때 그 프로세스를 scope 로 옮기므로, 이 값이
// session-N.scope 면 이미 이관이 끝난 것이다.
static int wp_proc_cgroup(char *out, size_t n)
{
    int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    char buf[512];
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0)
        return -1;
    buf[r] = 0;
    char *p = strstr(buf, "0::");
    if (!p)
        return -1;
    p += 3;
    char *e = strchr(p, '\n');
    if (e)
        *e = 0;
    snprintf(out, n, "%s", p);
    return 0;
}

// cgroup id = cgroup 디렉터리의 inode 번호. bpf_get_current_cgroup_id() 가
// 돌려주는 kn->id 와 같은 값이다 (cgroup v2).
static unsigned long long wp_cgid(const char *rel)
{
    char path[512];
    struct stat st;
    snprintf(path, sizeof(path), WP_CGROOT "%s", rel);
    if (stat(path, &st) != 0)
        return 0;
    return (unsigned long long)st.st_ino;
}

static const char *wp_item(pam_handle_t *pamh, int item)
{
    const void *v = NULL;
    if (pam_get_item(pamh, item, &v) != PAM_SUCCESS || !v)
        return "-";
    return (const char *)v;
}

static void wp_record(pam_handle_t *pamh, const char *phase, int wait_ms)
{
    char line[2048], proc_cg[512] = "-", scope[512] = "-";
    const char *user = wp_item(pamh, PAM_USER);
    const char *sid  = pam_getenv(pamh, "XDG_SESSION_ID");
    unsigned long long proc_id = 0, scope_id = 0;
    uid_t uid = (uid_t)-1;
    int present_t0 = 0;
    unsigned long t0 = wp_now_us(), waited = 0;

    struct passwd *pw = (user && *user != '-') ? getpwnam(user) : NULL;
    if (pw)
        uid = pw->pw_uid;

    // 경로 둘을 따로 구한다.
    //   (a) /proc/self/cgroup  — sshd 가 이미 scope 안에 있는가
    //   (b) XDG_SESSION_ID 로 조립한 경로 — 제품이 실제로 쓸 방법 (§11 T1)
    // 둘이 어긋나면 어긋난 사실 자체가 결과다. 한쪽만 보면 모른다.
    if (sid && *sid && uid != (uid_t)-1)
        snprintf(scope, sizeof(scope),
                 "/user.slice/user-%u.slice/session-%s.scope", (unsigned)uid, sid);

    if (wp_proc_cgroup(proc_cg, sizeof(proc_cg)) == 0)
        proc_id = wp_cgid(proc_cg);
    if (scope[0] == '/')
        scope_id = wp_cgid(scope);
    present_t0 = (scope_id != 0);

    // 없으면 상한까지 기다려 본다. 이 대기 시간이 곧 태깅 공백이다 —
    // 제품이 여기서 못 읽으면 warrantd 가 cgroup 트리를 순회해야 한다.
    for (int i = 0; !scope_id && scope[0] == '/' && i < wait_ms * 1000 / WP_STEP_US; i++) {
        usleep(WP_STEP_US);
        scope_id = wp_cgid(scope);
    }
    if (!present_t0 && scope_id)
        waited = wp_now_us() - t0;

    time_t wall = time(NULL);
    struct tm tm;
    char ts[32] = "-";
    if (localtime_r(&wall, &tm))
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

    snprintf(line, sizeof(line),
             "ts=%s boot_us=%lu phase=%s service=%s user=%s uid=%d rhost=%s "
             "xdg_session_id=%s proc_cgroup=%s proc_cgid=%llu "
             "scope=%s scope_cgid=%llu present_t0=%s waited_us=%lu match=%s\n",
             ts, t0, phase, wp_item(pamh, PAM_SERVICE), user, (int)uid,
             wp_item(pamh, PAM_RHOST),
             (sid && *sid) ? sid : "-", proc_cg, proc_id,
             scope, scope_id, present_t0 ? "yes" : "no", waited,
             (proc_id && proc_id == scope_id) ? "yes" : "no");
    wp_emit(line);
}

// PAM 진입점. 로그인을 막는 반환은 없다.

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int wait_ms = WP_WAIT_MS;
    for (int i = 0; i < argc; i++)
        if (strncmp(argv[i], "wait_ms=", 8) == 0)
            wait_ms = atoi(argv[i] + 8);
    (void)flags;
    wp_record(pamh, "open_session", wait_ms);
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    // §11 T4 — 세션 종료로 scope 가 사라지는 시점. 여기서 아직 살아 있으면
    // 엔트리 정리를 close_session 에 걸 수 있다는 뜻이다.
    wp_record(pamh, "close_session", 0);
    return PAM_SUCCESS;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    // §11 T1 은 account 단계에서 영장 유무를 확인한다. 그 시점에 scope 가
    // 아직 없다는 걸 기록으로 남긴다 — 있으면 설계를 당길 수 있다.
    wp_record(pamh, "acct_mgmt", 0);
    return PAM_SUCCESS;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{ (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_IGNORE; }

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{ (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS; }
