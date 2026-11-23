// S4 — fanotify 가 inode 교체를 실제로 알려주는가 (§15)
//
// 알려주는지, 언제 알려주는지만 본다. 맵 갱신은 warrantd 가 할 일이다.
//
// 왜 inotify 가 아니라 fanotify 인가: inotify 는 디렉터리마다 watch 를 걸어야
// 하고 재귀도 직접 해야 한다. fanotify 는 FAN_MARK_FILESYSTEM 으로 파일시스템
// 하나를 통째로 볼 수 있고, 이게 /usr 전체를 감시해야 하는 이 용도에 맞는다.
// 대신 CAP_SYS_ADMIN 이 필요하다 — warrantd 는 어차피 root 다.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t iw_stop;
static void iw_sig(int s) { (void)s; iw_stop = 1; }

// Watched prefixes and an open dir on each one's filesystem, for open_by_handle_at.
#define IW_MAX 16
static char iw_prefix[IW_MAX][PATH_MAX];
static int iw_mntfd[IW_MAX];
static int iw_n;

// Called per event: parent handle -> current path of that directory, or 0 when it is gone.
static int iw_resolve(struct file_handle *fh, char *out, size_t n)
{
    for (int i = 0; i < iw_n; i++) {
        int fd = open_by_handle_at(iw_mntfd[i], fh, O_PATH);
        if (fd < 0)
            continue;
        char link[64];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t l = readlink(link, out, n - 1);
        close(fd);
        if (l > 0) {
            out[l] = 0;
            return 1;
        }
    }
    return 0;
}

static int iw_watched(const char *path)
{
    for (int i = 0; i < iw_n; i++) {
        size_t l = strlen(iw_prefix[i]);
        if (strncmp(path, iw_prefix[i], l) == 0 && (path[l] == 0 || path[l] == '/'))
            return 1;
    }
    return 0;
}

static unsigned long long iw_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (unsigned long long)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

// 한 이벤트에 여러 비트가 켜질 수 있다.
static void iw_mask(unsigned long long m, char *out, size_t n)
{
    struct { unsigned long long bit; const char *name; } tbl[] = {
        { FAN_CREATE,      "CREATE"     },
        { FAN_DELETE,      "DELETE"     },
        { FAN_MOVED_FROM,  "MOVED_FROM" },
        { FAN_MOVED_TO,    "MOVED_TO"   },
        { FAN_MODIFY,      "MODIFY"     },
        { FAN_ATTRIB,      "ATTRIB"     },
        { FAN_DELETE_SELF, "DELETE_SELF"},
        { FAN_MOVE_SELF,   "MOVE_SELF"  },
        { FAN_ONDIR,       "ONDIR"      },
    };
    out[0] = 0;
    size_t used = 0;
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (!(m & tbl[i].bit))
            continue;
        int w = snprintf(out + used, n - used, "%s%s", used ? "|" : "", tbl[i].name);
        if (w < 0 || (size_t)w >= n - used)
            break;
        used += (size_t)w;
    }
    if (!out[0])
        snprintf(out, n, "0x%llx", m);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage: inowatch <감시대상> [...]\n"
            "  각 경로가 속한 파일시스템 전체를 감시하고(FAN_MARK_FILESYSTEM),\n"
            "  그 경로 아래 이벤트만 path= 로 찍는다.\n");
        return 2;
    }

    // No SA_RESTART: read() must return EINTR so the loop sees iw_stop.
    struct sigaction sa = { .sa_handler = iw_sig };
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // FAN_REPORT_DFID_NAME: 이벤트에 부모 디렉터리 file_handle 과 이름이 실린다.
    // 5.9+ 필요. 이게 없으면 "무언가 바뀌었다"만 알고 무엇인지 모른다.
    int fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR: fanotify_init: %s\n", strerror(errno));
        if (errno == EPERM)
            fprintf(stderr, "       root 로 돌려야 한다 (CAP_SYS_ADMIN).\n");
        if (errno == EINVAL)
            fprintf(stderr, "       FAN_REPORT_DFID_NAME 은 커널 5.9+ 다.\n");
        return 1;
    }

    // 디렉터리 자체의 교체(DELETE_SELF · MOVE_SELF)도 본다 — 금지 목록은
    // 디렉터리 inode 로 걸리므로(§15) 그게 갈리면 금지가 통째로 무효가 된다.
    unsigned long long mask = FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM |
                              FAN_MOVED_TO | FAN_MODIFY | FAN_ATTRIB |
                              FAN_DELETE_SELF | FAN_MOVE_SELF | FAN_ONDIR;

    // A directory mark only sees direct children, so always mark the whole filesystem
    // and keep events under the given paths (2026-11-15: lab/bin/* came back 0).
    for (int i = 1; i < argc && iw_n < IW_MAX; i++) {
        if (!realpath(argv[i], iw_prefix[iw_n])) {
            fprintf(stderr, "ERROR: realpath %s: %s\n", argv[i], strerror(errno));
            return 1;
        }
        iw_mntfd[iw_n] = open(iw_prefix[iw_n], O_RDONLY | O_DIRECTORY);
        if (iw_mntfd[iw_n] < 0 ||
            fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, AT_FDCWD, iw_prefix[iw_n]) < 0) {
            fprintf(stderr, "ERROR: mark %s: %s\n", argv[i], strerror(errno));
            return 1;
        }
        printf("MARK %s (filesystem)\n", iw_prefix[iw_n]);
        iw_n++;
    }

    printf("READY\n");
    fflush(stdout);

    char buf[8192];
    while (!iw_stop) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        unsigned long long t = iw_now_us();

        struct fanotify_event_metadata *m = (struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(m, n)) {
            char ms[192];
            iw_mask(m->mask, ms, sizeof(ms));

            // DFID_NAME carries the parent handle + name; DFID (self events) the dir itself.
            const char *name = "";
            struct file_handle *fh = NULL;
            struct fanotify_event_info_header *h =
                (struct fanotify_event_info_header *)(m + 1);
            char *end = (char *)m + m->event_len;
            while ((char *)h + sizeof(*h) <= end && h->len > 0) {
                if (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME ||
                    h->info_type == FAN_EVENT_INFO_TYPE_DFID ||
                    h->info_type == FAN_EVENT_INFO_TYPE_FID) {
                    struct fanotify_event_info_fid *fid =
                        (struct fanotify_event_info_fid *)h;
                    fh = (struct file_handle *)fid->handle;
                    if (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME)
                        name = (const char *)fh->f_handle + fh->handle_bytes;
                    break;
                }
                h = (struct fanotify_event_info_header *)((char *)h + h->len);
            }

            char dir[PATH_MAX], path[PATH_MAX + NAME_MAX + 2];
            if (fh && iw_resolve(fh, dir, sizeof(dir))) {
                snprintf(path, sizeof(path), "%s%s%s", dir, name[0] ? "/" : "", name);
                if (iw_watched(path)) {
                    printf("EV us=%llu mask=%s path=%s\n", t, ms, path);
                    fflush(stdout);
                }
            }
            if (m->fd >= 0)
                close(m->fd);
            m = FAN_EVENT_NEXT(m, n);
        }
    }
    close(fd);
    printf("STOPPED\n");
    return 0;
}
