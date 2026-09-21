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
            "  경로가 마운트포인트면 그 파일시스템 전체(FAN_MARK_FILESYSTEM),\n"
            "  아니면 그 디렉터리만(FAN_MARK_ADD) 감시한다.\n");
        return 2;
    }

    signal(SIGINT, iw_sig);
    signal(SIGTERM, iw_sig);

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

    for (int i = 1; i < argc; i++) {
        // 마운트포인트면 파일시스템 전체를 잡는다.
        struct stat st, pst;
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%s/..", argv[i]);
        unsigned int flags = FAN_MARK_ADD;
        if (stat(argv[i], &st) == 0 && stat(parent, &pst) == 0 &&
            st.st_dev != pst.st_dev)
            flags |= FAN_MARK_FILESYSTEM;

        if (fanotify_mark(fd, flags, mask, AT_FDCWD, argv[i]) < 0) {
            fprintf(stderr, "ERROR: mark %s: %s\n", argv[i], strerror(errno));
            return 1;
        }
        printf("MARK %s %s\n", argv[i],
               (flags & FAN_MARK_FILESYSTEM) ? "(filesystem)" : "(directory)");
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

            // 이름은 info 레코드에 붙어 온다. DFID_NAME 이면 부모 handle + 이름.
            const char *name = "-";
            struct fanotify_event_info_header *h =
                (struct fanotify_event_info_header *)(m + 1);
            char *end = (char *)m + m->event_len;
            while ((char *)h + sizeof(*h) <= end && h->len > 0) {
                if (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                    struct fanotify_event_info_fid *fid =
                        (struct fanotify_event_info_fid *)h;
                    struct file_handle *fh = (struct file_handle *)fid->handle;
                    name = (const char *)fh->f_handle + fh->handle_bytes;
                    break;
                }
                h = (struct fanotify_event_info_header *)((char *)h + h->len);
            }

            printf("EV us=%llu mask=%s name=%s\n", t, ms, name);
            fflush(stdout);
            m = FAN_EVENT_NEXT(m, n);
        }
    }
    close(fd);
    printf("STOPPED\n");
    return 0;
}
