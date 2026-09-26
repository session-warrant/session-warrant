#include <security/_pam_types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <stdint.h>
#include <stdio.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <security/pam_appl.h> 
#include <security/pam_modules.h>
#include <sys/un.h>


#define WR_SOCKET   "/run/warrantd/pam.sock"
#define WR_CGROOT "/sys/fs/cgroup"
#define WR_LINE_MAX 2048


static const char *wr_socket_path(int argc, const char** argv)
{
    for(int i = 0; i<argc; i++){
        if(strncmp(argv[i], "socket=", 7) == 0) return argv[i] + 7;
    }
    return WR_SOCKET;
}



static void wr_send(const char* socket_path, const char* line)
{
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_DGRAM| SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    
    if(fd < 0) return;

    memset(&addr , 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if(strlen(socket_path) >= sizeof(addr.sun_path)){
        close(fd);
        return;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    sendto(fd, line, strlen(line), MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
}


static const char * wr_item(pam_handle_t * pam_handle, int itype){

    const void* v = NULL;
    if(pam_get_item(pam_handle, itype, &v) != PAM_SUCCESS || !v) return "-";

    return (const char *) v;
}

// get cgroup id by user id and session id
static unsigned long long wr_cgid(uid_t uid, const char* sid)
{
    
    char path[512];
    struct stat st;
    
    if(!sid || !*sid || uid == (uid_t) -1) return 0;

    snprintf(path, sizeof(path), WR_CGROOT "/user.slice/user-%u.slice/session-%s.scope",(unsigned)uid, sid);

    if(stat(path, &st) != 0) return 0;

    return (uint64_t) st.st_ino;
}


// get session's uid by user
static uid_t wr_uid(const char* user)
{
    struct passwd *pw;

    if(!user|| *user == '-') return (uid_t) -1;
    pw = getpwnam(user);
    return pw ? pw->pw_uid : (uid_t)-1;
}

static void wr_sanitize_field(char *str)
{
    for(; *str; str++){
        if(*str == '\t' || *str == '\n' || *str == '\r') *str = ' ';
    }
}


int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char** argv){

    char line[WR_LINE_MAX], auth[WR_LINE_MAX / 2] ;

    const char * user = wr_item(pamh, PAM_USER);
    const char * rhost = wr_item(pamh, PAM_RHOST);
    const char * sid = pam_getenv(pamh, "XDG_SESSION_ID");
    const char* auth_info;
    uid_t uid = wr_uid(user);

    (void)flags;

    auth_info = pam_getenv(pamh, "SSH_AUTH_INFO_0");
    snprintf(auth, sizeof(auth) , "%s", auth_info ? auth_info : "-");
    wr_sanitize_field(auth);

    snprintf(line, sizeof(line), "OPEN\t%s\t%llu\t%s\t%s\t%s\n",
            (sid && *sid)? sid:"-",
            wr_cgid(uid, sid),
            user,rhost,auth);
    
    wr_send(wr_socket_path(argc, argv), line);
    return PAM_SUCCESS;   
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char** argv){
    char line[WR_LINE_MAX];
    const char* sid = pam_getenv(pamh, "XDG_SESSION_ID");
    uid_t uid = wr_uid(wr_item(pamh, PAM_USER));

    (void)flags;

    snprintf(line, sizeof(line), "CLOSE\t%s\t%llu\n",
            (sid && *sid) ? sid : "-" , wr_cgid(uid, sid));
    wr_send(wr_socket_path(argc, argv), line);
    return PAM_SUCCESS;
}


int pam_sm_authenticate(pam_handle_t *p, int f, int c, const char **v)
{ (void)p; (void)f; (void)c; (void)v; return PAM_IGNORE; }
int pam_sm_setcred(pam_handle_t *p, int f, int c, const char **v)
{ (void)p; (void)f; (void)c; (void)v; return PAM_IGNORE; }
int pam_sm_acct_mgmt(pam_handle_t *p, int f, int c, const char **v)
{ (void)p; (void)f; (void)c; (void)v; return PAM_IGNORE; }
int pam_sm_chauthtok(pam_handle_t *p, int f, int c, const char **v)
{ (void)p; (void)f; (void)c; (void)v; return PAM_IGNORE; }
