package io.seswar.warrant.domain.audit;

/** 감사 이벤트 종류. */
public enum AuditEventType {

    /** bprm_check_security. 실행된 프로세스 — 이것이 <b>1급 증거</b>다. */
    EXEC,

    /** socket_connect. AF_UNIX 도 여기로 온다 (sun_path 검사 결과 포함). */
    CONNECT,

    /** file_open (쓰기). 허용 건은 집계로 대체하고 차단만 전건 기록한다. */
    FILE_WRITE,

    /** inode_create · unlink · rename · link · symlink. */
    INODE_MUTATE,

    /** socket_sendmsg. 영장에 UDP 플래그가 있을 때만 온다. */
    UDP_SEND,

    /** 자기 보호 6종에 걸린 시도. <b>전건 기록 + 즉시 경보</b>. */
    SELF_PROTECTION_HIT,

    /** 영장 없이 성공한 세션. 도입 2단계의 주력 데이터(§07 STEP 2). */
    UNWARRANTED_SESSION,

    /** 위임 요청 자체 — 막지는 못해도 보이기는 한다(§18). */
    DELEGATION_ATTEMPT,

    /** bash readline uprobe 로 잡은 명령줄. <b>보조 증거일 뿐</b>이다(§14). */
    SHELL_COMMAND_LINE
}
