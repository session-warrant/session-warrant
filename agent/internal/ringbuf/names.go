package ringbuf

// 커널이 보내는 숫자를 사람이 읽는 이름으로 바꾼다.
// 값은 proto/audit.proto 의 enum 과 같다 — 이름만 짧게 줄였다.

func HookName(h uint16) string {
	switch h {
	case HookSchedProcessFork:
		return "FORK"
	case HookBprmCheckSecurity:
		return "EXEC"
	case HookSocketConnect:
		return "CONNECT"
	case HookFileOpen:
		return "WRITE"
	case HookInodeCreate:
		return "CREATE"
	case HookInodeUnlink:
		return "UNLINK"
	case HookInodeRename:
		return "RENAME"
	case HookInodeLink:
		return "LINK"
	case HookInodeSymlink:
		return "SYMLINK"
	case HookBPF:
		return "SP:BPF"
	case HookTaskKill:
		return "SP:KILL"
	case HookSbUmount:
		return "SP:UMOUNT"
	case HookPtraceAccessCheck:
		return "SP:PTRACE"
	case HookKernelModuleReq:
		return "SP:MODULE"
	case HookSocketSendmsg:
		return "SENDMSG"
	}
	return "HOOK?"
}

// VerdictName 은 판정과 모드를 함께 본다.
// 모드를 안 보면 관찰 모드의 「막았을 것」과 강제 모드의 「막았다」가 같아 보인다.
func VerdictName(verdict, mode uint8) string {
	switch verdict {
	case 0:
		return "ALLOW"
	case 1:
		return "DENY"
	case 2:
		if mode == 0 {
			return "OBSERVE"
		}
		return "DRY-DENY"
	}
	return "?"
}

// TagSourceName 은 영장을 어느 겹에서 찾았는지다.
// task 로 찍히면 cgroup 을 벗어난 프로세스를 2차 방어선이 잡은 것이다.
func TagSourceName(t uint8) string {
	switch t {
	case 0:
		return "-"
	case 1:
		return "cg"
	case 2:
		return "task"
	}
	return "?"
}

func OriginName(o uint8) string {
	switch o {
	case 1:
		return "lsm"
	case 2:
		return "kprobe"
	case 3:
		return "agent"
	}
	return "?"
}

func OpName(op uint8) string {
	switch op {
	case 1:
		return "create"
	case 2:
		return "unlink"
	case 3:
		return "rename"
	case 4:
		return "link"
	case 5:
		return "symlink"
	}
	return "?"
}
