package main

import (
	"slices"
	"testing"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// 제품 오브젝트의 SEC 이름 15개 전부. kprobe 미러는 lsm/file_open 과 같은 훅이라 14개로 합쳐진다.
func TestHooksFromSectionsCoversEveryProductHook(t *testing.T) {
	got := hooksFromSections([]string{
		"kprobe/security_file_open",
		"lsm/bpf",
		"lsm/bprm_check_security",
		"lsm/file_open",
		"lsm/inode_create",
		"lsm/inode_link",
		"lsm/inode_rename",
		"lsm/inode_symlink",
		"lsm/inode_unlink",
		"lsm/kernel_module_request",
		"lsm/ptrace_access_check",
		"lsm/sb_umount",
		"lsm/socket_connect",
		"lsm/task_kill",
		"tp_btf/sched_process_fork",
	})

	want := []pb.Hook{
		pb.Hook_HOOK_SCHED_PROCESS_FORK,
		pb.Hook_HOOK_BPRM_CHECK_SECURITY,
		pb.Hook_HOOK_SOCKET_CONNECT,
		pb.Hook_HOOK_FILE_OPEN,
		pb.Hook_HOOK_INODE_CREATE,
		pb.Hook_HOOK_INODE_UNLINK,
		pb.Hook_HOOK_INODE_RENAME,
		pb.Hook_HOOK_INODE_LINK,
		pb.Hook_HOOK_INODE_SYMLINK,
		pb.Hook_HOOK_BPF,
		pb.Hook_HOOK_TASK_KILL,
		pb.Hook_HOOK_SB_UMOUNT,
		pb.Hook_HOOK_PTRACE_ACCESS_CHECK,
		pb.Hook_HOOK_KERNEL_MODULE_REQUEST,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("hooks =\n %v\nwant\n %v", got, want)
	}
}

// proto 에 없는 훅은 빼고 나머지만 보고한다. 알 수 없는 훅 하나로 노드 등록이 깨지면 안 된다.
func TestHooksFromSectionsSkipsUnknownSections(t *testing.T) {
	got := hooksFromSections([]string{"lsm/not_in_proto", "lsm/bpf", "noslash"})
	if !slices.Equal(got, []pb.Hook{pb.Hook_HOOK_BPF}) {
		t.Fatalf("hooks = %v, want [HOOK_BPF]", got)
	}
}
