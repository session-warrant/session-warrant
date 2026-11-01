package main

import (
	"slices"
	"strings"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// Called by run with loader.AttachedHooks; the result goes into NodeHello.attached_hooks.
// "lsm/bprm_check_security" → HOOK_BPRM_CHECK_SECURITY. The kprobe mirror folds into its lsm hook.
func hooksFromSections(sections []string) []pb.Hook {
	var hooks []pb.Hook
	for _, sec := range sections {
		_, name, ok := strings.Cut(sec, "/")
		if !ok {
			continue
		}
		name = strings.TrimPrefix(name, "security_")
		if v, known := pb.Hook_value["HOOK_"+strings.ToUpper(name)]; known {
			hooks = append(hooks, pb.Hook(v))
		}
	}
	slices.Sort(hooks)
	return slices.Compact(hooks)
}
