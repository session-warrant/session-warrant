package main

import (
	"fmt"
	"log"
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

// Called by run after AttachAll. A missing kprobe mirror only loses the cross-check;
// any other gap means a hook (maybe self-protection) is not running, so warrantd stops (§16).
func checkAttached(attached, missingMirrors []string, total int) error {
	if len(attached)+len(missingMirrors) != total {
		return fmt.Errorf("attach: %d of %d programs", len(attached), total)
	}
	for _, m := range missingMirrors {
		log.Printf("warrantd: mirror not attached, lsm verdict only: %s", m)
	}
	return nil
}
