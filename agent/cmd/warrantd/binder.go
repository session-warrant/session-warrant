package main

import (
	"context"
	"log"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pamsock"
)

type binder struct {
	maps *bpfmap.Maps
}

var _ pamsock.Binder = (*binder)(nil)

func (b *binder) Bind(ctx context.Context, r pamsock.Request) (uint64, error) {

	fp, err := pamsock.Fingerprint(r.AuthInfo)

	if err != nil {
		log.Printf("binder: fingerprint cgroup %d account %q: %v", r.CgroupID, r.LoginAccount, err)
		fp = ""
	}
	reason := "NO_WARRANT"
	if fp == "" {
		reason = "NO_KEY"
	}
	log.Printf("binder: unwarranted session reason=%s cgroup=%d session=%q account=%q rhost=%q key=%q",
		reason, r.CgroupID, r.SessionID, r.LoginAccount, r.RHost, fp)

	return 0, nil
}

func (b *binder) Unbind(ctx context.Context, cgroupID uint64) error {
	return b.maps.UntagCgroup(cgroupID)
}
