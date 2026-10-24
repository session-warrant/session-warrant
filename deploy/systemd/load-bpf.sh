#!/bin/sh
# warrant-bpf.service 가 부른다. bpftool 로 warrant.bpf.o 를 올리고 pin 한다 (loader 대역).
# 맵은 warrantd 기본 -pin-dir 인 /sys/fs/bpf/warrant, 프로그램 · 링크는 /sys/fs/bpf/warrant-progs.
# 시험 하네스(bpf/wtest.sh · warrantctl)의 wtest · wmaps 와 섞이지 않게 이름을 따로 쓴다.
set -eu

OBJ=${WARRANT_BPF_OBJ:-/usr/lib/warrant/warrant.bpf.o}
MAPS=/sys/fs/bpf/warrant
PROGS=/sys/fs/bpf/warrant-progs

# Already pinned (warrantd restart, or this unit restarted): keep it. Reloading would drop tags.
if [ -e "$MAPS/cgroup_warrant" ] && [ -d "$PROGS" ]; then
    echo "warrant-bpf: already pinned at $MAPS, keeping it"
    exit 0
fi

if ! grep -qw bpf /sys/kernel/security/lsm; then
    echo "warrant-bpf: bpf is not in /sys/kernel/security/lsm — run deploy/enable-bpf-lsm.sh and reboot" >&2
    exit 1
fi

# A half-done earlier attempt would make loadall fail on existing pins.
rm -rf "$MAPS" "$PROGS"
bpftool prog loadall "$OBJ" "$PROGS" pinmaps "$MAPS" autoattach
echo "warrant-bpf: loaded $OBJ → $MAPS (maps), $PROGS (programs)"
