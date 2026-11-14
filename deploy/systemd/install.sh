#!/bin/sh
# 노드에 warrantd 를 설치하고 켠다. 리포 최상단에서, 빌드가 끝난 뒤:
#   make -C bpf warrant.bpf.o && (cd agent && go build -o ../.cache/bin/warrantd ./cmd/warrantd)
#   sudo deploy/systemd/install.sh [-upstream 호스트:9090 -tls-cert … -tls-key … -tls-ca …]   (mTLS: deploy/README.md)
#   sudo deploy/systemd/install.sh --uninstall      # 유닛 · 바이너리 제거. pin 은 남긴다(재부팅하면 사라진다)
#
# 인자는 그대로 /etc/default/warrantd 의 WARRANTD_ARGS 가 된다. 이미 있으면 덮어쓰지 않는다.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
UNIT=warrantd.service

if [ "$(id -u)" != 0 ]; then
    echo "root 로 실행할 것: sudo $0 $*" >&2
    exit 1
fi

# Before warrantd had a loader, warrant-bpf.service pinned links in warrant-progs. loader looks in
# warrant/links, so leaving them would hang a second copy of every program on every hook.
remove_bpftool_install() {
    systemctl disable --now warrant-bpf.service 2>/dev/null || true
    rm -f /etc/systemd/system/warrant-bpf.service /usr/lib/warrant/load-bpf.sh
    if [ -d /sys/fs/bpf/warrant-progs ]; then
        systemctl stop "$UNIT" 2>/dev/null || true
        rm -rf /sys/fs/bpf/warrant-progs /sys/fs/bpf/warrant
        echo "옛 bpftool pin 을 지웠다 (warrant-progs · warrant)"
    fi
}

if [ "${1:-}" = "--uninstall" ]; then
    remove_bpftool_install
    systemctl disable --now "$UNIT" 2>/dev/null || true
    rm -f "/etc/systemd/system/$UNIT"
    rm -f /usr/local/sbin/warrantd
    rm -rf /usr/lib/warrant
    systemctl daemon-reload
    echo "제거했다. /etc/default/warrantd 와 bpffs pin 은 남겼다."
    exit 0
fi

for f in "$ROOT/.cache/bin/warrantd" "$ROOT/bpf/warrant.bpf.o"; do
    [ -f "$f" ] || { echo "없다: $f — 위의 빌드 명령을 먼저" >&2; exit 1; }
done
remove_bpftool_install

install -m 0755 "$ROOT/.cache/bin/warrantd" /usr/local/sbin/warrantd
install -d -m 0755 /usr/lib/warrant
install -m 0644 "$ROOT/bpf/warrant.bpf.o" /usr/lib/warrant/warrant.bpf.o
install -m 0644 "$ROOT/deploy/systemd/$UNIT" "/etc/systemd/system/$UNIT"

if [ ! -f /etc/default/warrantd ]; then
    printf '# warrantd 추가 인자. 예: -upstream central.example:9090\nWARRANTD_ARGS="%s"\n' "$*" > /etc/default/warrantd
fi

systemctl daemon-reload
systemctl enable "$UNIT"
systemctl restart "$UNIT"
systemctl --no-pager --lines=5 status "$UNIT" || true
