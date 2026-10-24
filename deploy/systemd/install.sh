#!/bin/sh
# 노드에 warrantd 를 설치하고 켠다. 리포 최상단에서, 빌드가 끝난 뒤:
#   make -C bpf warrant.bpf.o && (cd agent && go build -o ../.cache/bin/warrantd ./cmd/warrantd)
#   sudo deploy/systemd/install.sh [-upstream 호스트:9090]
#   sudo deploy/systemd/install.sh --uninstall      # 유닛 · 바이너리 제거. pin 은 남긴다(재부팅하면 사라진다)
#
# 인자는 그대로 /etc/default/warrantd 의 WARRANTD_ARGS 가 된다. 이미 있으면 덮어쓰지 않는다.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
UNITS="warrant-bpf.service warrantd.service"

if [ "$(id -u)" != 0 ]; then
    echo "root 로 실행할 것: sudo $0 $*" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now $UNITS 2>/dev/null || true
    for u in $UNITS; do rm -f "/etc/systemd/system/$u"; done
    rm -f /usr/local/sbin/warrantd
    rm -rf /usr/lib/warrant
    systemctl daemon-reload
    echo "제거했다. /etc/default/warrantd 와 bpffs pin 은 남겼다."
    exit 0
fi

for f in "$ROOT/.cache/bin/warrantd" "$ROOT/bpf/warrant.bpf.o"; do
    [ -f "$f" ] || { echo "없다: $f — 위의 빌드 명령을 먼저" >&2; exit 1; }
done
command -v bpftool >/dev/null || { echo "bpftool 이 없다: ./deploy/bootstrap.sh --install" >&2; exit 1; }

install -m 0755 "$ROOT/.cache/bin/warrantd" /usr/local/sbin/warrantd
install -d -m 0755 /usr/lib/warrant
install -m 0644 "$ROOT/bpf/warrant.bpf.o" /usr/lib/warrant/warrant.bpf.o
install -m 0755 "$ROOT/deploy/systemd/load-bpf.sh" /usr/lib/warrant/load-bpf.sh
for u in $UNITS; do install -m 0644 "$ROOT/deploy/systemd/$u" "/etc/systemd/system/$u"; done

if [ ! -f /etc/default/warrantd ]; then
    printf '# warrantd 추가 인자. 예: -upstream central.example:9090\nWARRANTD_ARGS="%s"\n' "$*" > /etc/default/warrantd
fi

systemctl daemon-reload
systemctl enable --now $UNITS
systemctl --no-pager --lines=5 status warrantd.service || true
