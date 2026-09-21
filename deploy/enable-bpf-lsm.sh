#!/usr/bin/env bash
# lsm= 부팅 파라미터에 bpf 를 추가한다. 재부팅이 필요하다.
#
# 핵심: lsm=bpf 만 단독으로 넣으면 AppArmor 가 빠지면서 부팅이 깨질 수 있다.
#       그래서 지금 실제로 떠 있는 목록(/sys/kernel/security/lsm)을 읽어
#       거기에 ,bpf 만 덧붙인다.
#
#   sudo ./deploy/enable-bpf-lsm.sh          # 무엇을 바꿀지 보여주고 물어본다
#   sudo ./deploy/enable-bpf-lsm.sh --yes    # 묻지 않는다

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "root 로 실행할 것: sudo $0"; exit 1; }
ASSUME_YES=0; [[ "${1:-}" == "--yes" ]] && ASSUME_YES=1

CUR=$(cat /sys/kernel/security/lsm 2>/dev/null) || {
  echo "/sys/kernel/security/lsm 을 읽을 수 없다."
  echo "securityfs 가 안 붙었을 수 있다: mount -t securityfs none /sys/kernel/security"
  exit 1
}
echo "현재 LSM: $CUR"

if [[ ",$CUR," == *",bpf,"* ]]; then
  echo "bpf 가 이미 활성이다. 할 일 없음."
  exit 0
fi

NEW="$CUR,bpf"
GRUB=/etc/default/grub

if [[ -f $GRUB ]]; then
  # ── Debian/Ubuntu ────────────────────────────────────────────────
  LINE=$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB" || true)
  [[ -n $LINE ]] || { echo "GRUB_CMDLINE_LINUX_DEFAULT 를 못 찾았다. 수동으로 편집할 것."; exit 1; }

  if [[ $LINE == *lsm=* ]]; then
    UPDATED=$(sed -E 's/(lsm=[^ "]*)/\1,bpf/' <<<"$LINE")
  else
    # 없으면 커널이 알려준 현재 목록 전체 + bpf 를 넣는다
    UPDATED=$(sed -E "s/^(GRUB_CMDLINE_LINUX_DEFAULT=\")(.*)(\")$/\1\2 lsm=$NEW\3/" <<<"$LINE")
  fi

  echo
  echo "  이전: $LINE"
  echo "  이후: $UPDATED"
  echo

  if (( ! ASSUME_YES )); then
    read -rp "적용할까? [y/N] " a
    [[ $a == [yY] ]] || { echo "취소."; exit 0; }
  fi

  BAK="$GRUB.bak.$(date +%Y%m%d%H%M%S)"
  cp -a "$GRUB" "$BAK"
  echo "백업: $BAK"

  # 라인 전체 치환. sed 구분자 충돌을 피하려고 파이썬을 쓴다
  python3 - "$GRUB" "$LINE" "$UPDATED" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert old in s, "원본 라인을 찾지 못했다"
open(p, 'w').write(s.replace(old, new, 1))
PY

  update-grub
  echo
  echo "완료. 재부팅 후 확인:"
  echo "  cat /sys/kernel/security/lsm     # bpf 가 보여야 한다"
  echo
  echo "부팅이 깨지면 GRUB 메뉴에서 e 를 눌러 lsm=... 부분을 지우고 부팅한 뒤"
  echo "  cp $BAK $GRUB && update-grub"

elif command -v grubby >/dev/null; then
  # ── RHEL/Rocky ───────────────────────────────────────────────────
  echo "  grubby --update-kernel=ALL --args=\"lsm=$NEW\""
  if (( ! ASSUME_YES )); then
    read -rp "적용할까? [y/N] " a
    [[ $a == [yY] ]] || { echo "취소."; exit 0; }
  fi
  grubby --update-kernel=ALL --args="lsm=$NEW"
  echo "완료. 재부팅 후 cat /sys/kernel/security/lsm 확인."
else
  echo "grub 도 grubby 도 없다. 부트로더 설정을 수동으로 편집할 것: lsm=$NEW"
  exit 1
fi
