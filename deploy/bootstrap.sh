#!/usr/bin/env bash
# 개발 노드 부트스트랩 — BPF LSM 성립 여부 확인 + 툴체인 설치.
# 기준 Ubuntu 24.04 / 커널 6.8. 22.04 는 clang 18 을 apt.llvm.org 에서 가져온다.
#
#   ./deploy/bootstrap.sh          # 확인만
#   ./deploy/bootstrap.sh --install # 확인 + 설치

set -euo pipefail

INSTALL=0
[[ "${1:-}" == "--install" ]] && INSTALL=1

GREEN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
ok(){   printf '  %sOK  %s %s\n'   "$GREEN" "$OFF" "$1"; }
bad(){  printf '  %sNO  %s %s\n'   "$RED"   "$OFF" "$1"; FAIL=1; }
warn(){ printf '  %s??  %s %s\n'   "$YEL"   "$OFF" "$1"; }
hdr(){  printf '\n%s\n%s\n' "$1" "${1//?/─}"; }
FAIL=0

. /etc/os-release
hdr "환경"
printf '  %-22s %s %s\n' "배포판" "$PRETTY_NAME" ""
printf '  %-22s %s\n'    "커널"   "$(uname -r)"
printf '  %-22s %s\n'    "아키텍처" "$(uname -m)"

KVER=$(uname -r | cut -d. -f1,2)
KMAJ=${KVER%%.*}; KMIN=${KVER##*.}
if (( KMAJ > 6 || (KMAJ == 6 && KMIN >= 8) )); then
  ok "커널 $KVER — 기준(6.8) 충족"
elif (( KMAJ > 5 || (KMAJ == 5 && KMIN >= 7) )); then
  warn "커널 $KVER — BPF LSM 자체는 되지만 verifier 가 약하다. 6.8 권장"
  echo "     ${DIM}sudo apt install linux-generic-hwe-22.04${OFF}"
else
  bad "커널 $KVER — BPF LSM 은 5.7+ 필요"
fi

hdr "커널 설정"
CFG=/boot/config-$(uname -r)
if [[ -r $CFG ]]; then
  for c in CONFIG_BPF_LSM CONFIG_DEBUG_INFO_BTF CONFIG_BPF_SYSCALL CONFIG_FUNCTION_ERROR_INJECTION; do
    if grep -q "^${c}=y" "$CFG"; then ok "$c=y"; else
      [[ $c == CONFIG_FUNCTION_ERROR_INJECTION ]] && warn "$c 없음 (선택)" || bad "$c 없음"
    fi
  done
else
  warn "$CFG 를 읽을 수 없다 — 건너뜀"
fi

[[ -r /sys/kernel/btf/vmlinux ]] \
  && ok "/sys/kernel/btf/vmlinux 존재 (CO-RE 가능)" \
  || bad "/sys/kernel/btf/vmlinux 없음 — CO-RE 불가"

hdr "LSM 목록"
if [[ -r /sys/kernel/security/lsm ]]; then
  LSMS=$(cat /sys/kernel/security/lsm)
  printf '  %s\n' "$LSMS"
  if [[ ",$LSMS," == *",bpf,"* ]]; then
    ok "bpf 활성 — 강제 모드 가능"
  else
    bad "bpf 없음 — 강제 모드는 한 줄도 못 짠다"
    echo "     ${DIM}sudo ./deploy/enable-bpf-lsm.sh   (재부팅 필요)${OFF}"
  fi
else
  bad "securityfs 가 안 붙어 있다 — sudo mount -t securityfs none /sys/kernel/security"
fi

hdr "툴체인"
have(){ command -v "$1" >/dev/null 2>&1; }

CLANG=""
for c in clang-19 clang-18 clang; do
  if have "$c"; then
    v=$("$c" --version | head -1 | grep -oE '[0-9]+' | head -1)
    (( v >= 18 )) && { CLANG=$c; ok "$c ($v)"; break; } || warn "$c ($v) — 18+ 필요"
  fi
done
[[ -z $CLANG ]] && bad "clang 18+ 없음"

have bpftool && ok "bpftool $(bpftool version 2>/dev/null | head -1 | awk '{print $2}')" || bad "bpftool 없음"
pkg-config --exists libbpf 2>/dev/null \
  && ok "libbpf $(pkg-config --modversion libbpf)" \
  || bad "libbpf-dev 없음"
have make && ok "make" || bad "make 없음"
have bats && ok "bats" || warn "bats 없음 (bench/bypass 에 필요)"

if have go; then
  gv=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | tr -d 'go')
  ok "go $gv $( [[ $(echo "$gv" | cut -d. -f2) -ge 25 ]] || echo "${DIM}— 1.25+ 권장${OFF}" )"
else
  warn "go 없음 (warrantd 에 필요, 스파이크 단계에는 불필요)"
fi

if (( INSTALL )); then
  hdr "설치"
  PKGS=(build-essential pkg-config libelf-dev zlib1g-dev
        libbpf-dev linux-tools-common "linux-tools-$(uname -r)" bats)

  if [[ $ID == ubuntu && ${VERSION_ID%%.*} -lt 24 ]]; then
    echo "  22.04 이하 — apt.llvm.org 에서 clang 18 을 가져온다"
    sudo apt-get install -y wget gnupg lsb-release software-properties-common
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
      | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc >/dev/null
    sudo add-apt-repository -y "deb http://apt.llvm.org/$VERSION_CODENAME/ llvm-toolchain-$VERSION_CODENAME-18 main"
  fi
  PKGS+=(clang-18 llvm-18)

  sudo apt-get update
  sudo apt-get install -y "${PKGS[@]}"

  # Ubuntu 는 bpftool 을 linux-tools-<ver> 안에 넣어두고 PATH 에 안 건다
  if ! have bpftool && [[ -x /usr/lib/linux-tools/$(uname -r)/bpftool ]]; then
    sudo ln -sf "/usr/lib/linux-tools/$(uname -r)/bpftool" /usr/local/bin/bpftool
    echo "  bpftool 심볼릭 링크 생성"
  fi
  echo
  echo "  설치 완료. 다시 확인하려면: ./deploy/bootstrap.sh"
fi

hdr "결과"
if (( FAIL )); then
  echo "  ${RED}막힌 항목이 있다.${OFF} 위의 NO 를 먼저 해결할 것."
  (( INSTALL )) || echo "  설치가 필요하면: ${DIM}./deploy/bootstrap.sh --install${OFF}"
  exit 1
fi
echo "  ${GREEN}준비 완료.${OFF} 다음: ${DIM}make -C bpf smoke && sudo ./bpf/smoke${OFF}"
