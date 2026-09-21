#!/usr/bin/env bash
# S4 — 어느 시점에 (dev, ino) 가 바뀌는가
#
#   sudo ./cases.sh                 기본 세트
#   sudo ./cases.sh --with-apt      실제 패키지 재설치 포함 (네트워크 필요)
#   sudo ./cases.sh --out out/xxx
#
# 재는 건 둘이다: ① 조작이 (dev, ino) 를 바꾸는가 ② fanotify 가 그걸 알려주는가.
# ②가 더 중요하다 — 놓치는 게 문제다. 허용(파일 inode)과 금지(디렉터리 inode)를
# 나눠 본다 (§15).

set -euo pipefail
cd "$(dirname "$0")"

WITH_APT=0
OUT="out/$(date +%Y%m%d-%H%M%S)"
APT_PKG=${SW_APT_PKG:-jq}

while [[ $# -gt 0 ]]; do
    case $1 in
        --with-apt) WITH_APT=1; shift ;;
        --out)      OUT=$2; shift 2 ;;
        *) echo "알 수 없는 인자: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "ERROR: root 로 돌려야 한다 (fanotify CAP_SYS_ADMIN)." >&2; exit 1; }
[[ -x ./inowatch ]] || { echo "ERROR: 빌드가 안 돼 있다. make" >&2; exit 1; }

mkdir -p "$OUT"
LAB=$(mktemp -d /tmp/s4lab.XXXXXX)
trap 'rm -rf "$LAB"' EXIT

CSV="$OUT/cases.csv"
WLOG="$OUT/fanotify.log"
echo "case,target,kind,dev_before,ino_before,dev_after,ino_after,changed,fanotify" > "$CSV"

{
    echo "kernel   $(uname -r)"
    echo "distro   $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "fs       $(findmnt -no FSTYPE / ) (/) · $(findmnt -no FSTYPE /usr 2>/dev/null || echo '= /')"
    echo "lab      $LAB ($(findmnt -no FSTYPE -T "$LAB"))"
    echo "date     $(date -Is)"
} | tee "$OUT/env.txt"
echo

# /usr 는 실제 패키지 교체용, 랩은 조작을 통제된 조건에서 재현하기 위한 것이다.
./inowatch "$LAB" /usr >"$WLOG" 2>&1 &
WPID=$!
for _ in $(seq 100); do
    grep -q '^READY' "$WLOG" 2>/dev/null && break
    kill -0 "$WPID" 2>/dev/null || { cat "$WLOG" >&2; exit 1; }
    sleep 0.1
done
grep -q '^READY' "$WLOG" || { echo "ERROR: inowatch READY 타임아웃" >&2; cat "$WLOG" >&2; exit 1; }
trap 'kill -INT "$WPID" 2>/dev/null || true; wait "$WPID" 2>/dev/null || true; rm -rf "$LAB"' EXIT

devino() { stat -c '%d %i' "$1" 2>/dev/null || echo "0 0"; }

# case <이름> <대상경로> <kind: allow|deny> <조작...>
#   allow — 허용 목록이 걸리는 자리(파일 inode)
#   deny  — 금지 목록이 걸리는 자리(디렉터리 inode)
run_case() {
    local name=$1 target=$2 kind=$3; shift 3
    local before after b_dev b_ino a_dev a_ino changed fan mark

    mark=$(wc -l < "$WLOG")
    before=$(devino "$target"); read -r b_dev b_ino <<< "$before"

    if ! "$@" >/dev/null 2>&1; then
        printf '  %-28s %s\n' "$name" "건너뜀 (조작 실패)"
        return 0
    fi
    sync; sleep 0.3   # fanotify 이벤트가 도착할 시간

    after=$(devino "$target"); read -r a_dev a_ino <<< "$after"
    [[ "$b_dev $b_ino" == "$a_dev $a_ino" ]] && changed=no || changed=yes

    fan=$(tail -n +$((mark + 1)) "$WLOG" | grep -c '^EV ' || true)

    printf '  %-28s inode %-8s fanotify %s건\n' "$name" "$changed" "$fan"
    echo "$name,$target,$kind,$b_dev,$b_ino,$a_dev,$a_ino,$changed,$fan" >> "$CSV"
}

mkdir -p "$LAB/bin" "$LAB/etc" "$LAB/log"
printf '#!/bin/sh\necho v1\n' > "$LAB/bin/tool"; chmod 755 "$LAB/bin/tool"
printf 'key=1\n' > "$LAB/etc/conf"
printf 'line1\n' > "$LAB/log/app.log"

echo "── 허용 목록(파일 inode)이 무효가 되는가 ──────────────────────"

# 편집기 기본 동작. vim 은 backupcopy=auto 라 대개 새 파일 쓰고 rename 한다.
run_case "vim 저장(rename 방식)" "$LAB/etc/conf" allow \
    sh -c "printf 'key=2\n' > '$LAB/etc/.conf.swp' && mv '$LAB/etc/.conf.swp' '$LAB/etc/conf'"

# backupcopy=yes. 같은 inode 에 덮어쓴다.
run_case "편집기 제자리 덮어쓰기" "$LAB/etc/conf" allow \
    sh -c "printf 'key=3\n' > '$LAB/etc/conf'"

run_case "sed -i" "$LAB/etc/conf" allow \
    sed -i 's/key=3/key=4/' "$LAB/etc/conf"

run_case "cp 덮어쓰기" "$LAB/bin/tool" allow \
    sh -c "printf '#!/bin/sh\necho v2\n' > '$LAB/bin/.new' && cp '$LAB/bin/.new' '$LAB/bin/tool'"

run_case "mv 덮어쓰기" "$LAB/bin/tool" allow \
    sh -c "printf '#!/bin/sh\necho v3\n' > '$LAB/bin/.new2' && mv '$LAB/bin/.new2' '$LAB/bin/tool'"

run_case "install(1)" "$LAB/bin/tool" allow \
    sh -c "printf '#!/bin/sh\necho v4\n' > '$LAB/bin/.new3' && install -m755 '$LAB/bin/.new3' '$LAB/bin/tool'"

run_case "unlink 후 재생성" "$LAB/bin/tool" allow \
    sh -c "rm -f '$LAB/bin/tool' && printf '#!/bin/sh\necho v5\n' > '$LAB/bin/tool' && chmod 755 '$LAB/bin/tool'"

run_case "chmod (내용 그대로)" "$LAB/bin/tool" allow \
    chmod 750 "$LAB/bin/tool"

run_case "truncate + 재기록" "$LAB/bin/tool" allow \
    sh -c ": > '$LAB/bin/tool' && printf '#!/bin/sh\necho v6\n' >> '$LAB/bin/tool'"

# 심볼릭 링크 갈아끼우기. /usr/bin/python3 → python3.12 같은 경로다.
ln -sfn "$LAB/bin/tool" "$LAB/bin/link"
run_case "심링크 대상 교체" "$LAB/bin/link" allow \
    sh -c "printf '#!/bin/sh\necho other\n' > '$LAB/bin/tool2' && chmod 755 '$LAB/bin/tool2' && ln -sfn '$LAB/bin/tool2' '$LAB/bin/link'"

echo
echo "── logrotate 두 방식 ──────────────────────────────────────────"

run_case "logrotate copytruncate" "$LAB/log/app.log" allow \
    sh -c "cp '$LAB/log/app.log' '$LAB/log/app.log.1' && : > '$LAB/log/app.log'"

run_case "logrotate create(기본)" "$LAB/log/app.log" allow \
    sh -c "mv '$LAB/log/app.log' '$LAB/log/app.log.2' && : > '$LAB/log/app.log'"

echo
echo "── 금지 목록(디렉터리 inode)이 무효가 되는가 ──────────────────"

run_case "디렉터리 안 파일 생성" "$LAB/etc" deny \
    sh -c "printf 'x\n' > '$LAB/etc/added'"

run_case "디렉터리 안 파일 mv 후 재생성" "$LAB/etc" deny \
    sh -c "mv '$LAB/etc/conf' '$LAB/etc/conf.bak' && printf 'key=9\n' > '$LAB/etc/conf'"

# 이게 금지 목록을 뚫는 경로다 — 디렉터리 자체를 갈아치운다.
run_case "디렉터리 자체 교체" "$LAB/etc" deny \
    sh -c "mkdir -p '$LAB/etc.new' && cp -a '$LAB/etc/.' '$LAB/etc.new/' && rm -rf '$LAB/etc' && mv '$LAB/etc.new' '$LAB/etc'"

echo
echo "── (dev, ino) 가 우회를 막는가 — 문서의 주장 검증 ─────────────"

# §15 주장: bind mount 우회는 경로 비교로는 뚫리지만 (dev, ino) 로는 안 뚫린다.
mkdir -p "$LAB/bindsrc" "$LAB/binddst"
printf '#!/bin/sh\necho bind\n' > "$LAB/bindsrc/prog"; chmod 755 "$LAB/bindsrc/prog"
if mount --bind "$LAB/bindsrc" "$LAB/binddst" 2>/dev/null; then
    src=$(devino "$LAB/bindsrc/prog"); dst=$(devino "$LAB/binddst/prog")
    if [[ "$src" == "$dst" ]]; then
        echo "  bind mount                   (dev,ino) 동일 — 우회 안 됨 ✓"
        echo "bind-mount,$LAB/binddst/prog,claim,${src% *},${src#* },${dst% *},${dst#* },no,0" >> "$CSV"
    else
        echo "  bind mount                   (dev,ino) 다름 — 문서 주장 반증 ✗"
        echo "bind-mount,$LAB/binddst/prog,claim,${src% *},${src#* },${dst% *},${dst#* },yes,0" >> "$CSV"
    fi
    umount "$LAB/binddst" 2>/dev/null || true
else
    echo "  bind mount                   건너뜀 (mount 실패)"
fi

# 바이너리 복사 우회. 새 inode 라 허용 목록에 없어야 정상이다.
cp /bin/sh "$LAB/bin/copied" 2>/dev/null || true
if [[ -f $LAB/bin/copied ]]; then
    a=$(devino /bin/sh); b=$(devino "$LAB/bin/copied")
    if [[ "$a" != "$b" ]]; then
        echo "  바이너리 복사                 (dev,ino) 다름 — 복사 우회 자동 차단 ✓"
        echo "binary-copy,$LAB/bin/copied,claim,${a% *},${a#* },${b% *},${b#* },yes,0" >> "$CSV"
    fi
fi

# 하드링크. 같은 inode 라 허용 목록을 그대로 물고 온다 — 이건 우회다.
if ln "$LAB/bin/tool" "$LAB/bin/hardlink" 2>/dev/null; then
    a=$(devino "$LAB/bin/tool"); b=$(devino "$LAB/bin/hardlink")
    if [[ "$a" == "$b" ]]; then
        echo "  하드링크                     (dev,ino) 동일 — 허용이 딸려간다 ⚠"
        echo "hardlink,$LAB/bin/hardlink,claim,${a% *},${a#* },${b% *},${b#* },no,0" >> "$CSV"
    fi
fi

if [[ $WITH_APT == 1 ]]; then
    echo
    echo "── 실제 패키지 재설치 ($APT_PKG) ──────────────────────────────"
    BIN=$(command -v "$APT_PKG" || true)
    if [[ -n $BIN ]]; then
        run_case "apt --reinstall $APT_PKG" "$BIN" allow \
            apt-get install -y --reinstall -o Dpkg::Use-Pty=0 "$APT_PKG"
    else
        echo "  $APT_PKG 가 설치돼 있지 않다 — 건너뜀"
    fi
fi

kill -INT "$WPID" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true

echo
python3 report.py "$OUT" | tee "$OUT/report.txt"
if [[ -n ${SUDO_USER:-} ]]; then chown -R "$SUDO_USER" "$OUT"; fi
echo
echo "결과: $OUT"
echo "커밋: git add bench/inode/out && git commit -m \"S4 실측: $(uname -r)\""
