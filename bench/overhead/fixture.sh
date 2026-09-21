#!/usr/bin/env bash
# 워크로드 픽스처를 만든다. 네트워크를 타지 않는다 — 재현 가능해야 한다.
#
#   ./fixture.sh          만든다 (이미 있으면 건너뛴다)
#   ./fixture.sh --force  다시 만든다
set -euo pipefail
cd "$(dirname "$0")"

DIR=fixtures
FILES=${SW_FIXTURE_FILES:-20000}   # 트리 파일 수
SRCS=${SW_FIXTURE_SRCS:-400}       # 컴파일 대상 .c 수

[[ ${1:-} == --force ]] && rm -rf "$DIR"
if [[ -d $DIR/.done ]]; then
    echo "픽스처 있음: $DIR  (다시 만들려면 ./fixture.sh --force)"
    exit 0
fi

mkdir -p "$DIR"

echo "트리 생성: $FILES 파일"
mkdir -p "$DIR/tree"
for d in $(seq 0 199); do
    mkdir -p "$DIR/tree/d$d"
done
i=0
while [ $i -lt "$FILES" ]; do
    printf 'fixture %d\n%s\n' "$i" "$(head -c 64 /dev/zero | tr '\0' 'x')" \
        > "$DIR/tree/d$((i % 200))/f$i.txt"
    i=$((i + 1))
done

echo "git 리포 초기화"
git -C "$DIR/tree" init -q
git -C "$DIR/tree" -c user.email=bench@local -c user.name=bench add -A
git -C "$DIR/tree" -c user.email=bench@local -c user.name=bench commit -qm fixture

echo "tar 아카이브"
tar cf "$DIR/tree.tar" -C "$DIR" tree

# 컴파일 대상 — 쓰기 무거운 워크로드(w_build)용.
echo "소스 생성: $SRCS 개"
mkdir -p "$DIR/src"
i=0
while [ $i -lt "$SRCS" ]; do
    cat > "$DIR/src/m$i.c" <<C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int t$i(int x){ return x * $((i + 1)) + 7; }
int f$i(int x){ int a = t$i(x); for (int k = 0; k < 16; k++) a = t$i(a) ^ k; return a; }
C
    i=$((i + 1))
done

mkdir -p "$DIR/.done"
echo "완료: $DIR ($(du -sh "$DIR" | cut -f1))"
