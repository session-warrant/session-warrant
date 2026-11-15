# bench/inode/ — S4: inode 갱신 추적의 안정성

§09가 지목한 선행 검증 셋의 **마지막 하나**다 (PAM 타이밍 ✅ S3 · `file_open`
오버헤드 ✅ S1).

## 재는 것 — 숫자가 아니라 목록이다

§15가 세운 설계와 그 대가:

> 정책에는 `/usr/bin/git` 이라고 쓰지만 맵에는 inode 번호가 들어간다. BPF에서
> 경로 문자열을 다루지 않아도 되고, 부수적으로 바이너리 복사 우회가 자동으로
> 막힌다. **대가는 패키지 업데이트로 inode가 바뀌면 재컴파일이 필요하다는
> 것이고, warrantd가 fanotify로 감시해 자동 갱신한다.**

> fanotify로 감시해 재컴파일하고, **어느 시점에 inode가 바뀌는지(upgrade ·
> vim 저장 · logrotate)를 목록화하는 것이 마지막 스파이크 S4다.**

그래서 두 가지를 잰다.

| | 무엇 | |
|---|---|---|
| ① | 이 조작이 `(dev, ino)` 를 바꾸는가 — **`i_generation` 까지** | 재컴파일이 필요한 지점의 목록 |
| ② | **fanotify 가 그걸 알려주는가** | 자동 갱신이 가능한가 |

**②가 ①보다 중요하다.** 바뀌는 건 이미 대충 알고 있고, **놓치는 게 문제다.**
놓치면 정책이 조용히 무효가 된다 — 에러도 로그도 없이.

**판정:** inode 가 바뀌는 조작 중 fanotify 가 못 잡는 게 하나라도 있으면 실패다.
실패하면 fanotify 마스크·범위를 넓히거나 주기적 재`stat` 로 메워야 한다.

## 허용과 금지는 비대칭이다 (§15)

케이스를 두 갈래로 나눈 이유다.

| | 무엇으로 걸리나 | 무효가 되면 |
|---|---|---|
| **허용 목록** | 파일 inode | 그 영장의 실행·쓰기 허용이 사라진다. **불편하지만 안전한 방향** |
| **금지 목록** | **디렉터리** inode | 금지가 **풀린다.** 조용히 열리는 방향이라 훨씬 나쁘다 |

§15가 금지를 디렉터리로 거는 이유가 *"`/etc/passwd` 의 inode를 막아도 mv 후
재생성하면 새 inode라 목록 밖"* 이기 때문인데, **그럼 디렉터리 inode 자체가
갈리면?** 그 케이스를 넣어 뒀다.

## 케이스

### 허용 목록이 무효가 되는가 — 파일 inode

| 조작 | 왜 넣었나 |
|---|---|
| vim 저장(rename 방식) | `backupcopy=auto` 기본 동작. 새 파일 쓰고 rename |
| 편집기 제자리 덮어쓰기 | `backupcopy=yes`. 같은 inode |
| `sed -i` | 임시파일 + rename — vim 과 같은 패턴 |
| `cp` 덮어쓰기 | truncate + write. inode 유지가 기대값 |
| `mv` 덮어쓰기 | rename. 새 inode |
| `install(1)` | `make install` 이 쓰는 경로 |
| unlink 후 재생성 | 가장 노골적인 교체 |
| `chmod` | 내용이 안 바뀌어도 이벤트가 오는가 |
| truncate + 재기록 | inode 유지 |
| 심링크 대상 교체 | `/usr/bin/python3 → python3.12` 같은 경로 |
| logrotate `copytruncate` | inode 유지 방식 |
| logrotate `create`(기본) | rename 방식 |
| `apt --reinstall` | **실물.** `--with-apt` 일 때만 |

### 금지 목록이 무효가 되는가 — 디렉터리 inode

| 조작 | |
|---|---|
| 디렉터리 안 파일 생성 | 디렉터리 inode 는 그대로여야 정상 |
| 디렉터리 안 파일 mv 후 재생성 | §15가 금지를 디렉터리로 거는 이유. 여전히 잡혀야 한다 |
| **디렉터리 자체 교체** | 여기가 금지 목록을 뚫는 경로다 |

### 문서의 주장 검증

| 주장 (§15) | 확인 |
|---|---|
| bind mount 우회는 `(dev, ino)` 로 안 뚫린다 | 같은 `(dev, ino)` 가 나오는가 |
| 바이너리 복사는 새 inode 라 자동 차단된다 | 다른 `(dev, ino)` 가 나오는가 |
| — | **하드링크는?** 같은 inode 라 허용이 딸려간다. 문서에 없는 경로다 |

## 왜 inotify 가 아니라 fanotify 인가

`inotify` 는 디렉터리마다 watch 를 걸고 재귀도 직접 해야 한다. `/usr` 전체를
감시하는 용도로는 못 쓴다. `fanotify` 는 `FAN_MARK_FILESYSTEM` 으로 파일시스템
하나를 통째로 본다. 대가는 `CAP_SYS_ADMIN` 인데 **warrantd 는 어차피 root 다.**

`inowatch.c` 는 `FAN_REPORT_DFID_NAME`(커널 5.9+)으로 부모 디렉터리와 이름을
같이 받는다. 이게 없으면 "무언가 바뀌었다"만 알고 무엇인지 모른다.

**마크는 언제나 `FAN_MARK_FILESYSTEM` 이다.** 디렉터리 마크는 바로 아래 자식만
본다 — 처음 하네스는 마운트포인트가 아닌 경로에 디렉터리 마크를 걸어서 `lab/bin/*`
조작이 전부 0건으로 나왔다(2026-11-15). 지금은 파일시스템 전체를 잡고, 부모
handle 을 `open_by_handle_at` 으로 경로로 풀어 감시 대상 아래 이벤트만 `path=` 로 찍는다.

마스크에 `FAN_DELETE_SELF` · `FAN_MOVE_SELF` 를 넣은 건 **금지 목록이 디렉터리
inode 로 걸리기 때문**이다. 그 디렉터리가 통째로 갈리면 금지가 무효가 되는데,
파일 이벤트만 보면 그 순간이 안 보인다.

## 실행

```sh
make check              # 커널 · fanotify 헤더 · 파일시스템 확인
make
sudo make test          # 기본 세트 (랩 + /usr 감시)
sudo make test-apt      # 실제 패키지 재설치 포함 (네트워크 필요)
```

랩은 `mktemp -d` 로 만들고 끝나면 지운다. `/usr` 는 **감시만 하고 건드리지
않는다** — 실물 교체를 보려면 `test-apt` 다.

**위험이 없다.** S3과 달리 시스템 설정을 바꾸지 않는다. fanotify 는 읽기 전용
알림이고(`FAN_CLASS_NOTIF`), 조작은 전부 `/tmp` 아래 랩에서 일어난다.
`--with-apt` 만 실제 시스템을 건드리는데 그것도 `--reinstall` 이라 버전이
안 바뀐다.

## 읽을 때

`/tmp` 가 tmpfs 면 랩 케이스는 tmpfs 위에서 돈다. **실디스크(ext4)와 inode
동작이 같은지는 별개 문제다** — `make check` 가 파일시스템을 찍어주고,
다르면 `sudo SW_LAB=/var/tmp ./cases.sh` 로 옮겨 한 번 더 돌린다.

**`(dev, ino)` 가 같아도 새 파일일 수 있다.** ext4 는 지운 inode 번호를 바로 다음
파일에 준다. 그래서 `stat` 의 두 값만 비교하면 `install(1)` · unlink 후 재생성이
「그대로」로 보인다. `cases.sh` 는 `lsattr -v` 의 generation 을 같이 비교하고, 번호는
같은데 generation 이 다르면 `reused=yes` 로 적는다.

`fanotify 0건` 인데 `inode 바뀜` 이면 그게 **정확히 이 스파이크가 찾는 것**이다.
반대로 `inode 그대로` 인데 이벤트가 오는 건 문제가 아니다 — warrantd 가
재`stat` 해서 같으면 아무것도 안 하면 된다. 헛수고지 구멍이 아니다.

## 이 코드는 던져버린다

`inowatch.c` 와 `cases.sh` 는 스파이크다. 남는 건 **`out/` 의 카탈로그**와,
거기서 나온 "재컴파일 트리거 목록"이다. 그 목록이
`agent/internal/policy` 의 fanotify 마스크와 재컴파일 조건이 된다.
