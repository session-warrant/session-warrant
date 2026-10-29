package loader

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pin 재사용 경로는 진짜 bpffs 와 root 가 있어야 잰다. 둘이 없으면 건너뛴다 —
// 「건너뛰었다」와 「통과했다」가 구분돼야 한다.
//
//	sudo WARRANT_PIN_OBJ=bpf/warrant.bpf.o WARRANT_PIN_DIR=/sys/fs/bpf/lt \
//	    go test ./internal/loader/ -run Pin -v
func pinEnv(t *testing.T) (obj, dir string) {
	t.Helper()
	obj = os.Getenv("WARRANT_PIN_OBJ")
	dir = os.Getenv("WARRANT_PIN_DIR")
	if obj == "" || dir == "" {
		t.Skip("WARRANT_PIN_OBJ · WARRANT_PIN_DIR 가 필요하다 (bpffs + root)")
	}
	os.RemoveAll(dir)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return obj, dir
}

// 같은 오브젝트를 두 번 올리면 두 번째는 pin 을 재사용해야 한다.
// loader 가 문서로 약속한 동작이고, warrantd 재시작이 여기에 걸려 있다.
func TestPinReuseOnSecondLoad(t *testing.T) {
	obj, dir := pinEnv(t)
	l1, err := LoadObject(obj, dir)
	if err != nil {
		t.Fatalf("1차 로드: %v", err)
	}
	l1.Close()

	l2, err := LoadObject(obj, dir)
	if err != nil {
		t.Fatalf("2차 로드가 pin 을 재사용하지 못했다: %v", err)
	}
	l2.Close()
}

// 이전 로드가 중간에 죽어 pin 이 일부만 남은 상태.
func TestPinPartialLeftover(t *testing.T) {
	obj, dir := pinEnv(t)
	l1, err := LoadObject(obj, dir)
	if err != nil {
		t.Fatalf("1차 로드: %v", err)
	}
	names := make([]string, 0, len(l1.spec.Maps))
	for n := range l1.spec.Maps {
		if !strings.HasPrefix(n, ".") {
			names = append(names, n)
		}
	}
	l1.Close()
	if len(names) == 0 {
		t.Fatal("pin 되는 맵이 없다 — 이 테스트는 아무것도 안 쟀다")
	}
	if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
		t.Fatalf("pin 하나 지우기: %v", err)
	}

	l2, err := LoadObject(obj, dir)
	if err != nil {
		t.Fatalf("일부만 남은 pin 에서 로드 실패: %v", err)
	}
	l2.Close()
}

// 두 프로세스가 동시에 올린다.
//
// 이게 핵심 회귀 테스트다. goroutine 으로는 못 잡는다 — 한 프로세스 안에서는
// 라이브러리가 직렬화해서 수정 전에도 통과한다. 실제로는 서로 다른 프로세스가
// 겹쳤고 (warrantd 재시작), 둘 다 pin 이 없는 것을 보고 각자 만든 뒤 하나가
// 먼저 pin 해서 나머지가 EEXIST 로 죽었다 — 10회 중 3회.
func TestPinConcurrentProcesses(t *testing.T) {
	// 자식은 pinEnv 를 타면 안 된다 — 거기서 pin 디렉터리를 지우므로
	// 자식들이 서로의 pin 을 지우고, 그러면 경쟁이 아니라 다른 것을 재게 된다.
	if os.Getenv("WARRANT_PIN_CHILD") != "" {
		o, d := os.Getenv("WARRANT_PIN_OBJ"), os.Getenv("WARRANT_PIN_DIR")
		l, err := LoadObject(o, d)
		if err != nil {
			t.Fatalf("자식 로드 실패: %v", err)
		}
		l.Close()
		return
	}

	obj, dir := pinEnv(t)
	_ = obj

	const rounds = 10
	for i := 0; i < rounds; i++ {
		os.RemoveAll(dir)

		cmds := make([]*exec.Cmd, 2)
		outs := make([]strings.Builder, 2)
		for k := range cmds {
			c := exec.Command(os.Args[0], "-test.run", "^TestPinConcurrentProcesses$")
			c.Env = append(os.Environ(), "WARRANT_PIN_CHILD=1")
			c.Stdout = &outs[k]
			c.Stderr = &outs[k]
			if err := c.Start(); err != nil {
				t.Fatalf("자식 기동: %v", err)
			}
			cmds[k] = c
		}
		for k, c := range cmds {
			if err := c.Wait(); err != nil {
				t.Fatalf("%d회차 자식 %d 실패: %v\n%s", i+1, k, err, outs[k].String())
			}
		}
	}
}
