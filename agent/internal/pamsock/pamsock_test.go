package pamsock

import "testing"

func TestParse(t *testing.T) {
	const key = "publickey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"

	tests := []struct {
		name    string
		in      string
		want    Request
		wantErr bool
	}{
		{
			name: "OPEN",
			in:   "OPEN\t14\t13299\tdeploy\t10.0.0.7\t" + key + "\n",
			want: Request{Op: "OPEN", SessionID: "14", CgroupID: 13299, LoginAccount: "deploy", RHost: "10.0.0.7", AuthInfo: key},
		},
		{
			name: "CLOSE",
			in:   "CLOSE\t14\t13299\n",
			want: Request{Op: "CLOSE", SessionID: "14", CgroupID: 13299},
		},
		{
			name: "값이 전부 -",
			in:   "OPEN\t-\t-\t-\t-\t-\n",
			want: Request{Op: "OPEN"},
		},
		{
			name: "session_id 가 숫자가 아니다",
			in:   "CLOSE\tc1\t13299\n",
			want: Request{Op: "CLOSE", SessionID: "c1", CgroupID: 13299},
		},
		{
			name: "auth_info 여러 줄 · 끝 줄바꿈 보존",
			in:   "OPEN\t14\t13299\tdeploy\t10.0.0.7\t" + key + "\npassword\n\n",
			want: Request{Op: "OPEN", SessionID: "14", CgroupID: 13299, LoginAccount: "deploy", RHost: "10.0.0.7", AuthInfo: key + "\npassword\n"},
		},
		{
			name: "auth_info 안의 탭 · 끝 공백 보존",
			in:   "OPEN\t14\t13299\tdeploy\t10.0.0.7\ta\tb  \n",
			want: Request{Op: "OPEN", SessionID: "14", CgroupID: 13299, LoginAccount: "deploy", RHost: "10.0.0.7", AuthInfo: "a\tb  "},
		},
		{
			name: "끝 줄바꿈 없음",
			in:   "CLOSE\t14\t13299",
			want: Request{Op: "CLOSE", SessionID: "14", CgroupID: 13299},
		},
		{
			name: "cgroup_id 최댓값",
			in:   "CLOSE\t14\t18446744073709551615\n",
			want: Request{Op: "CLOSE", SessionID: "14", CgroupID: 1<<64 - 1},
		},

		{name: "OPEN 필드 부족", in: "OPEN\t14\t13299\tdeploy\n", wantErr: true},
		{name: "CLOSE 필드 부족", in: "CLOSE\t14\n", wantErr: true},
		{name: "CLOSE 필드 초과", in: "CLOSE\t14\t13299\textra\n", wantErr: true},
		{name: "모르는 op", in: "PING\t14\t13299\n", wantErr: true},
		{name: "소문자 op", in: "open\t14\t13299\tdeploy\t10.0.0.7\t-\n", wantErr: true},
		{name: "cgroup_id 가 숫자가 아니다", in: "CLOSE\t14\tabc\n", wantErr: true},
		{name: "cgroup_id 음수", in: "CLOSE\t14\t-1\n", wantErr: true},
		{name: "cgroup_id 빈 값", in: "CLOSE\t14\t\n", wantErr: true},
		{name: "cgroup_id 범위 초과", in: "CLOSE\t14\t18446744073709551616\n", wantErr: true},
		{name: "탭 없음", in: "OPEN\n", wantErr: true},
		{name: "빈 입력", in: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// Checks that Request does not alias the input buffer.
func TestParseCopies(t *testing.T) {
	buf := []byte("CLOSE\tc1\t13299\n")
	got, err := parse(buf)
	if err != nil {
		t.Fatal(err)
	}
	for i := range buf {
		buf[i] = 'X'
	}
	if got.SessionID != "c1" {
		t.Errorf("SessionID = %q, buf 를 덮어쓴 뒤 바뀌었다", got.SessionID)
	}
}

// Keys and certs generated with ssh-keygen; want is `ssh-keygen -lf` output.
const (
	fpKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMSAbXyR+rORY6QMtD5jNWmiMxwd7QXBOJJmuw20r7N"
	fpCert1 = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIEsXuXbjArpeVU/TidzEHNPGSO/9M8p+P5zSh+VzDNWjAAAAILMSAbXyR+rORY6QMtD5jNWmiMxwd7QXBOJJmuw20r7NAAAAAAAAAAIAAAABAAAABmFsaWNlMgAAAAoAAAAGZGVwbG95AAAAAAAAAAD//////////wAAABoAAAANZm9yY2UtY29tbWFuZAAAAAUAAAABeAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgCNJWQgntY/HmdRHCybXssMVZtkFJl9T/GB7FOLLiSkkAAABTAAAAC3NzaC1lZDI1NTE5AAAAQPN1BMqQdl//11eP500ztOXpLmsGT23mYmWlZ01ds/HJWjwAHm+/WqCwfR5pPIRIxX0cpCdTYorFqmJkpCy06Ak="
	fpCert2 = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAILeXBcuIfoT4mQKlH06647X+amXHrcrsmXp81XCec2unAAAAILMSAbXyR+rORY6QMtD5jNWmiMxwd7QXBOJJmuw20r7NAAAAAAAAAGMAAAABAAAADmFsaWNlLXJlaXNzdWVkAAAACgAAAAZkZXBsb3kAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgCNJWQgntY/HmdRHCybXssMVZtkFJl9T/GB7FOLLiSkkAAABTAAAAC3NzaC1lZDI1NTE5AAAAQLguQAw5ogGLcxyanPdjI9+TRnByv13kSqacJyk67kIrk6rVgTYc+eaU5ob2IRLr5fa9USOglsqTQKKPYyxIVQI="
	fpWant  = "SHA256:jboFL1JPH9fffG2ASuLTLJfvaA7inV9SPlWM5gciBjs"
)

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "publickey", in: "publickey " + fpKey + "\n", want: fpWant},
		{name: "끝 줄바꿈 없음", in: "publickey " + fpKey, want: fpWant},
		{name: "password 뒤에 publickey", in: "password\npublickey " + fpKey + "\n", want: fpWant},
		{name: "인증서는 안의 키", in: "publickey " + fpCert1 + "\n", want: fpWant},
		{name: "재발급 인증서도 같은 지문", in: "publickey " + fpCert2 + "\n", want: fpWant},
		{name: "password 만", in: "password\n", want: ""},
		{name: "keyboard-interactive 만", in: "keyboard-interactive\n", want: ""},
		{name: "빈 값", in: "", want: ""},
		{name: "publickey 접두사만 같은 줄", in: "publickeyx " + fpKey + "\n", want: ""},
		{name: "깨진 base64", in: "publickey ssh-ed25519 !!!notbase64\n", wantErr: true},
		{name: "키 없음", in: "publickey \n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Fingerprint(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
