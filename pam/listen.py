#!/usr/bin/env python3
"""pam_warrant.so 테스트 수신기 — warrantd 대신 데이터그램을 받아 그대로 찍는다.

    sudo make listen                      # 기본 /tmp/warrant-test.sock
    sudo python3 listen.py /run/x.sock    # 경로를 바꿀 때

repr 로 찍는 이유: 탭 · 끝 공백 · 개행이 눈에 보여야 형식 문제를 잡는다
(S3 후속에서 auth info 끝의 공백을 이걸로 봤다).
"""
import os
import socket
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/warrant-test.sock"

if os.path.exists(path):
    os.unlink(path)

s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(path)
os.chmod(path, 0o600)  # root 만 보낼 수 있어야 한다 — 공개키는 비밀이 아니다
print(f"수신 대기: {path}  (Ctrl+C 로 끝낸다)", flush=True)

try:
    while True:
        print(repr(s.recv(8192)), flush=True)
except KeyboardInterrupt:
    pass
finally:
    s.close()
    if os.path.exists(path):
        os.unlink(path)
