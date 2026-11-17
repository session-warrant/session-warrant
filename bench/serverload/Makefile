# 중앙 서버 부하 — 준비와 정리. **부하는 k6 가 직접 돌린다.**
#
#   make check              k6 · 서버 · DB · 인증서 확인
#   make certs NODES=8      가짜 노드 인증서 (mtls 프로필일 때만 필요)
#   make clean-rows CONFIRM=1   가짜 노드가 남긴 행을 지운다
#
# 부하는 이렇게 돌린다 (sudo 불필요, 전부 맥에서):
#   k6 run smoke.js                                 길 확인 (30건 · ack 까지)
#   k6 run -e NODES=4 ingest.js                     쓰기
#   k6 run -e BASIC=<계정>:<암호> read.js            읽기
#   ./run.sh --scale 1,2,4,8                        DB 검산 · out/ 보존까지
#
# run.sh 를 거치지 않으면 처리량 검산이 없다 — 적재가 멱등이라 보낸 것이 전건 중복으로
# 걸러져도 k6 쪽은 빨랐다고 보고한다. 숫자를 남길 거면 run.sh 로 돌린다.

SHELL := /bin/bash
ROOT := $(shell cd ../.. && pwd)
NODES ?= 1
PREFIX ?= k6-node-
CERTS ?= $(ROOT)/.cache/pki
DB_CONTAINER ?= session-warrant-postgres-1
API ?= http://localhost:8080

.PHONY: check certs clean-rows

check:
	@echo "k6        = $$(command -v k6 >/dev/null && k6 version 2>&1 | head -1 || echo '없음 ← brew install k6')"
	@echo "서버      = $$(curl -fsS -m 5 $(API)/actuator/health 2>/dev/null || echo '없음 ← server/ 에서 ./gradlew bootRun')"
	@echo "인증 모드 = $$(curl -fsS -m 5 $(API)/api/auth/config 2>/dev/null | sed -n 's/.*"mode":"\([^"]*\)".*/\1/p')"
	@echo "gRPC 9090 = $$(nc -z localhost 9090 2>/dev/null && echo 열림 || echo '닫힘 ← 서버가 안 떠 있다')"
	@echo "gRPC 9091 = $$(nc -z localhost 9091 2>/dev/null && echo '열림 (t3.micro 컨테이너)' || echo 닫힘)"
	@echo "DB        = $$(docker exec $(DB_CONTAINER) true 2>/dev/null && echo $(DB_CONTAINER) || echo '없음 ← server/ 에서 docker compose up -d')"
	@echo "CA        = $$(test -f $(CERTS)/ca.pem && echo $(CERTS)/ca.pem || echo '없음 ← deploy/pki/pki.sh ca (평문이면 PKI 를 비운다)')"
	@echo "노드 인증서 = $$(ls $(CERTS)/nodes/$(PREFIX)*.pem 2>/dev/null | wc -l | tr -d ' ')개 ($(PREFIX)*)"
	@echo
	@echo "  mtls 프로필 서버에 쏘려면 노드마다 인증서가 필요하다 — make certs NODES=8,"
	@echo "  그리고 k6 run -e PKI=$(CERTS) ingest.js"

certs:
	@for i in $$(seq 1 $(NODES)); do \
	  host=$$(printf '%s%02d' '$(PREFIX)' $$i); \
	  test -f $(CERTS)/nodes/$$host.pem || $(ROOT)/deploy/pki/pki.sh node $$host; \
	done
	@echo "노드 인증서 $$(ls $(CERTS)/nodes/$(PREFIX)*.pem | wc -l | tr -d ' ')개"

# 가짜 노드가 남긴 행은 대시보드 · Grafana 에 섞인다. 지우기 전에 건수를 찍는다.
clean-rows:
	@docker exec -i $(DB_CONTAINER) psql -U warrant -d warrant -c \
	  "select n.hostname, count(e.*) from node n left join audit_event e on e.node_id=n.id \
	   where n.hostname like '$(PREFIX)%' group by 1 order by 1"
	@test "$(CONFIRM)" = 1 || { echo; echo "지우려면 CONFIRM=1 을 붙인다 — make clean-rows CONFIRM=1"; exit 2; }
	@docker exec -i $(DB_CONTAINER) psql -U warrant -d warrant -c \
	  "delete from audit_event where node_id in (select id from node where hostname like '$(PREFIX)%'); \
	   delete from audit_gap where node_id in (select id from node where hostname like '$(PREFIX)%'); \
	   delete from unwarranted_session where node_id in (select id from node where hostname like '$(PREFIX)%'); \
	   delete from warranted_session where node_id in (select id from node where hostname like '$(PREFIX)%'); \
	   delete from node where hostname like '$(PREFIX)%'"
