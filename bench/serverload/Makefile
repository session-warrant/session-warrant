# 중앙 서버 부하 — k6
#
#   make check              k6 · 서버 · DB · 인증서 확인
#   make certs NODES=8      가짜 노드 인증서 (mtls 프로필일 때만 필요)
#   sudo 는 필요 없다. 전부 맥에서 돈다
#   make test               노드 1대 · 30초
#   make test-scale         노드 1 · 2 · 4 · 8 로 한 번씩 — 적재가 직렬화되는지 본다
#   make clean-rows CONFIRM=1   가짜 노드가 남긴 행을 지운다
#
# 읽기 부하는 인증이 필요해 Makefile 에 넣지 않았다 — ./run.sh --both --token "$$T".

SHELL := /bin/bash
ROOT := $(shell cd ../.. && pwd)
NODES ?= 1
DURATION ?= 30
PREFIX ?= k6-node-
CERTS ?= $(ROOT)/.cache/pki
DB_CONTAINER ?= session-warrant-postgres-1
API ?= http://localhost:8080

.PHONY: check certs test test-scale clean-rows

check:
	@echo "k6        = $$(command -v k6 >/dev/null && k6 version 2>&1 | head -1 || echo '없음 ← brew install k6')"
	@echo "서버      = $$(curl -fsS -m 5 $(API)/actuator/health 2>/dev/null || echo '없음 ← server/ 에서 ./gradlew bootRun')"
	@echo "인증 모드 = $$(curl -fsS -m 5 $(API)/api/auth/config 2>/dev/null | sed -n 's/.*"mode":"\([^"]*\)".*/\1/p')"
	@echo "gRPC 9090 = $$(nc -z localhost 9090 2>/dev/null && echo 열림 || echo '닫힘 ← 서버가 안 떠 있다')"
	@echo "DB        = $$(docker exec $(DB_CONTAINER) true 2>/dev/null && echo $(DB_CONTAINER) || echo '없음 ← server/ 에서 docker compose up -d')"
	@echo "CA        = $$(test -f $(CERTS)/ca.pem && echo $(CERTS)/ca.pem || echo '없음 ← deploy/pki/pki.sh ca (평문이면 run.sh --no-tls)')"
	@echo "노드 인증서 = $$(ls $(CERTS)/nodes/$(PREFIX)*.pem 2>/dev/null | wc -l | tr -d ' ')개 ($(PREFIX)*)"
	@echo
	@echo "  mtls 프로필로 띄운 서버는 노드마다 인증서가 필요하다 — make certs NODES=8"
	@echo "  mtls 없이 띄웠으면 ./run.sh --no-tls"

certs:
	@for i in $$(seq 1 $(NODES)); do \
	  host=$$(printf '%s%02d' '$(PREFIX)' $$i); \
	  test -f $(CERTS)/nodes/$$host.pem || $(ROOT)/deploy/pki/pki.sh node $$host; \
	done
	@echo "노드 인증서 $$(ls $(CERTS)/nodes/$(PREFIX)*.pem | wc -l | tr -d ' ')개"

test:
	./run.sh --nodes $(NODES) --duration $(DURATION)

# 같은 실행 안에서 노드 수만 바꾼다. 실행끼리 섞어 비교하면 안 되므로 한 번에 돌린다.
test-scale:
	@for n in 1 2 4 8; do \
	  echo; echo "=== 노드 $$n 대 ==="; \
	  ./run.sh --nodes $$n --duration $(DURATION) || exit $$?; \
	done

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
