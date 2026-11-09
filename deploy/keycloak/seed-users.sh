#!/bin/sh
# Keycloak realm 「warrant」에 개발용 사용자를 넣는다. 비밀번호는 저장소에 두지 않는다.
#   deploy/keycloak/seed-users.sh [계정 파일]      # 기본 server/.cache/dev-accounts.txt (git 무시)
# 계정 파일 한 줄: <이메일> <비밀번호> <그룹,그룹>   예) a@example.com s3cret warrant-requesters,warrant-approvers
# 다시 돌려도 된다 — 있는 사용자는 비밀번호 · 그룹만 맞춘다.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FILE=${1:-$ROOT/server/.cache/dev-accounts.txt}
ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-admin}
# </dev/null: exec reads stdin and would swallow the rest of the account file.
kc() { docker compose -f "$ROOT/server/compose.yaml" exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }

kc config credentials --server http://localhost:8180 --realm master --user admin --password "$ADMIN_PASSWORD" >/dev/null
while read -r email password groups; do
    case "$email" in ''|'#'*) continue ;; esac
    kc create users -r warrant -s "username=$email" -s "email=$email" -s emailVerified=true -s enabled=true >/dev/null 2>&1 || true
    kc set-password -r warrant --username "$email" --new-password "$password"
    uid=$(kc get users -r warrant -q "username=$email" -q exact=true --fields id --format csv --noquotes)
    # Keycloak 26 requires first/last name; without them login stops at "Account is not fully set up".
    name=${email%%@*}
    kc update "users/$uid" -r warrant -s "firstName=$name" -s "lastName=$name" -s 'requiredActions=[]'
    for g in $(echo "${groups:-}" | tr ',' ' '); do
        gid=$(kc get groups -r warrant -q "search=$g" -q exact=true --fields id --format csv --noquotes)
        kc update "users/$uid/groups/$gid" -r warrant -n
    done
    echo "  $email → ${groups:-그룹 없음}"
done < "$FILE"
