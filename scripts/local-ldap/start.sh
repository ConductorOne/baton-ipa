#!/usr/bin/env bash
#
# Start a local OpenLDAP server seeded with an IPA-shaped directory, for
# exercising the connector without a FreeIPA instance. See README.md.
#
# Usage: scripts/local-ldap/start.sh [--port 3389] [--stop]
#
# Requires: slapd, ldap-utils (Debian/Ubuntu: apt-get install slapd ldap-utils).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${BATON_LOCAL_LDAP_DIR:-${TMPDIR:-/tmp}/baton-ipa-local-ldap}"
PORT=3389
STOP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --stop) STOP=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

SLAPD="$(command -v slapd || echo /usr/sbin/slapd)"
SLAPADD="$(command -v slapadd || echo /usr/sbin/slapadd)"

if [ "$STOP" -eq 1 ]; then
  if [ -f "$RUN_DIR/slapd.pid" ]; then
    pid="$(cat "$RUN_DIR/slapd.pid")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.5
    done
    rm -f "$RUN_DIR/slapd.pid"
    echo "stopped slapd"
  else
    echo "no slapd.pid in $RUN_DIR; nothing to stop"
  fi
  exit 0
fi

if [ -f "$RUN_DIR/slapd.pid" ] && kill -0 "$(cat "$RUN_DIR/slapd.pid")" 2>/dev/null; then
  echo "slapd is already running (pid $(cat "$RUN_DIR/slapd.pid")); run with --stop first" >&2
  exit 1
fi

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/db"

cat > "$RUN_DIR/slapd.conf" <<EOF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include /etc/ldap/schema/nis.schema
include $HERE/ipa.schema

modulepath /usr/lib/ldap
moduleload back_mdb

pidfile $RUN_DIR/slapd.pid
argsfile $RUN_DIR/slapd.args

database mdb
maxsize 268435456
suffix "dc=example,dc=test"
rootdn "cn=Directory Manager,dc=example,dc=test"
rootpw Secret123
directory $RUN_DIR/db
index objectClass eq
index ipaUniqueID eq
index cn,uid eq
index member,memberManager,memberHost,memberUser eq
EOF

"$SLAPADD" -f "$RUN_DIR/slapd.conf" -l "$HERE/fixtures.ldif" >/dev/null
"$SLAPD" -h "ldap://127.0.0.1:$PORT" -f "$RUN_DIR/slapd.conf" -d 0 >"$RUN_DIR/slapd.log" 2>&1 &

for _ in $(seq 1 20); do
  if ldapsearch -LLL -x -H "ldap://127.0.0.1:$PORT" -b "dc=example,dc=test" -s base "(objectClass=*)" dn >/dev/null 2>&1; then
    cat <<EOF
slapd is listening on ldap://127.0.0.1:$PORT (data + logs in $RUN_DIR)

Point the connector at it with:

  export BATON_URL="ldap://127.0.0.1:$PORT"
  export BATON_BIND_DN="cn=Directory Manager,dc=example,dc=test"
  export BATON_PASSWORD="Secret123"
  export BATON_BASE_DN="dc=example,dc=test"
  export BATON_USER_SEARCH_DN="cn=users,cn=accounts,dc=example,dc=test"
  export BATON_GROUP_SEARCH_DN="cn=groups,cn=accounts,dc=example,dc=test"
  export BATON_ROLE_SEARCH_DN="cn=roles,cn=accounts,dc=example,dc=test"

Then: go build ./cmd/baton-ipa && ./baton-ipa --file=sync.c1z
Stop it with: scripts/local-ldap/start.sh --stop
EOF
    exit 0
  fi
  sleep 0.5
done

echo "slapd did not come up; see $RUN_DIR/slapd.log" >&2
tail -20 "$RUN_DIR/slapd.log" >&2 || true
exit 1
