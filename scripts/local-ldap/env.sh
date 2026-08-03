#!/usr/bin/env bash
#
# Print the connector configuration for the local LDAP harness.
# Usage: eval "$(scripts/local-ldap/env.sh)"   [--port 3389]

PORT="${2:-3389}"

cat <<EOF
export BATON_URL="ldap://127.0.0.1:$PORT"
export BATON_BIND_DN="cn=Directory Manager,dc=example,dc=test"
export BATON_PASSWORD="Secret123"
export BATON_BASE_DN="dc=example,dc=test"
export BATON_USER_SEARCH_DN="cn=users,cn=accounts,dc=example,dc=test"
export BATON_GROUP_SEARCH_DN="cn=groups,cn=accounts,dc=example,dc=test"
export BATON_ROLE_SEARCH_DN="cn=roles,cn=accounts,dc=example,dc=test"
EOF
