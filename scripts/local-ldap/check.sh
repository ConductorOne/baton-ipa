#!/usr/bin/env bash
#
# Sync the local LDAP harness and assert the grants and entitlements that the
# connector can only produce by resolving an LDAP DN from the resource it is
# handed. Mirrors the "Test sync resolves DNs for every resource type" step in
# .github/workflows/ci.yaml, against fixtures with fixed ipaUniqueIDs.
#
# Usage:
#   scripts/local-ldap/start.sh
#   eval "$(scripts/local-ldap/env.sh)"
#   go build ./cmd/baton-ipa
#   scripts/local-ldap/check.sh [./baton-ipa] [./baton]
#
# Requires the baton CLI: https://github.com/ConductorOne/baton (or scripts/get-baton.sh).

set -euo pipefail

CONNECTOR="${1:-./baton-ipa}"
BATON="${2:-baton}"
C1Z="$(mktemp -u)/local-ldap.c1z"
mkdir -p "$(dirname "$C1Z")"

# Fixed in fixtures.ldif, except the role, which is keyed by the entryUUID the
# directory generates.
USER1_ID=11111111-1111-1111-1111-111111111111
USER2_ID=22222222-2222-2222-2222-222222222222
GROUP_ID=33333333-3333-3333-3333-333333333333
HOST_ID=44444444-4444-4444-4444-444444444444
HOSTGROUP_ID=55555555-5555-5555-5555-555555555555

"$CONNECTOR" --file="$C1Z"

ROLE_ID=$("$BATON" resources --file="$C1Z" --output-format=json \
  | jq --raw-output --exit-status \
    'first(.resources[] | select(.resource.id.resourceType == "role") | .resource.id.resource)')

failures=0

assert_grant() {
  local entitlement="$1" principal="$2"
  if "$BATON" grants --file="$C1Z" --entitlement="$entitlement" --output-format=json \
    | jq --exit-status --arg p "$principal" \
      'any(.grants[]?; .principal.id.resource == $p)' >/dev/null; then
    echo "ok:   $entitlement -> $principal"
  else
    echo "FAIL: no grant of '$entitlement' to '$principal'"
    failures=$((failures + 1))
  fi
}

assert_entitlement() {
  local entitlement="$1"
  if "$BATON" entitlements --file="$C1Z" --output-format=json \
    | jq --exit-status --arg id "$entitlement" \
      'any(.entitlements[]?; .entitlement.id == $id)' >/dev/null; then
    echo "ok:   $entitlement"
  else
    echo "FAIL: entitlement '$entitlement' was not synced"
    failures=$((failures + 1))
  fi
}

# group.Grants - the failure reported in CXP-842
assert_grant "group:$GROUP_ID:member" "$USER1_ID"
assert_grant "group:$GROUP_ID:manager" "$USER2_ID"

# role.Grants, for both a user and a nested group member
assert_grant "role:$ROLE_ID:member" "$USER1_ID"
assert_grant "role:$ROLE_ID:member" "$GROUP_ID"

# host_group.Grants, static and HBAC-derived
assert_grant "host_group:$HOSTGROUP_ID:member" "$HOST_ID"
assert_grant "host_group:$HOSTGROUP_ID:manager" "$USER2_ID"
assert_entitlement "host_group:$HOSTGROUP_ID:testhbac1"
assert_grant "host_group:$HOSTGROUP_ID:testhbac1" "$USER1_ID"

# host.Entitlements/Grants. Hosts have no trait profile to carry a DN, so these
# only appear if the DN was resolved by ipaUniqueID.
assert_entitlement "host:$HOST_ID:testhbac1"
assert_grant "host:$HOST_ID:testhbac1" "$USER1_ID"

# The inherited entitlement host_group.Entitlements projects onto each member host
assert_entitlement "host:$HOST_ID:testhostgroup1 - testhbac1"
assert_grant "host:$HOST_ID:testhostgroup1 - testhbac1" "$USER1_ID"

rm -rf "$(dirname "$C1Z")"

if [ "$failures" -ne 0 ]; then
  echo "$failures assertion(s) failed"
  exit 1
fi
echo "all assertions passed"
