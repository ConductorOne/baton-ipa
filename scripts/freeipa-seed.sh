#!/usr/bin/env bash
#
# Seed a FreeIPA server with the fixtures the baton-ipa CI sync tests expect.
# Intended to be executed *inside* the FreeIPA container (e.g. via `docker exec`)
# once the server has finished installing. It obtains an admin Kerberos ticket
# and creates a test user, group, and role. The operations are idempotent so the
# script is safe to re-run.
#
# Environment:
#   PASSWORD          admin (and Directory Manager) password (required)
#   BATON_TEST_USER       user UID to create       (default: testuser1)
#   BATON_TEST_USER2      manager UID to create    (default: testuser2)
#   BATON_TEST_GROUP      group name to create     (default: testgroup1)
#   BATON_TEST_ROLE       role name to create      (default: testrole1)
#   BATON_TEST_HOST       host fqdn to create      (default: host1.<domain>)
#   BATON_TEST_HOSTGROUP  host group to create     (default: testhostgroup1)
#   BATON_TEST_HBACRULE   HBAC rule to create      (default: testhbac1)

set -euxo pipefail

: "${PASSWORD:?PASSWORD must be set}"

TEST_USER="${BATON_TEST_USER:-testuser1}"
TEST_USER2="${BATON_TEST_USER2:-testuser2}"
TEST_GROUP="${BATON_TEST_GROUP:-testgroup1}"
TEST_ROLE="${BATON_TEST_ROLE:-testrole1}"
TEST_HOST="${BATON_TEST_HOST:-host1.$(hostname -d)}"
TEST_HOSTGROUP="${BATON_TEST_HOSTGROUP:-testhostgroup1}"
TEST_HBACRULE="${BATON_TEST_HBACRULE:-testhbac1}"

# Suppress xtrace so the expanded password is not echoed into CI logs.
{ set +x; } 2>/dev/null
echo "$PASSWORD" | kinit admin
set -x

# Users. Two of them, because group.Grants() unions members and managers and
# emits only the member grant for a principal that is both - so the manager
# entitlement needs a principal that is not also a member.
if ! ipa user-show "$TEST_USER" >/dev/null 2>&1; then
  ipa user-add "$TEST_USER" --first "Test" --last "User1"
fi
if ! ipa user-show "$TEST_USER2" >/dev/null 2>&1; then
  ipa user-add "$TEST_USER2" --first "Test" --last "User2"
fi

# Group (POSIX user group -> objectClass ipausergroup, which the connector syncs)
if ! ipa group-show "$TEST_GROUP" >/dev/null 2>&1; then
  ipa group-add "$TEST_GROUP" --desc "baton-ipa integration test group"
fi

# Role
if ! ipa role-show "$TEST_ROLE" >/dev/null 2>&1; then
  ipa role-add "$TEST_ROLE" --desc "baton-ipa integration test role"
fi

# Host (--force skips the DNS check; the fixture host does not have to resolve)
if ! ipa host-show "$TEST_HOST" >/dev/null 2>&1; then
  ipa host-add "$TEST_HOST" --force --desc "baton-ipa integration test host"
fi

# Host group
if ! ipa hostgroup-show "$TEST_HOSTGROUP" >/dev/null 2>&1; then
  ipa hostgroup-add "$TEST_HOSTGROUP" --desc "baton-ipa integration test host group"
fi

# HBAC rule over the host group, so host groups and hosts both have dynamic
# entitlements and grants to sync.
if ! ipa hbacrule-show "$TEST_HBACRULE" >/dev/null 2>&1; then
  ipa hbacrule-add "$TEST_HBACRULE" --desc "baton-ipa integration test HBAC rule"
fi

# ipa *-add-member exits non-zero when every requested member is already
# present, which is not a failure for a seed script that documents being
# re-runnable. Anything else still fails the script.
ensure_member() {
  local out
  if out=$("$@" 2>&1); then
    echo "$out"
    return 0
  fi
  if grep -qiE "already a member|already exists" <<<"$out"; then
    echo "$out"
    return 0
  fi
  echo "$out" >&2
  return 1
}

# Memberships. These are what the Grants() calls have to return, and they are
# what regressed in CXP-842: every one of them is read through a DN that the
# connector has to resolve from the resource c1 hands back.
ensure_member ipa group-add-member "$TEST_GROUP" --users="$TEST_USER"
ensure_member ipa group-add-member-manager "$TEST_GROUP" --users="$TEST_USER2"
ensure_member ipa role-add-member "$TEST_ROLE" --users="$TEST_USER"
ensure_member ipa role-add-member "$TEST_ROLE" --groups="$TEST_GROUP"
ensure_member ipa hostgroup-add-member "$TEST_HOSTGROUP" --hosts="$TEST_HOST"
ensure_member ipa hostgroup-add-member-manager "$TEST_HOSTGROUP" --users="$TEST_USER2"
# Both the host group and the host directly: host groups project inherited HBAC
# entitlements onto their members, while a directly-attached rule is what
# host.Entitlements()/Grants() resolve through the host's own DN.
ensure_member ipa hbacrule-add-host "$TEST_HBACRULE" --hostgroups="$TEST_HOSTGROUP"
ensure_member ipa hbacrule-add-host "$TEST_HBACRULE" --hosts="$TEST_HOST"
ensure_member ipa hbacrule-add-user "$TEST_HBACRULE" --users="$TEST_USER"

echo "FreeIPA seed complete: user=$TEST_USER user2=$TEST_USER2 group=$TEST_GROUP role=$TEST_ROLE" \
  "host=$TEST_HOST hostgroup=$TEST_HOSTGROUP hbacrule=$TEST_HBACRULE"
