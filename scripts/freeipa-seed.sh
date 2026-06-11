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
#   BATON_TEST_USER   user UID to create   (default: testuser1)
#   BATON_TEST_GROUP  group name to create (default: testgroup1)
#   BATON_TEST_ROLE   role name to create  (default: testrole1)

set -euxo pipefail

: "${PASSWORD:?PASSWORD must be set}"

TEST_USER="${BATON_TEST_USER:-testuser1}"
TEST_GROUP="${BATON_TEST_GROUP:-testgroup1}"
TEST_ROLE="${BATON_TEST_ROLE:-testrole1}"

# Suppress xtrace so the expanded password is not echoed into CI logs.
{ set +x; } 2>/dev/null
echo "$PASSWORD" | kinit admin
set -x

# User
if ! ipa user-show "$TEST_USER" >/dev/null 2>&1; then
  ipa user-add "$TEST_USER" --first "Test" --last "User1"
fi

# Group (POSIX user group -> objectClass ipausergroup, which the connector syncs)
if ! ipa group-show "$TEST_GROUP" >/dev/null 2>&1; then
  ipa group-add "$TEST_GROUP" --desc "baton-ipa integration test group"
fi

# Role
if ! ipa role-show "$TEST_ROLE" >/dev/null 2>&1; then
  ipa role-add "$TEST_ROLE" --desc "baton-ipa integration test role"
fi

echo "FreeIPA seed complete: user=$TEST_USER group=$TEST_GROUP role=$TEST_ROLE"
