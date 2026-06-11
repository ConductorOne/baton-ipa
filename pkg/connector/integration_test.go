//go:build integration

// Package connector integration tests exercise the baton-ipa connector against
// a real FreeIPA instance. They are gated behind the `integration` build tag so
// they never run during the normal unit `go test ./...`. CI runs them with the
// tag set against a FreeIPA container; locally they are skipped unless the
// BATON_URL environment variable points at a reachable FreeIPA server.
//
// The central scenario these tests protect is grant/revoke DN resolution. In
// c1 service mode the resource ExternalId is nil, so Grant/Revoke must resolve
// the LDAP DN from the resource's trait profile "path" field via
// getDNFromResource. The tests reproduce that condition by stripping ExternalId
// from synced resources before provisioning, then verify the membership change
// landed in FreeIPA with a direct LDAP read.
package connector

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Test fixtures seeded into FreeIPA before the suite runs (see the CI workflow
// and scripts/freeipa-seed.sh). The names are overridable via environment
// variables so the suite can be pointed at a differently-seeded directory.
const (
	defaultTestUserUID   = "testuser1"
	defaultTestGroupName = "testgroup1"
	defaultTestRoleName  = "testrole1"
)

type integrationEnv struct {
	client        *ldap.Client
	baseDN        *ldap3.DN
	userSearchDN  *ldap3.DN
	groupSearchDN *ldap3.DN
	roleSearchDN  *ldap3.DN

	testUserUID   string
	testGroupName string
	testRoleName  string
}

// newIntegrationEnv reads connection details from the environment, dials
// FreeIPA, and returns a ready-to-use harness. The test is skipped (not failed)
// when BATON_URL is unset so that `go test -tags integration ./...` is safe to
// run in environments without a FreeIPA server.
func newIntegrationEnv(t *testing.T, ctx context.Context) *integrationEnv {
	t.Helper()

	serverURL := os.Getenv("BATON_URL")
	if serverURL == "" {
		t.Skip("BATON_URL not set; skipping FreeIPA integration test")
	}

	bindDN := os.Getenv("BATON_BIND_DN")
	require.NotEmpty(t, bindDN, "BATON_BIND_DN must be set for integration tests")
	password := os.Getenv("BATON_PASSWORD")
	require.NotEmpty(t, password, "BATON_PASSWORD must be set for integration tests")

	baseDNStr := os.Getenv("BATON_BASE_DN")
	require.NotEmpty(t, baseDNStr, "BATON_BASE_DN must be set for integration tests")

	insecure := true
	if v := os.Getenv("BATON_INSECURE_SKIP_VERIFY"); v != "" {
		parsed, err := strconv.ParseBool(v)
		require.NoError(t, err, "BATON_INSECURE_SKIP_VERIFY must be a boolean")
		insecure = parsed
	}

	baseDN, err := ldap.CanonicalizeDN(baseDNStr)
	require.NoError(t, err)

	client, err := ldap.NewClient(ctx, serverURL, password, bindDN, insecure, "")
	require.NoError(t, err, "failed to connect to FreeIPA at %s", serverURL)

	env := &integrationEnv{
		client:        client,
		baseDN:        baseDN,
		userSearchDN:  baseDN,
		groupSearchDN: baseDN,
		roleSearchDN:  baseDN,
		testUserUID:   getenvDefault("BATON_TEST_USER", defaultTestUserUID),
		testGroupName: getenvDefault("BATON_TEST_GROUP", defaultTestGroupName),
		testRoleName:  getenvDefault("BATON_TEST_ROLE", defaultTestRoleName),
	}
	return env
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// listAllResources drains a resource syncer's paginated List into a single slice.
func listAllResources(t *testing.T, ctx context.Context, syncer interface {
	List(context.Context, *v2.ResourceId, *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error)
}) []*v2.Resource {
	t.Helper()

	var out []*v2.Resource
	pageToken := ""
	for {
		resources, next, _, err := syncer.List(ctx, nil, &pagination.Token{Token: pageToken, Size: int(ResourcesPageSize)})
		require.NoError(t, err)
		out = append(out, resources...)
		if next == "" {
			break
		}
		pageToken = next
	}
	return out
}

func (e *integrationEnv) users(t *testing.T, ctx context.Context) []*v2.Resource {
	return listAllResources(t, ctx, userBuilder(e.client, e.userSearchDN, false))
}

func (e *integrationEnv) groups(t *testing.T, ctx context.Context) []*v2.Resource {
	return listAllResources(t, ctx, groupBuilder(e.client, e.groupSearchDN, e.userSearchDN))
}

func (e *integrationEnv) roles(t *testing.T, ctx context.Context) []*v2.Resource {
	return listAllResources(t, ctx, roleBuilder(e.client, e.roleSearchDN))
}

// stripExternalID clones a synced resource and removes its ExternalId, leaving
// only the trait profile "path" to carry the DN. This is exactly the shape of a
// resource provided by c1 in service mode, where ExternalId is nil.
func stripExternalID(t *testing.T, r *v2.Resource) *v2.Resource {
	t.Helper()
	clone := proto.Clone(r).(*v2.Resource)
	clone.ExternalId = nil
	require.Nil(t, clone.GetExternalId(), "ExternalId must be nil to simulate service mode")
	return clone
}

// ldapEntryHasMember reads an entry directly from FreeIPA and reports whether
// the given attribute (member / memberManager) contains wantDN, compared as
// canonicalized DNs so server-side normalization does not cause false negatives.
func (e *integrationEnv) ldapEntryHasMember(t *testing.T, ctx context.Context, entryDN, attr, wantDN string) bool {
	t.Helper()

	entry, err := e.client.LdapGetWithStringDN(ctx, entryDN, "", nil)
	require.NoError(t, err)

	want, err := ldap.CanonicalizeDN(wantDN)
	require.NoError(t, err)

	for _, member := range entry.GetEqualFoldAttributeValues(attr) {
		got, err := ldap.CanonicalizeDN(member)
		if err != nil {
			continue
		}
		if got.Equal(want) {
			return true
		}
	}
	return false
}

func findUserByUID(t *testing.T, users []*v2.Resource, uid string) *v2.Resource {
	t.Helper()
	for _, u := range users {
		trait, err := rs.GetUserTrait(u)
		if err != nil {
			continue
		}
		if login, ok := rs.GetProfileStringValue(trait.GetProfile(), "login"); ok && login == uid {
			return u
		}
		if userID, ok := rs.GetProfileStringValue(trait.GetProfile(), "user_id"); ok && userID == uid {
			return u
		}
	}
	require.FailNowf(t, "user not found", "no synced user with uid %q (seed it before running)", uid)
	return nil
}

func findByDisplayName(t *testing.T, resources []*v2.Resource, name string) *v2.Resource {
	t.Helper()
	for _, r := range resources {
		if r.DisplayName == name {
			return r
		}
	}
	require.FailNowf(t, "resource not found", "no synced resource named %q (seed it before running)", name)
	return nil
}

// TestSyncResourcesCarryProfilePath confirms that syncing users, groups, and
// roles produces resources whose trait profile "path" holds the LDAP DN. This
// is the field Grant/Revoke depend on in service mode.
func TestSyncResourcesCarryProfilePath(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)

	t.Run("user", func(t *testing.T) {
		user := findUserByUID(t, env.users(t, ctx), env.testUserUID)
		trait, err := rs.GetUserTrait(user)
		require.NoError(t, err)
		path, ok := rs.GetProfileStringValue(trait.GetProfile(), pathProfileProperty)
		require.True(t, ok, "user trait profile must contain a path")
		require.NotEmpty(t, path)
		require.Contains(t, path, "uid="+env.testUserUID)
	})

	t.Run("group", func(t *testing.T) {
		group := findByDisplayName(t, env.groups(t, ctx), env.testGroupName)
		trait, err := rs.GetGroupTrait(group)
		require.NoError(t, err)
		path, ok := rs.GetProfileStringValue(trait.GetProfile(), pathProfileProperty)
		require.True(t, ok, "group trait profile must contain a path")
		require.NotEmpty(t, path)
		require.Contains(t, path, "cn="+env.testGroupName)
	})

	t.Run("role", func(t *testing.T) {
		role := findByDisplayName(t, env.roles(t, ctx), env.testRoleName)
		trait, err := rs.GetRoleTrait(role)
		require.NoError(t, err)
		path, ok := rs.GetProfileStringValue(trait.GetProfile(), pathProfileProperty)
		require.True(t, ok, "role trait profile must contain a path")
		require.NotEmpty(t, path)
		require.Contains(t, path, "cn="+env.testRoleName)
	})
}

// TestGroupGrantRevokeServiceMode is the core service-mode regression for
// groups. Both the entitlement resource and the principal have ExternalId ==
// nil, so the DN can only come from the trait profile "path". Before the fix,
// Grant/Revoke failed here with "entitlement resource missing external ID".
func TestGroupGrantRevokeServiceMode(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)

	gb := groupBuilder(env.client, env.groupSearchDN, env.userSearchDN)

	group := stripExternalID(t, findByDisplayName(t, env.groups(t, ctx), env.testGroupName))
	user := stripExternalID(t, findUserByUID(t, env.users(t, ctx), env.testUserUID))

	// Sanity: with ExternalId nil, the DN must still resolve from the profile path.
	groupDN, err := getDNFromResource(group)
	require.NoError(t, err, "group DN must resolve from trait profile path in service mode")
	userDN, err := getDNFromResource(user)
	require.NoError(t, err, "user DN must resolve from trait profile path in service mode")

	entitlement := ent.NewAssignmentEntitlement(group, groupMemberEntitlement)

	// Start from a known-clean state regardless of prior runs.
	_, _ = gb.Revoke(ctx, &v2.Grant{Entitlement: entitlement, Principal: user})
	require.False(t, env.ldapEntryHasMember(t, ctx, groupDN, attrGroupMember, userDN),
		"precondition: user should not be a member before granting")

	// Grant — must succeed despite ExternalId being nil (the regression).
	_, err = gb.Grant(ctx, user, entitlement)
	require.NoError(t, err, "group Grant must succeed with ExternalId nil and only profile path set")

	require.True(t, env.ldapEntryHasMember(t, ctx, groupDN, attrGroupMember, userDN),
		"membership must exist in FreeIPA after Grant")

	// Revoke — must succeed and remove the membership.
	_, err = gb.Revoke(ctx, &v2.Grant{Entitlement: entitlement, Principal: user})
	require.NoError(t, err, "group Revoke must succeed with ExternalId nil and only profile path set")

	require.False(t, env.ldapEntryHasMember(t, ctx, groupDN, attrGroupMember, userDN),
		"membership must be removed from FreeIPA after Revoke")
}

// TestRoleGrantRevokeServiceMode is the core service-mode regression for roles,
// under the same ExternalId == nil condition as the group case.
func TestRoleGrantRevokeServiceMode(t *testing.T) {
	ctx := context.Background()
	env := newIntegrationEnv(t, ctx)

	rb := roleBuilder(env.client, env.roleSearchDN)

	role := stripExternalID(t, findByDisplayName(t, env.roles(t, ctx), env.testRoleName))
	user := stripExternalID(t, findUserByUID(t, env.users(t, ctx), env.testUserUID))

	roleDN, err := getDNFromResource(role)
	require.NoError(t, err, "role DN must resolve from trait profile path in service mode")
	userDN, err := getDNFromResource(user)
	require.NoError(t, err, "user DN must resolve from trait profile path in service mode")

	entitlement := ent.NewAssignmentEntitlement(role, roleMemberEntitlement)

	_, _ = rb.Revoke(ctx, &v2.Grant{Entitlement: entitlement, Principal: user})
	require.False(t, env.ldapEntryHasMember(t, ctx, roleDN, attrRoleMember, userDN),
		"precondition: user should not be a role member before granting")

	_, err = rb.Grant(ctx, user, entitlement)
	require.NoError(t, err, "role Grant must succeed with ExternalId nil and only profile path set")

	require.True(t, env.ldapEntryHasMember(t, ctx, roleDN, attrRoleMember, userDN),
		"role membership must exist in FreeIPA after Grant")

	_, err = rb.Revoke(ctx, &v2.Grant{Entitlement: entitlement, Principal: user})
	require.NoError(t, err, "role Revoke must succeed with ExternalId nil and only profile path set")

	require.False(t, env.ldapEntryHasMember(t, ctx, roleDN, attrRoleMember, userDN),
		"role membership must be removed from FreeIPA after Revoke")
}
