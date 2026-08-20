package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

// TestResourceCarriesItsDN pins down the invariant that CXP-594 and CXP-842 both
// broke: c1 persists a resource's profile but not Resource.ExternalId, so every
// resource this connector emits has to carry its DN in the profile. Anything that
// reads a DN off a resource in Entitlements()/Grants() depends on this, and a
// standalone CLI sync would not catch a regression - it used to round-trip
// ExternalId through the c1z, which is exactly why the bug reached customers.
func TestResourceCarriesItsDN(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name   string
		build  func() (*v2.Resource, error)
		wantDN string
	}{
		{
			name:   "group",
			wantDN: "cn=testgroup1,cn=groups,cn=accounts,dc=example,dc=test",
			build: func() (*v2.Resource, error) {
				return groupResource(ctx, ldap3.NewEntry("cn=testgroup1,cn=groups,cn=accounts,dc=example,dc=test", map[string][]string{
					attrIPAUniqueID:      {"group-unique-id"},
					attrGroupCommonName:  {"testgroup1"},
					attrGroupDescription: {"a group"},
					attrGroupIdPosix:     {"1000"},
				}))
			},
		},
		{
			name:   "role",
			wantDN: "cn=testrole1,cn=roles,cn=accounts,dc=example,dc=test",
			build: func() (*v2.Resource, error) {
				return roleResource(ctx, ldap3.NewEntry("cn=testrole1,cn=roles,cn=accounts,dc=example,dc=test", map[string][]string{
					attrRoleCommonName:  {"testrole1"},
					attrRoleDescription: {"a role"},
					attrEntryUUID:       {"role-entry-uuid"},
				}))
			},
		},
		{
			name:   "user",
			wantDN: "uid=testuser1,cn=users,cn=accounts,dc=example,dc=test",
			build: func() (*v2.Resource, error) {
				return userResource(ctx, ldap3.NewEntry("uid=testuser1,cn=users,cn=accounts,dc=example,dc=test", map[string][]string{
					attrIPAUniqueID:    {"user-unique-id"},
					attrUserUID:        {"testuser1"},
					attrUserCommonName: {"Test User1"},
					attrFirstName:      {"Test"},
					attrLastName:       {"User1"},
					attrObjectClass:    {"posixaccount", "person"},
				}))
			},
		},
		{
			// Hosts have no trait. Before baton-sdk v0.20.x moved the profile
			// onto Resource itself there was nowhere for a host to keep its DN.
			name:   "host",
			wantDN: "fqdn=host1.example.test,cn=computers,cn=accounts,dc=example,dc=test",
			build: func() (*v2.Resource, error) {
				return hostResource(ctx, ldap3.NewEntry("fqdn=host1.example.test,cn=computers,cn=accounts,dc=example,dc=test", map[string][]string{
					attrIPAUniqueID: {"host-unique-id"},
					attrCommonName:  {"host1.example.test"},
					attrDescription: {"a host"},
				}))
			},
		},
		{
			// Host groups were built with an empty profile, leaving the DN read
			// in Entitlements()/Grants() nothing to fall back to.
			name:   "host group",
			wantDN: "cn=testhostgroup1,cn=hostgroups,cn=accounts,dc=example,dc=test",
			build: func() (*v2.Resource, error) {
				return hostGroupResource(ctx, ldap3.NewEntry("cn=testhostgroup1,cn=hostgroups,cn=accounts,dc=example,dc=test", map[string][]string{
					attrIPAUniqueID: {"host-group-unique-id"},
					attrCommonName:  {"testhostgroup1"},
					attrDescription: {"a host group"},
				}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := tt.build()
			require.NoError(t, err)

			dn, err := getDNFromResource(resource)
			require.NoError(t, err)
			require.Equal(t, tt.wantDN, dn)
		})
	}
}
