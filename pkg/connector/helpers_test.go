package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

func TestGetDNFromResource(t *testing.T) {
	const dn = "cn=admins,cn=groups,cn=accounts,dc=example,dc=test"

	groupWithProfilePath, err := rs.NewGroupResource("admins", resourceTypeGroup, "group-unique-id", nil,
		rs.WithResourceProfile(map[string]interface{}{pathProfileProperty: dn}))
	require.NoError(t, err)

	userWithProfilePath, err := rs.NewUserResource("jdoe", resourceTypeUser, "user-unique-id", nil,
		rs.WithResourceProfile(map[string]interface{}{pathProfileProperty: dn}))
	require.NoError(t, err)

	// Hosts have no trait at all. Since baton-sdk v0.20.x the profile lives on
	// Resource itself, so they carry a DN like every other resource type.
	hostWithProfilePath, err := rs.NewResource("host1.example.test", resourceTypeHost, "host-unique-id",
		rs.WithResourceProfile(map[string]interface{}{pathProfileProperty: dn}))
	require.NoError(t, err)

	groupWithoutPath, err := rs.NewGroupResource("admins", resourceTypeGroup, "group-unique-id", nil,
		rs.WithResourceProfile(map[string]interface{}{"group_description": "no path here"}))
	require.NoError(t, err)

	groupWithoutProfile, err := rs.NewGroupResource("admins", resourceTypeGroup, "group-unique-id", nil)
	require.NoError(t, err)

	tests := []struct {
		name     string
		resource *v2.Resource
		wantDN   string
		wantErr  bool
	}{
		{name: "group profile path", resource: groupWithProfilePath, wantDN: dn},
		{name: "user profile path", resource: userWithProfilePath, wantDN: dn},
		{name: "host profile path", resource: hostWithProfilePath, wantDN: dn},
		{name: "profile without a path", resource: groupWithoutPath, wantErr: true},
		{name: "no profile at all", resource: groupWithoutProfile, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getDNFromResource(tt.resource)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantDN, got)
		})
	}
}

func TestSameDN(t *testing.T) {
	const dn = "cn=admins,cn=groups,cn=accounts,dc=example,dc=test"

	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "identical", a: dn, b: dn, want: true},
		{name: "attribute type case differs", a: dn, b: "CN=admins,CN=groups,CN=accounts,DC=example,DC=test", want: true},
		{name: "value case differs", a: dn, b: "cn=Admins,cn=Groups,cn=accounts,dc=example,dc=test", want: true},
		{name: "spacing differs", a: dn, b: "cn=admins, cn=groups, cn=accounts, dc=example, dc=test", want: true},
		{name: "different object", a: dn, b: "cn=users,cn=groups,cn=accounts,dc=example,dc=test", want: false},
		{name: "different depth", a: dn, b: "cn=admins,cn=accounts,dc=example,dc=test", want: false},
		{name: "unparseable", a: dn, b: "not-a-dn", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, sameDN(tt.a, tt.b))
			require.Equal(t, tt.want, sameDN(tt.b, tt.a))
		})
	}
}
