package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

func TestGetDNFromResource(t *testing.T) {
	const dn = "cn=admins,cn=groups,cn=accounts,dc=example,dc=test"

	groupWithExternalID, err := rs.NewGroupResource("admins", resourceTypeGroup, "group-unique-id", nil,
		rs.WithExternalID(&v2.ExternalId{Id: dn}))
	require.NoError(t, err)

	groupWithProfilePath, err := rs.NewGroupResource("admins", resourceTypeGroup, "group-unique-id", nil,
		rs.WithResourceProfile(map[string]interface{}{pathProfileProperty: dn}))
	require.NoError(t, err)

	userWithProfilePath, err := rs.NewUserResource("jdoe", resourceTypeUser, "user-unique-id", nil,
		rs.WithResourceProfile(map[string]interface{}{pathProfileProperty: dn}))
	require.NoError(t, err)

	groupWithNeither, err := rs.NewGroupResource("admins", resourceTypeGroup, "group-unique-id", nil,
		rs.WithResourceProfile(map[string]interface{}{"group_description": "no path here"}))
	require.NoError(t, err)

	tests := []struct {
		name     string
		resource *v2.Resource
		wantDN   string
		wantErr  bool
	}{
		{name: "external_id present", resource: groupWithExternalID, wantDN: dn},
		{name: "external_id nil but group resource profile path present", resource: groupWithProfilePath, wantDN: dn},
		{name: "external_id nil but user resource profile path present", resource: userWithProfilePath, wantDN: dn},
		{name: "neither external_id nor profile path present", resource: groupWithNeither, wantErr: true},
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
