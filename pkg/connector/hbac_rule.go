package connector

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
)

func newHbacRuleGrantFromDN(resource *v2.Resource, accessRule string, ipaUniqueID string, resourceType *v2.ResourceType) (*v2.Grant, error) {
	grantOpts := []grant.GrantOption{}
	if resourceType == resourceTypeGroup {
		grantOpts = append(grantOpts, grant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("group:%s:member", ipaUniqueID),
			},
		}))
	}

	switch resourceType {
	case resourceTypeGroup:
		// supported
	case resourceTypeUser:
		// supported
	default:
		return nil, fmt.Errorf("baton-ipa: unsupported resource type: %s", resourceType.Id)
	}

	g := grant.NewGrant(
		// remove group profile from grant so we're not saving all group memberships in every grant
		&v2.Resource{
			Id: resource.Id,
		},
		accessRule,
		// remove user profile from grant so we're not saving repetitive user info in every grant
		&v2.ResourceId{
			ResourceType: resourceType.Id,
			Resource:     ipaUniqueID,
		},
		grantOpts...,
	)
	return g, nil
}
