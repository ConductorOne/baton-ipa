package connector

import (
	"context"

	"github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	ldap3 "github.com/go-ldap/ldap/v3"
)

const (
	hostFilter = "(&(objectClass=ipahost))"
)

type hostResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
	baseDN       *ldap3.DN
}

func (r *hostResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// Create a new connector resource for an IPA Host.
func hostResource(ctx context.Context, host *ldap.Entry) (*v2.Resource, error) {
	hdn, err := ldap.CanonicalizeDN(host.DN)
	if err != nil {
		return nil, err
	}
	hostDN := hdn.String()

	ipaUniqueID := host.GetEqualFoldAttributeValue(attrIPAUniqueID)
	hostName := host.GetEqualFoldAttributeValue(attrCommonName)
	description := host.GetEqualFoldAttributeValue(attrDescription)

	resource, err := rs.NewResource(
		hostName,
		resourceTypeHost,
		ipaUniqueID,
		rs.WithDescription(description),
		rs.WithExternalID(&v2.ExternalId{
			Id: hostDN,
		}),
	)
	if err != nil {
		return nil, err
	}
	return resource, nil
}

func (r *hostResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeHost.Id})
	if err != nil {
		return nil, "", nil, err
	}

	hostEntries, nextPage, err := r.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		r.baseDN,
		hostFilter,
		nil,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, host := range hostEntries {
		hr, err := hostResource(ctx, host)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, hr)
	}

	nextPageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextPageToken, nil, nil
}

func (r *hostResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (r *hostResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func hostBuilder(client *ldap.Client, baseDN *ldap3.DN) *hostResourceType {
	return &hostResourceType{
		resourceType: resourceTypeHost,
		client:       client,
		baseDN:       baseDN,
	}
}
