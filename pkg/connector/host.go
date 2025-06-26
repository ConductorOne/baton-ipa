package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"

	ldap3 "github.com/go-ldap/ldap/v3"
)

const (
	hostFilter              = "(&(objectClass=ipahost))"
	hostHbacRuleFilter      = "(&(objectClass=ipahbacrule)(memberHost=%s))"
	hostHbacRuleEntitlement = "access"
)

type hostResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
	baseDN       *ldap3.DN

	// Member lookup by DN.
	ipaObjectCache *ipaObjectCache
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

func (r *hostResourceType) Entitlements(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeHbacRule.Id})
	if err != nil {
		return nil, "", nil, err
	}

	hostDN := resource.GetExternalId().GetId()
	if hostDN == "" {
		return nil, "", nil, fmt.Errorf("baton-ipa: host resource %s has no external ID", resource.DisplayName)
	}

	hbacRuleEntries, nextPage, err := r.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		r.baseDN,
		hbacRuleFilter,
		nil,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("baton-ipa: failed to list hbac rules in '%s': %w", r.baseDN.String(), err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Entitlement
	for _, hbacRuleEntry := range hbacRuleEntries {
		accessRule := hbacRuleEntry.GetEqualFoldAttributeValue(attrCommonName)
		assignmentOptions := []ent.EntitlementOption{
			ent.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
			ent.WithDisplayName(fmt.Sprintf("%s Host HBAC Rule %s", resource.DisplayName, accessRule)),
			ent.WithDescription(fmt.Sprintf("Host-Based Access Control for Host %s via rule '%s'", resource.DisplayName, accessRule)),
		}

		rv = append(rv, ent.NewAssignmentEntitlement(
			resource,
			accessRule,
			assignmentOptions...,
		))
	}

	return rv, pageToken, nil, nil
}

func (r *hostResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	hostDN := resource.GetExternalId().GetId()
	if hostDN == "" {
		return nil, "", nil, fmt.Errorf("baton-ipa: host resource %s has no external ID", resource.DisplayName)
	}

	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: "hbac_rule"})
	if err != nil {
		return nil, "", nil, err
	}

	hbacRuleFilter := fmt.Sprintf(hostHbacRuleFilter, hostDN)
	hbacRuleEntries, nextPage, err := r.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		r.baseDN,
		hbacRuleFilter,
		nil,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("baton-ipa: failed to list hbac rules using filter '%s': %w", hbacRuleFilter, err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var grants []*v2.Grant
	for _, hbacRuleEntry := range hbacRuleEntries {
		accessRule := hbacRuleEntry.GetEqualFoldAttributeValue(attrCommonName)
		members := parseValues(hbacRuleEntry, []string{attrHBACRuleMemberUser})

		// for each member, lookup the ipaUniqueID and resource type
		for _, member := range members.ToSlice() {
			m, err := r.ipaObjectCache.get(ctx, member)
			if err != nil {
				return nil, "", nil, fmt.Errorf("baton-ipa: failed to get member %s: %w", member, err)
			}

			grant, err := newHbacRuleGrantFromDN(resource, accessRule, m.ipaUniqueID, m.resourceType)
			if err != nil {
				return nil, "", nil, fmt.Errorf("baton-ipa: failed to create grant for member %s: %w", member, err)
			}

			grants = append(grants, grant)
		}
	}

	return grants, pageToken, nil, nil
}

func hostBuilder(client *ldap.Client, baseDN *ldap3.DN) *hostResourceType {
	return &hostResourceType{
		resourceType:   resourceTypeHost,
		client:         client,
		baseDN:         baseDN,
		ipaObjectCache: newMemberCache(client, baseDN),
	}
}
