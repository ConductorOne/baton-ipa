package connector

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"

	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
	membersCache   map[string]*member
	membersCacheMu sync.RWMutex
}

type member struct {
	ipaUniqueID  string
	dn           string
	resourceType *v2.ResourceType
}

func (r *hostResourceType) getMember(ctx context.Context, dn string) (*member, error) {
	r.membersCacheMu.RLock()
	defer r.membersCacheMu.RUnlock()

	m, ok := r.membersCache[dn]
	if ok {
		return m, nil
	}

	memberEntry, err := r.client.LdapGetWithStringDN(ctx, dn, "", []string{attrIPAUniqueID, attrObjectClass})
	if err != nil {
		return nil, fmt.Errorf("baton-ipa: failed to search for member %s: %w", dn, err)
	}

	ipaUniqueID := memberEntry.GetEqualFoldAttributeValue(attrIPAUniqueID)

	var resourceType *v2.ResourceType
	for _, objectClass := range memberEntry.GetAttributeValues(attrObjectClass) {
		if rt, ok := objectClassesToResourceTypes[objectClass]; ok {
			resourceType = rt
			break
		}
	}

	if resourceType == nil {
		return nil, fmt.Errorf("baton-ipa: unsupported object class for member %s: %s", dn, strings.Join(memberEntry.GetAttributeValues("objectClass"), ", "))
	}

	m = &member{
		ipaUniqueID:  ipaUniqueID,
		dn:           dn,
		resourceType: resourceType,
	}

	r.membersCache[dn] = m
	return m, nil
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
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: "hbac_rule"})
	if err != nil {
		return nil, "", nil, err
	}

	hostDN := resource.GetExternalId().GetId()
	if hostDN == "" {
		return nil, "", nil, fmt.Errorf("baton-ipa: host resource %s has no external ID", resource.DisplayName)
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
	l := ctxzap.Extract(ctx)

	hostDN := resource.GetExternalId().GetId()
	if hostDN == "" {
		return nil, "", nil, fmt.Errorf("baton-ipa: host resource %s has no external ID", resource.DisplayName)
	}

	canonicalDN, err := ldap.CanonicalizeDN(hostDN)
	if err != nil {
		return nil, "", nil, fmt.Errorf("baton-ipa: invalid host DN: '%s' in host grants: %w", resource.Id.Resource, err)
	}
	l = l.With(zap.Stringer("host_dn", canonicalDN))

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
		return nil, "", nil, fmt.Errorf("baton-ipa: failed to list hbac rules in '%s': %w", r.baseDN.String(), err)
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
			m, err := r.getMember(ctx, member)
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
		membersCache:   make(map[string]*member),
		membersCacheMu: sync.RWMutex{},
	}
}
