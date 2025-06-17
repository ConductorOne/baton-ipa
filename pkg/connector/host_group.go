package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	hostGroupMembershipEntitlement    = "member"
	hostGroupMemberManagerEntitlement = "manager"

	hostGroupFilter = "(&(objectClass=ipahostgroup))"

	attrHostGroupMember  = "member"
	attrHostGroupManager = "memberManager"
)

type hostGroupResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
	baseDN       *ldap3.DN
}

func (r *hostGroupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// Create a new connector resource for an IPA Host.
func hostGroupResource(ctx context.Context, hostGroup *ldap.Entry) (*v2.Resource, error) {
	hdn, err := ldap.CanonicalizeDN(hostGroup.DN)
	if err != nil {
		return nil, err
	}
	hostDN := hdn.String()

	ipaUniqueID := hostGroup.GetEqualFoldAttributeValue(attrIPAUniqueID)
	hostGroupName := hostGroup.GetEqualFoldAttributeValue(attrCommonName)
	description := hostGroup.GetEqualFoldAttributeValue(attrDescription)

	resource, err := rs.NewResource(
		hostGroupName,
		resourceTypeHostGroup,
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

func (r *hostGroupResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeHost.Id})
	if err != nil {
		return nil, "", nil, err
	}

	entries, nextPage, err := r.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		r.baseDN,
		hostGroupFilter,
		nil,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, hostGroup := range entries {
		hr, err := hostGroupResource(ctx, hostGroup)
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

func (r *hostGroupResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeHost, resourceTypeHostGroup),
		ent.WithDisplayName(fmt.Sprintf("%s Host Group %s", resource.DisplayName, hostGroupMembershipEntitlement)),
		ent.WithDescription(fmt.Sprintf("Access to %s host group in IPA", resource.DisplayName)),
	}

	// create membership entitlement
	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		hostGroupMembershipEntitlement,
		assignmentOptions...,
	))

	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		hostGroupMemberManagerEntitlement,
		ent.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
		ent.WithDisplayName(fmt.Sprintf("%s Host Group %s", resource.DisplayName, hostGroupMemberManagerEntitlement)),
		ent.WithDescription(fmt.Sprintf("Manage %s host group in IPA", resource.DisplayName)),
	))

	return rv, "", nil, nil
}

func (r *hostGroupResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	externalId := resource.GetExternalId()
	if externalId == nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: hbac rule %s has no external ID", resource.Id.Resource)
	}

	hostGroupDN, err := ldap.CanonicalizeDN(externalId.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("baton-ipa: invalid host group DN: '%s' in host group grants: %w", resource.Id.Resource, err)
	}
	l = l.With(zap.Stringer("host_group_dn", hostGroupDN))

	var ldapHostGroup *ldap3.Entry
	ldapHostGroup, err = r.getHostGroupWithFallback(ctx, l, resource.Id, externalId)
	if err != nil {
		l.Error("baton-ipa: failed to list host group members", zap.String("host_group_dn", resource.Id.Resource), zap.Error(err))
		return nil, "", nil, fmt.Errorf("baton-ipa: failed to list host group %s members: %w", resource.Id.Resource, err)
	}

	members := parseValues(ldapHostGroup, []string{attrHostGroupMember, attrHostGroupManager})

	// create grants
	var rv []*v2.Grant
	for memberDN := range members.Iter() {
		_, err := ldap.CanonicalizeDN(memberDN)
		if err != nil {
			l.Error("baton-ipa: invalid member DN", zap.String("member_dn", memberDN), zap.Error(err))
			continue
		}

		member, _, err := r.client.LdapSearchWithStringDN(
			ctx,
			ldap3.ScopeBaseObject,
			memberDN,
			"",
			nil,
			"",
			1,
		)
		if err != nil {
			l.Error("baton-ipa: failed to get host group member", zap.String("host_group_dn", resource.Id.Resource), zap.String("member_dn", memberDN), zap.Error(err))
			continue
		}
		var g *v2.Grant
		if len(member) != 1 {
			l.Warn("baton-ipa: member not found", zap.String("host_group_dn", resource.Id.Resource), zap.String("member_dn", memberDN))
			continue
		}

		g = newHostGroupGrantFromEntry(resource, member[0])
		if g == nil {
			l.Warn("baton-ipa: member not supported", zap.String("host_group_dn", resource.Id.Resource), zap.String("member_dn", memberDN))
			continue
		}

		if g.Id == "" {
			l.Error("baton-ipa: failed to create grant", zap.String("host_group_dn", resource.Id.Resource), zap.String("member_dn", memberDN), zap.Error(err))
			continue
		}
		rv = append(rv, g)
	}

	rv = uniqueGrants(rv)

	return rv, "", nil, nil
}

func (r *hostGroupResourceType) getHostGroupWithFallback(ctx context.Context, l *zap.Logger, resourceId *v2.ResourceId, externalId *v2.ExternalId) (*ldap3.Entry, error) {
	hostGroupDN := externalId.Id
	ldapRule, err := r.client.LdapGetWithStringDN(
		ctx,
		hostGroupDN,
		hostGroupFilter,
		nil,
	)
	if err == nil {
		return ldapRule, nil
	}

	if ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) {
		filter := fmt.Sprintf(ipaUniqueIDFilter, resourceId.Resource)
		ldapRules, _, err := r.client.LdapSearch(
			ctx,
			ldap3.ScopeWholeSubtree,
			r.baseDN,
			filter,
			nil,
			"",
			2,
		)
		if err != nil {
			l.Error("baton-ipa: failed to get host group", zap.String("host_group_dn", hostGroupDN), zap.Error(err))
			return nil, err
		}
		if len(ldapRules) == 0 {
			notFoundError := status.Errorf(codes.NotFound, "baton-ipa: no such object")
			return nil, notFoundError
		}
		if len(ldapRules) > 1 {
			l.Error("baton-ipa: multiple host groups found", zap.String("host_group_dn", hostGroupDN), zap.Error(err))
			return nil, fmt.Errorf("baton-ipa: multiple host groups found")
		}
		return ldapRules[0], nil
	}

	return nil, err
}

func newHostGroupGrantFromEntry(hostGroupResource *v2.Resource, entry *ldap3.Entry) *v2.Grant {
	ipaUniqueID := entry.GetEqualFoldAttributeValue(attrIPAUniqueID)

	for _, objectClass := range entry.GetAttributeValues("objectClass") {
		if resourceType, ok := objectClassesToResourceTypes[objectClass]; ok {
			return newHostGroupGrantFromDN(hostGroupResource, ipaUniqueID, resourceType)
		}
	}

	return nil
}

func newHostGroupGrantFromDN(hostGroupResource *v2.Resource, ipaUniqueID string, resourceType *v2.ResourceType) *v2.Grant {
	grantOpts := []grant.GrantOption{}

	switch resourceType {
	case resourceTypeHostGroup:
		grantOpts = append(grantOpts, grant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("host_group:%s:member", ipaUniqueID),
			},
		}))
	case resourceTypeGroup:
		grantOpts = append(grantOpts, grant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("group:%s:member", ipaUniqueID),
			},
		}))
	}

	entitlement := hostGroupMembershipEntitlement
	switch resourceType {
	// Making an assumption that if the resource type is a group or user, the grant is for the manager entitlement
	case resourceTypeGroup, resourceTypeUser:
		entitlement = hostGroupMemberManagerEntitlement
	}

	g := grant.NewGrant(
		// remove group profile from grant so we're not saving all group memberships in every grant
		&v2.Resource{
			Id: hostGroupResource.Id,
		},
		entitlement,
		// remove user profile from grant so we're not saving repetitive user info in every grant
		&v2.ResourceId{
			ResourceType: resourceType.Id,
			Resource:     ipaUniqueID,
		},
		grantOpts...,
	)
	return g
}

func hostGroupBuilder(client *ldap.Client, baseDN *ldap3.DN) *hostGroupResourceType {
	return &hostGroupResourceType{
		resourceType: resourceTypeHostGroup,
		client:       client,
		baseDN:       baseDN,
	}
}
