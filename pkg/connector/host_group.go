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

	// Member lookup by DN.
	ipaObjectCache *ipaObjectCache
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
	hostGroupDN := hdn.String()

	ipaUniqueID := hostGroup.GetEqualFoldAttributeValue(attrIPAUniqueID)
	hostGroupName := hostGroup.GetEqualFoldAttributeValue(attrCommonName)
	description := hostGroup.GetEqualFoldAttributeValue(attrDescription)

	// Host groups previously carried an empty profile, leaving Entitlements() and
	// Grants() nothing to resolve a DN from once c1 dropped ExternalId.
	resource, err := rs.NewGroupResource(
		hostGroupName,
		resourceTypeHostGroup,
		ipaUniqueID,
		[]rs.GroupTraitOption{},
		rs.WithDescription(description),
		rs.WithResourceProfile(map[string]interface{}{
			pathProfileProperty: hostGroupDN,
		}),
	)
	if err != nil {
		return nil, err
	}
	return resource, nil
}

func inheritedHBACEntitlementID(hostGroupName string, hbacRuleName string) string {
	return fmt.Sprintf("%s - %s", hostGroupName, hbacRuleName)
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

func (r *hostGroupResourceType) Entitlements(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Entitlement

	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if pt.Token == "" {
		bag.Push(pagination.PageState{
			ResourceTypeID: hbacRuleEntryType,
		})
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeHostGroup.Id,
		})
	}

	var pageToken string
	if bag.Current().ResourceTypeID == resourceTypeHostGroup.Id { // Static entitlements for host group
		assignmentOptions := []ent.EntitlementOption{
			ent.WithGrantableTo(resourceTypeHost, resourceTypeHostGroup),
			ent.WithDisplayName(fmt.Sprintf("%s host group %s", resource.DisplayName, hostGroupMembershipEntitlement)),
			ent.WithDescription(fmt.Sprintf("Member of %s host group", resource.DisplayName)),
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
			ent.WithDisplayName(fmt.Sprintf("%s host group %s", resource.DisplayName, hostGroupMemberManagerEntitlement)),
			ent.WithDescription(fmt.Sprintf("Manager of %s host group", resource.DisplayName)),
		))

		bag.Pop()

		pageToken, err = bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}
	}

	if bag.Current() != nil && bag.Current().ResourceTypeID == hbacRuleEntryType { // Dynamic entitlements for host group hbac rules
		hostGroupDN, err := getDNFromResource(resource)
		if err != nil {
			return nil, "", nil, err
		}

		filter := fmt.Sprintf(hbacRuleHostFilter, hostGroupDN)

		hbacRuleEntries, nextPage, err := r.client.LdapSearch(
			ctx,
			ldap3.ScopeWholeSubtree,
			r.baseDN,
			filter,
			nil,
			bag.Current().Token,
			ResourcesPageSize,
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("baton-ipa: failed to list hbac rules in '%s': %w", r.baseDN.String(), err)
		}

		pageToken, err = bag.NextToken(nextPage)
		if err != nil {
			return nil, "", nil, err
		}

		if len(hbacRuleEntries) == 0 {
			return rv, pageToken, nil, nil
		}

		// Get all hosts in the host group
		members, err := r.getHostGroupMembers(ctx, l, resource)
		if err != nil {
			return nil, "", nil, err
		}

		for _, hbacRuleEntry := range hbacRuleEntries {
			accessRule := hbacRuleEntry.GetEqualFoldAttributeValue(attrCommonName)
			assignmentOptions := []ent.EntitlementOption{
				ent.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
				ent.WithDisplayName(fmt.Sprintf("%s host group %s HBAC rule", resource.DisplayName, accessRule)),
				ent.WithDescription(fmt.Sprintf("Allows access to host group via HBAC rule %s", accessRule)),
			}

			rv = append(rv, ent.NewAssignmentEntitlement(
				resource,
				accessRule,
				assignmentOptions...,
			))

			// Create corresponding entitlements for each host in the host group
			for _, member := range members {
				rv = append(rv, ent.NewAssignmentEntitlement(
					&v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeHost.Id,
							Resource:     member.ipaUniqueID,
						},
					},
					inheritedHBACEntitlementID(resource.DisplayName, accessRule),
					ent.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
					ent.WithDisplayName(fmt.Sprintf("%s host group %s HBAC rule", resource.DisplayName, accessRule)),
					ent.WithDescription(fmt.Sprintf("Allows inherited access to %s via HBAC rule %s and host group %s", member.cn, accessRule, resource.DisplayName)),
				))
			}
		}
	}

	return rv, pageToken, nil, nil
}

func (r *hostGroupResourceType) processHbacRuleEntries(ctx context.Context, resource *v2.Resource, hbacRuleEntries []*ldap3.Entry) ([]*v2.Grant, error) {
	l := ctxzap.Extract(ctx)
	var grants []*v2.Grant

	hostMembers, err := r.getHostGroupMembers(ctx, l, resource)
	if err != nil {
		return nil, fmt.Errorf("baton-ipa: failed to get host group members: %w", err)
	}

	for _, hbacRuleEntry := range hbacRuleEntries {
		accessRule := hbacRuleEntry.GetEqualFoldAttributeValue(attrCommonName)
		userCategory := hbacRuleEntry.GetEqualFoldAttributeValue(attrHBACRuleUserCategory)

		if userCategory == "all" { // access is granted to all users
			grants = append(grants, grant.NewGrant(
				resource,
				accessRule,
				&v2.ResourceId{
					ResourceType: resourceTypeGroup.Id,
					Resource:     internalAnyoneGroupID,
				},
				grant.WithAnnotation(&v2.GrantExpandable{
					EntitlementIds: []string{
						fmt.Sprintf("group:%s:member", internalAnyoneGroupID),
					},
				}),
			))

			// Apply the grant to each host in the host group
			for _, host := range hostMembers {
				grants = append(grants, grant.NewGrant(
					&v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeHost.Id,
							Resource:     host.ipaUniqueID,
						},
					},
					inheritedHBACEntitlementID(resource.DisplayName, accessRule),
					&v2.ResourceId{
						ResourceType: resourceTypeGroup.Id,
						Resource:     internalAnyoneGroupID,
					},
					grant.WithAnnotation(&v2.GrantExpandable{
						EntitlementIds: []string{
							fmt.Sprintf("group:%s:member", internalAnyoneGroupID),
						},
					}),
				))
			}
		} else { // access is granted to specific users
			members := parseValues(hbacRuleEntry, []string{attrHBACRuleMemberUser})

			// for each member, lookup the ipaUniqueID and resource type
			for _, member := range members.ToSlice() {
				m, err := r.ipaObjectCache.get(ctx, member)
				if err != nil {
					return nil, fmt.Errorf("baton-ipa: failed to get member %s: %w", member, err)
				}

				grant, err := newHbacRuleGrantFromDN(resource, accessRule, m.ipaUniqueID, m.resourceType)
				if err != nil {
					return nil, fmt.Errorf("baton-ipa: failed to create grant for member %s: %w", member, err)
				}

				grants = append(grants, grant)

				// Apply the grant to each host in the host group
				for _, host := range hostMembers {
					hostResource := &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeHost.Id,
							Resource:     host.ipaUniqueID,
						},
					}
					entitlementID := inheritedHBACEntitlementID(resource.DisplayName, accessRule)
					grant, err := newHbacRuleGrantFromDN(hostResource, entitlementID, m.ipaUniqueID, m.resourceType)
					if err != nil {
						return nil, fmt.Errorf("baton-ipa: failed to create grant for host %s: %w", host.ipaUniqueID, err)
					}
					grants = append(grants, grant)
				}
			}
		}
	}

	return grants, nil
}

func (r *hostGroupResourceType) Grants(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var grants []*v2.Grant
	l := ctxzap.Extract(ctx)

	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if pt.Token == "" {
		bag.Push(pagination.PageState{
			ResourceTypeID: hbacRuleEntryType,
		})
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeHostGroup.Id,
		})
	}

	// Both branches below need the host group DN, and the HBAC branch runs on a
	// later page - after the static branch has been popped - so resolve it up
	// front rather than inside a branch.
	hostGroupDN, err := getDNFromResource(resource)
	if err != nil {
		return nil, "", nil, err
	}
	l = l.With(zap.String("host_group_dn", hostGroupDN))

	var pageToken string
	if bag.Current().ResourceTypeID == resourceTypeHostGroup.Id { // Static (member/manager) grants for host group
		var ldapHostGroup *ldap3.Entry
		ldapHostGroup, err = r.getHostGroupWithFallback(ctx, l, resource.Id, hostGroupDN)
		if err != nil {
			l.Error("baton-ipa: failed to list host group members", zap.String("resource_id", resource.Id.Resource), zap.Error(err))
			return nil, "", nil, fmt.Errorf("baton-ipa: failed to list host group %s members: %w", resource.Id.Resource, err)
		}

		members := parseValues(ldapHostGroup, []string{attrHostGroupMember, attrHostGroupManager})
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
				l.Error("baton-ipa: failed to get host group member", zap.String("member_dn", memberDN), zap.Error(err))
				continue
			}
			var g *v2.Grant
			if len(member) != 1 {
				l.Warn("baton-ipa: member not found", zap.String("member_dn", memberDN))
				continue
			}

			g = newHostGroupGrantFromEntry(resource, member[0])
			if g == nil {
				l.Warn("baton-ipa: member not supported", zap.String("member_dn", memberDN))
				continue
			}

			if g.Id == "" {
				l.Error("baton-ipa: failed to create grant", zap.String("member_dn", memberDN), zap.Error(err))
				continue
			}
			grants = append(grants, g)
		}

		grants = uniqueGrants(grants)

		bag.Pop()
		pageToken, err = bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}
	}

	if bag.Current().ResourceTypeID == hbacRuleEntryType { // Dynamic grants for host group hbac rules
		filter := fmt.Sprintf(hbacRuleHostFilter, hostGroupDN)
		hbacRuleEntries, nextPage, err := r.client.LdapSearch(
			ctx,
			ldap3.ScopeWholeSubtree,
			r.baseDN,
			filter,
			nil,
			bag.Current().Token,
			ResourcesPageSize,
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("baton-ipa: failed to list hbac rules in '%s': %w", r.baseDN.String(), err)
		}

		if len(hbacRuleEntries) > 0 {
			dynamicGrants, err := r.processHbacRuleEntries(ctx, resource, hbacRuleEntries)
			if err != nil {
				return nil, "", nil, err
			}
			grants = append(grants, dynamicGrants...)
		}

		pageToken, err = bag.NextToken(nextPage)
		if err != nil {
			return nil, "", nil, err
		}
	}

	return grants, pageToken, nil, nil
}

// getHostGroupWithFallback get an LDAP entry for a host group.
// It first tries to get the host group by its DN. If that fails, it tries to get the host group by its IPA unique ID.
func (r *hostGroupResourceType) getHostGroupWithFallback(ctx context.Context, l *zap.Logger, resourceId *v2.ResourceId, hostGroupDN string) (*ldap3.Entry, error) {
	hostGroup, err := r.client.LdapGetWithStringDN(
		ctx,
		hostGroupDN,
		hostGroupFilter,
		nil,
	)
	if err == nil {
		return hostGroup, nil
	}

	if ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) {
		filter := fmt.Sprintf(ipaUniqueIDFilter, resourceId.Resource)
		hostGroups, _, err := r.client.LdapSearch(
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
		if len(hostGroups) == 0 {
			notFoundError := status.Errorf(codes.NotFound, "baton-ipa: no such object")
			return nil, notFoundError
		}
		if len(hostGroups) > 1 {
			l.Error("baton-ipa: multiple host groups found", zap.String("host_group_dn", hostGroupDN), zap.Error(err))
			return nil, fmt.Errorf("baton-ipa: multiple host groups found")
		}
		return hostGroups[0], nil
	}

	return nil, err
}

func (r *hostGroupResourceType) getHostGroupMembers(ctx context.Context, l *zap.Logger, resource *v2.Resource) ([]*ipaObject, error) {
	hostGroupDN, err := getDNFromResource(resource)
	if err != nil {
		return nil, err
	}

	hostGroup, err := r.getHostGroupWithFallback(ctx, l, resource.Id, hostGroupDN)
	if err != nil {
		return nil, fmt.Errorf("baton-ipa: failed to get host group members: %w", err)
	}

	memberDistinguishedNames := parseValues(hostGroup, []string{attrHostGroupMember})
	members := make([]*ipaObject, 0, len(memberDistinguishedNames.ToSlice()))
	for _, memberDN := range memberDistinguishedNames.ToSlice() {
		member, err := r.ipaObjectCache.get(ctx, memberDN)
		if err != nil {
			return nil, fmt.Errorf("baton-ipa: failed to get host group member: %w", err)
		}
		members = append(members, member)
	}

	return members, nil
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
		&v2.Resource{
			Id: hostGroupResource.Id,
		},
		entitlement,
		&v2.ResourceId{
			ResourceType: resourceType.Id,
			Resource:     ipaUniqueID,
		},
		grantOpts...,
	)
	return g
}

func hostGroupBuilder(client *ldap.Client, baseDN *ldap3.DN, ipaObjectCache *ipaObjectCache) *hostGroupResourceType {
	return &hostGroupResourceType{
		resourceType:   resourceTypeHostGroup,
		client:         client,
		baseDN:         baseDN,
		ipaObjectCache: ipaObjectCache,
	}
}
