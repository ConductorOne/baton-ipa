package connector

import (
	"context"
	"errors"
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
	"golang.org/x/exp/slices"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var objectClassesToResourceTypes = map[string]*v2.ResourceType{
	"ipaUserGroup": resourceTypeGroup,
	"posixAccount": resourceTypeUser,
}

const (
	groupFilter     = "(&(objectClass=ipausergroup)" + excludeCompatFilter + ")"
	groupByIDFilter = `(&(objectClass=ipausergroup)(ipaUniqueID=%s)` + excludeCompatFilter + `)`

	groupMemberUIDFilter        = `(&` + userFilter + `(uid=%s))`
	groupMemberCommonNameFilter = `(&` + userFilter + `(cn=%s))`

	groupMemberGidNumber = `(&` + userFilter + `(gidNumber=%s))`

	attrGroupCommonName  = "cn"
	attrGroupIdPosix     = "gidNumber"
	attrGroupMember      = "member"
	attrGroupDescription = "description"
	attrGroupObjectGUID  = "objectGUID"

	groupMemberEntitlement = "member"
)

type groupResourceType struct {
	resourceType  *v2.ResourceType
	groupSearchDN *ldap3.DN
	userSearchDN  *ldap3.DN
	client        *ldap.Client
}

func (g *groupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// Create a new connector resource for an LDAP Group.
func groupResource(ctx context.Context, group *ldap.Entry) (*v2.Resource, error) {
	ipaUniqueID := group.GetEqualFoldAttributeValue(attrIPAUniqueID)
	if ipaUniqueID == "" {
		return nil, fmt.Errorf("ldap-connector: group %s has no ipaUniqueID", group.DN)
	}

	gdn, err := ldap.CanonicalizeDN(group.DN)
	if err != nil {
		return nil, err
	}
	groupDN := gdn.String()
	groupId := parseValue(group, []string{attrGroupIdPosix})
	description := group.GetEqualFoldAttributeValue(attrGroupDescription)
	profile := map[string]interface{}{
		"path": groupDN,
	}

	groupRsTraitOptions := []rs.ResourceOption{}
	groupRsTraitOptions = append(groupRsTraitOptions, rs.WithExternalID(&v2.ExternalId{
		Id: group.DN,
	}))
	if description != "" {
		profile["group_description"] = description
		groupRsTraitOptions = append(groupRsTraitOptions, rs.WithDescription(description))
	}

	if groupId != "" {
		profile["gid"] = groupId
	}

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	groupName := group.GetEqualFoldAttributeValue(attrGroupCommonName)

	resource, err := rs.NewGroupResource(
		groupName,
		resourceTypeGroup,
		ipaUniqueID,
		groupTraitOptions,
		groupRsTraitOptions...,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (g *groupResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeGroup.Id})
	if err != nil {
		return nil, "", nil, err
	}

	groupEntries, nextPage, err := g.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		g.groupSearchDN,
		groupFilter,
		nil,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ipa-connector: failed to list groups in '%s': %w", g.groupSearchDN.String(), err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, groupEntry := range groupEntries {
		gr, err := groupResource(ctx, groupEntry)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, gr)
	}

	return rv, pageToken, nil, nil
}

func (g *groupResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("getting group", zap.String("resource_id", resourceId.Resource))

	filter := fmt.Sprintf(groupByIDFilter, resourceId.Resource)

	groupEntries, _, err := g.client.LdapSearch(ctx, ldap3.ScopeWholeSubtree, g.groupSearchDN, filter, allAttrs, "", ResourcesPageSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ipa-connector: failed to get group: %w", err)
	}

	if len(groupEntries) == 0 {
		return nil, nil, fmt.Errorf("ipa-connector: group not found")
	}

	groupEntry := groupEntries[0]

	gr, err := groupResource(ctx, groupEntry)
	if err != nil {
		return nil, nil, fmt.Errorf("ipa-connector: failed to get group: %w", err)
	}

	return gr, nil, nil
}

func (g *groupResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDisplayName(fmt.Sprintf("%s Group %s", resource.DisplayName, groupMemberEntitlement)),
		ent.WithDescription(fmt.Sprintf("Access to %s group in LDAP", resource.DisplayName)),
	}

	// create membership entitlement
	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		groupMemberEntitlement,
		assignmentOptions...,
	))

	// TODO: Add entitlement for group manager

	return rv, "", nil, nil
}

// newGrantFromDN - create a `Grant` from a given group and user distinguished name.
func newGrantFromDN(groupResource *v2.Resource, ipaUniqueID string, resourceType *v2.ResourceType) *v2.Grant {
	grantOpts := []grant.GrantOption{}
	if resourceType == resourceTypeGroup {
		grantOpts = append(grantOpts, grant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("group:%s:member", ipaUniqueID),
			},
		}))
	}
	g := grant.NewGrant(
		// remove group profile from grant so we're not saving all group memberships in every grant
		&v2.Resource{
			Id: groupResource.Id,
		},
		groupMemberEntitlement,
		// remove user profile from grant so we're not saving repetitive user info in every grant
		&v2.ResourceId{
			ResourceType: resourceType.Id,
			Resource:     ipaUniqueID,
		},
		grantOpts...,
	)
	return g
}

func newGrantFromEntry(groupResource *v2.Resource, entry *ldap3.Entry) *v2.Grant {
	ipaUniqueID := entry.GetEqualFoldAttributeValue(attrIPAUniqueID)

	for _, objectClass := range entry.GetAttributeValues("objectClass") {
		if resourceType, ok := objectClassesToResourceTypes[objectClass]; ok {
			return newGrantFromDN(groupResource, ipaUniqueID, resourceType)
		}
	}

	return newGrantFromDN(groupResource, ipaUniqueID, resourceTypeUser)
}

func (g *groupResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	externalId := resource.GetExternalId()
	if externalId == nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: group %s has no external ID", resource.Id.Resource)
	}

	groupDN, err := ldap.CanonicalizeDN(externalId.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ipa-connector: invalid group DN: '%s' in group grants: %w", resource.Id.Resource, err)
	}
	l = l.With(zap.Stringer("group_dn", groupDN))

	var ldapGroup *ldap3.Entry
	ldapGroup, err = g.getGroupWithFallback(ctx, l, resource.Id, externalId)
	if err != nil {
		l.Error("ipa-connector: failed to list group members", zap.String("group_dn", resource.Id.Resource), zap.Error(err))
		return nil, "", nil, fmt.Errorf("ipa-connector: failed to list group %s members: %w", resource.Id.Resource, err)
	}

	memberDNs := parseValues(ldapGroup, []string{attrGroupMember})

	// create membership grants
	var rv []*v2.Grant
	for memberDN := range memberDNs.Iter() {
		parsedDN, err := ldap.CanonicalizeDN(memberDN)
		if err != nil {
			l.Error("ipa-connector: invalid member DN", zap.String("member_dn", memberDN), zap.Error(err))
			continue
		}

		member, _, err := g.client.LdapSearchWithStringDN(
			ctx,
			ldap3.ScopeWholeSubtree,
			memberDN,
			"",
			nil,
			"",
			1,
		)
		if err != nil {
			l.Error("ipa-connector: failed to get group member", zap.String("group", groupDN.String()), zap.String("member_dn", memberDN), zap.Error(err))
		}
		var g *v2.Grant
		if len(member) == 1 {
			g = newGrantFromEntry(resource, member[0])
		} else {
			// Fall back to creating a grant and assuming it's for a user.
			g = newGrantFromDN(resource, parsedDN.String(), resourceTypeUser)
			l.Warn("ipa-connector: multiple members found", zap.String("group", groupDN.String()), zap.String("member_dn", memberDN))
		}

		if g.Id == "" {
			l.Error("ipa-connector: failed to create grant", zap.String("group", groupDN.String()), zap.String("member_dn", memberDN), zap.Error(err))
			continue
		}
		rv = append(rv, g)
	}

	rv = uniqueGrants(rv)

	return rv, "", nil, nil
}

func (g *groupResourceType) getGroupWithFallback(ctx context.Context, l *zap.Logger, resourceId *v2.ResourceId, externalId *v2.ExternalId) (*ldap3.Entry, error) {
	groupDN := externalId.Id
	ldapGroup, err := g.client.LdapGetWithStringDN(
		ctx,
		groupDN,
		groupFilter,
		nil,
	)
	if err == nil {
		return ldapGroup, nil
	}

	if ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) {
		filter := fmt.Sprintf(ipaUniqueIDFilter, resourceId.Resource)
		ldapGroups, _, err := g.client.LdapSearch(
			ctx,
			ldap3.ScopeWholeSubtree,
			g.groupSearchDN,
			filter,
			nil,
			"",
			2,
		)
		if err != nil {
			l.Error("ipa-connector: failed to get group", zap.String("group_dn", groupDN), zap.Error(err))
			return nil, err
		}
		if len(ldapGroups) == 0 {
			notFoundError := status.Errorf(codes.NotFound, "baton-ipa: no such object")
			return nil, notFoundError
		}
		if len(ldapGroups) > 1 {
			l.Error("ipa-connector: multiple groups found", zap.String("group_dn", groupDN), zap.Error(err))
			return nil, fmt.Errorf("ipa-connector: multiple groups found")
		}
		return ldapGroups[0], nil
	}

	return nil, err
}

func uniqueGrants(grants []*v2.Grant) []*v2.Grant {
	seen := make(map[string]struct{})
	var uniqueGrants []*v2.Grant
	for _, grant := range grants {
		if _, ok := seen[grant.Principal.Id.Resource]; !ok {
			uniqueGrants = append(uniqueGrants, grant)
			seen[grant.Principal.Id.Resource] = struct{}{}
		}
	}
	return uniqueGrants
}

func (g *groupResourceType) getGroup(ctx context.Context, groupDN string) (*ldap3.Entry, error) {
	gdn, err := ldap.CanonicalizeDN(groupDN)
	if err != nil {
		return nil, fmt.Errorf("ipa-connector: invalid group DN: '%s' in getGroup: %w", groupDN, err)
	}

	return g.client.LdapGet(
		ctx,
		gdn,
		groupFilter,
		nil,
	)
}

func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ipa: only users can have group membership granted")
	}

	groupDN := entitlement.Resource.Id.Resource

	modifyRequest := ldap3.NewModifyRequest(groupDN, nil)

	group, err := g.getGroup(ctx, groupDN)
	if err != nil {
		return nil, err
	}

	groupObjectGUID := parseValue(group, []string{attrGroupObjectGUID})
	principalDNArr := []string{principal.Id.Resource}

	switch {
	case slices.Contains(group.GetAttributeValues("objectClass"), "posixGroup"):
		dn, err := ldap.CanonicalizeDN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		username := []string{dn.RDNs[0].Attributes[0].Value}
		modifyRequest.Add(attrGroupMemberPosix, username)

	case slices.Contains(group.GetAttributeValues("objectClass"), "ipausergroup") || groupObjectGUID != "":
		modifyRequest.Add(attrGroupMember, principalDNArr)

	default:
		modifyRequest.Add(attrGroupUniqueMember, principalDNArr)
	}

	// grant group membership to the principal
	err = g.client.LdapModify(
		ctx,
		modifyRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("ipa-connector: failed to grant group membership to user: %w", err)
	}

	return nil, nil
}

func (g *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ipa: only users can have group membership revoked")
	}

	groupDN := entitlement.Resource.Id.Resource

	modifyRequest := ldap3.NewModifyRequest(groupDN, nil)

	group, err := g.getGroup(ctx, groupDN)
	if err != nil {
		return nil, err
	}

	groupObjectGUID := parseValue(group, []string{attrGroupObjectGUID})
	principalDNArr := []string{principal.Id.Resource}

	// TODO: check whether membership is via memberUid, uniqueMember, or member, and modify accordingly
	switch {
	case slices.Contains(group.GetAttributeValues("objectClass"), "posixGroup"):
		dn, err := ldap.CanonicalizeDN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		username := []string{dn.RDNs[0].Attributes[0].Value}
		modifyRequest.Delete(attrGroupMemberPosix, username)

	case slices.Contains(group.GetAttributeValues("objectClass"), "ipausergroup") || groupObjectGUID != "":
		modifyRequest.Delete(attrGroupMember, principalDNArr)

	default:
		modifyRequest.Delete(attrGroupUniqueMember, principalDNArr)
	}

	// revoke group membership from the principal
	err = g.client.LdapModify(
		ctx,
		modifyRequest,
	)

	if err != nil {
		var lerr *ldap3.Error
		if errors.As(err, &lerr) {
			if lerr.ResultCode == ldap3.LDAPResultNoSuchAttribute {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("ipa-connector: failed to revoke group membership from user: %w", err)
	}

	return nil, nil
}

func groupBuilder(client *ldap.Client, groupSearchDN *ldap3.DN,
	userSearchDN *ldap3.DN) *groupResourceType {
	return &groupResourceType{
		groupSearchDN: groupSearchDN,
		userSearchDN:  userSearchDN,
		resourceType:  resourceTypeGroup,
		client:        client,
	}
}
