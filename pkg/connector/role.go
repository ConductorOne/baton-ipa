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
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	ldap3 "github.com/go-ldap/ldap/v3"
)

const (
	roleFilter = "(&(objectClass=groupofnames)(cn:dn:=roles))"

	attrRoleCommonName  = "cn"
	attrRoleMember      = "member"
	attrRoleDescription = "description"

	roleMemberEntitlement = "member"
)

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
	roleSearchDN *ldap3.DN
}

func (r *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// Create a new connector resource for an LDAP Role.
func roleResource(ctx context.Context, role *ldap.Entry) (*v2.Resource, error) {
	rdn, err := ldap.CanonicalizeDN(role.DN)
	if err != nil {
		return nil, err
	}
	roleDN := rdn.String()
	profile := map[string]interface{}{
		"role_description": role.GetEqualFoldAttributeValue(attrRoleDescription),
		"path":             roleDN,
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	// Roles do not have an ipaUniqueID, so we use the entryUUID as the identifier
	entryUUID := role.GetEqualFoldAttributeValue(attrEntryUUID)

	roleName := role.GetEqualFoldAttributeValue(attrRoleCommonName)
	resource, err := rs.NewRoleResource(
		roleName,
		resourceTypeRole,
		entryUUID,
		roleTraitOptions,
		rs.WithExternalID(&v2.ExternalId{
			Id: role.DN,
		}),
	)
	if err != nil {
		return nil, err
	}
	return resource, nil
}

func (r *roleResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, "", nil, err
	}

	roleEntries, nextPage, err := r.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		r.roleSearchDN,
		roleFilter,
		allAttrs,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("baton-ipa: failed to list roles: %w", err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, roleEntry := range roleEntries {
		roleEntryCopy := roleEntry

		rr, err := roleResource(ctx, roleEntryCopy)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, rr)
	}

	return rv, pageToken, nil, nil
}

func (r *roleResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser, resourceTypeGroup, resourceTypeHostGroup, resourceTypeHost),
		ent.WithDisplayName(fmt.Sprintf("%s Role %s", resource.DisplayName, roleMemberEntitlement)),
		ent.WithDescription(fmt.Sprintf("Access to %s role in IPA", resource.DisplayName)),
	}

	// create membership entitlement
	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		roleMemberEntitlement,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

func (r *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	rawDN := resource.GetExternalId().Id
	roleDN, err := ldap.CanonicalizeDN(rawDN)
	if err != nil {
		return nil, "", nil, fmt.Errorf("baton-ipa: invalid role DN: '%s' in role grants: %w", resource.Id.Resource, err)
	}
	l = l.With(zap.Stringer("role_dn", roleDN))

	ldapRole, err := r.client.LdapGetWithStringDN(
		ctx,
		rawDN,
		"",
		nil,
	)
	if err != nil {
		err := fmt.Errorf("baton-ipa: failed to list role members: %w", err)
		l.Error("failed to get role object", zap.Error(err))
		return nil, "", nil, err
	}

	members := parseValues(ldapRole, []string{attrRoleMember})
	var rv []*v2.Grant
	for dn := range members.Iter() {
		_, err := ldap.CanonicalizeDN(dn)
		if err != nil {
			return nil, "", nil, fmt.Errorf("baton-ipa: invalid DN in role_members: '%s': %w", dn, err)
		}

		member, _, err := r.client.LdapSearchWithStringDN(
			ctx,
			ldap3.ScopeBaseObject,
			dn,
			"",
			nil,
			"",
			1,
		)
		if err != nil {
			l.Error("baton-ipa: failed to get role member", zap.String("role_dn", roleDN.String()), zap.String("member_dn", dn), zap.Error(err))
		}
		var g *v2.Grant
		if len(member) != 1 {
			l.Warn("baton-ipa: member not found", zap.String("role_dn", roleDN.String()), zap.String("member_dn", dn))
			continue
		}

		g = newRoleGrantFromEntry(resource, member[0])
		if g == nil {
			l.Error("baton-ipa: grant is not supported for member", zap.String("role_dn", roleDN.String()), zap.String("member_dn", dn), zap.Error(err))
			continue
		}

		rv = append(rv, g)
	}

	return rv, "", nil, nil
}

func newRoleGrantFromEntry(roleResource *v2.Resource, entry *ldap3.Entry) *v2.Grant {
	ipaUniqueID := entry.GetEqualFoldAttributeValue(attrIPAUniqueID)

	for _, objectClass := range entry.GetAttributeValues("objectClass") {
		if resourceType, ok := objectClassesToResourceTypes[objectClass]; ok {
			return newRoleGrantFromDN(roleResource, ipaUniqueID, resourceType)
		}
	}

	return nil
}

func newRoleGrantFromDN(roleResource *v2.Resource, ipaUniqueID string, resourceType *v2.ResourceType) *v2.Grant {
	grantOpts := []grant.GrantOption{}

	switch resourceType {
	case resourceTypeGroup:
		grantOpts = append(grantOpts, grant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("group:%s:member", ipaUniqueID),
			},
		}))
	case resourceTypeHostGroup, resourceTypeHost:
		grantOpts = append(grantOpts, grant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("host_group:%s:member", ipaUniqueID),
			},
		}))
	}

	g := grant.NewGrant(
		// remove group profile from grant so we're not saving all group memberships in every grant
		&v2.Resource{
			Id: roleResource.Id,
		},
		roleMemberEntitlement,
		// remove user profile from grant so we're not saving repetitive user info in every grant
		&v2.ResourceId{
			ResourceType: resourceType.Id,
			Resource:     ipaUniqueID,
		},
		grantOpts...,
	)
	return g
}

func (r *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	// if principal.Id.ResourceType != resourceTypeUser.Id {
	// 	return nil, fmt.Errorf("baton-ipa: only users can have role membership granted")
	// }

	roleDN := entitlement.Resource.GetExternalId().Id

	principalDNArr := []string{principal.GetExternalId().Id}
	modifyRequest := ldap3.NewModifyRequest(roleDN, nil)
	modifyRequest.Add(attrRoleMember, principalDNArr)

	// grant role memberships to the principal
	err := r.client.LdapModify(
		ctx,
		modifyRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("baton-ipa: failed to grant role membership to user: %w", err)
	}

	return nil, nil
}

func (r *roleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ipa: only users can have role membership revoked")
	}

	roleDN := entitlement.Resource.Id.Resource

	principalDNArr := []string{principal.Id.Resource}
	modifyRequest := ldap3.NewModifyRequest(roleDN, nil)
	modifyRequest.Delete(attrRoleMember, principalDNArr)

	// revoke role memberships from the principal
	err := r.client.LdapModify(
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
		return nil, fmt.Errorf("baton-ipa: failed to revoke role membership from user: %w", err)
	}

	return nil, nil
}

func roleBuilder(client *ldap.Client, roleSearchDN *ldap3.DN) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
		roleSearchDN: roleSearchDN,
	}
}
