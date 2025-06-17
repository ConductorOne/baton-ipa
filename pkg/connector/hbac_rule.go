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
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ldap3 "github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

const (
	permissionAssignmentEntitlement = "assigned"

	hbacRuleFilter = "(&(objectClass=ipahbacrule))"

	attrIPAEnabledFlag     = "ipaEnabledFlag"
	attrHBACRuleMemberUser = "memberUser"
	attrHBACRuleMemberHost = "memberHost"
)

type hbacRuleResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
	baseDN       *ldap3.DN
}

func (r *hbacRuleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

func hbacRuleResource(ctx context.Context, hbacRule *ldap.Entry) (*v2.Resource, error) {
	ipaUniqueID := hbacRule.GetEqualFoldAttributeValue(attrIPAUniqueID)
	if ipaUniqueID == "" {
		return nil, fmt.Errorf("ldap-connector: hbac rule %s has no ipaUniqueID", hbacRule.DN)
	}

	cdn, err := ldap.CanonicalizeDN(hbacRule.DN)
	if err != nil {
		return nil, err
	}
	hbacRuleDN := cdn.String()
	description := hbacRule.GetEqualFoldAttributeValue(attrGroupDescription)

	profile := map[string]interface{}{
		"path": hbacRuleDN,
	}

	resourceOptions := []rs.ResourceOption{}
	resourceOptions = append(resourceOptions, rs.WithExternalID(&v2.ExternalId{
		Id: hbacRule.DN,
	}))

	if description != "" {
		profile["hbac_rule_description"] = description
		resourceOptions = append(resourceOptions, rs.WithDescription(description))
	}

	ipaEnabledFlag := hbacRule.GetEqualFoldAttributeValue(attrIPAEnabledFlag)
	if ipaEnabledFlag == "TRUE" {
		profile["enabled"] = true
	} else {
		profile["enabled"] = false
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	ruleName := hbacRule.GetEqualFoldAttributeValue(attrCommonName)

	resource, err := rs.NewRoleResource(
		ruleName,
		resourceTypeHbacRule,
		ipaUniqueID,
		roleTraitOptions,
		resourceOptions...,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (r *hbacRuleResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeHbacRule.Id})
	if err != nil {
		return nil, "", nil, err
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

	var rv []*v2.Resource
	for _, hbacRuleEntry := range hbacRuleEntries {
		gr, err := hbacRuleResource(ctx, hbacRuleEntry)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, gr)
	}

	return rv, pageToken, nil, nil
}

func (r *hbacRuleResourceType) Entitlements(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
		ent.WithDisplayName(fmt.Sprintf("%s Permission %s", resource.DisplayName, permissionAssignmentEntitlement)),
		ent.WithDescription(fmt.Sprintf("Access to %s permission", resource.DisplayName)),
	}

	// create membership entitlement
	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		permissionAssignmentEntitlement,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

func (r *hbacRuleResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	externalId := resource.GetExternalId()
	if externalId == nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: hbac rule %s has no external ID", resource.Id.Resource)
	}

	hbacRuleDN, err := ldap.CanonicalizeDN(externalId.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("baton-ipa: invalid hbac rule DN: '%s' in hbac rule grants: %w", resource.Id.Resource, err)
	}
	l = l.With(zap.Stringer("hbac_rule_dn", hbacRuleDN))

	var ldapHbacRule *ldap3.Entry
	ldapHbacRule, err = r.getHbacRuleWithFallback(ctx, l, resource.Id, externalId)
	if err != nil {
		l.Error("baton-ipa: failed to list hbac rule members", zap.String("hbac_rule_dn", resource.Id.Resource), zap.Error(err))
		return nil, "", nil, fmt.Errorf("baton-ipa: failed to list hbac rule %s members: %w", resource.Id.Resource, err)
	}

	members := parseValues(ldapHbacRule, []string{attrHBACRuleMemberUser, attrHBACRuleMemberHost})

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
			l.Error("baton-ipa: failed to get hbac rule member", zap.String("hbac_rule_dn", hbacRuleDN.String()), zap.String("member_dn", memberDN), zap.Error(err))
			continue
		}
		var g *v2.Grant
		if len(member) == 1 {
			g = newHbacRuleGrantFromEntry(resource, member[0])
			if g == nil {
				l.Error("baton-ipa: grant is not supported for member", zap.String("hbac_rule_dn", hbacRuleDN.String()), zap.String("member_dn", memberDN), zap.Error(err))
				continue
			}
		} else {
			l.Warn("baton-ipa: member not found", zap.String("hbac_rule_dn", hbacRuleDN.String()), zap.String("member_dn", memberDN))
			continue
		}

		if g.Id == "" {
			l.Error("baton-ipa: failed to create grant", zap.String("hbac_rule_dn", hbacRuleDN.String()), zap.String("member_dn", memberDN), zap.Error(err))
			continue
		}
		rv = append(rv, g)
	}

	rv = uniqueGrants(rv)

	return rv, "", nil, nil
}

func (r *hbacRuleResourceType) getHbacRuleWithFallback(ctx context.Context, l *zap.Logger, resourceId *v2.ResourceId, externalId *v2.ExternalId) (*ldap3.Entry, error) {
	hbacRuleDN := externalId.Id
	ldapRule, err := r.client.LdapGetWithStringDN(
		ctx,
		hbacRuleDN,
		hbacRuleFilter,
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
			l.Error("baton-ipa: failed to get hbac rule", zap.String("hbac_rule_dn", hbacRuleDN), zap.Error(err))
			return nil, err
		}
		if len(ldapRules) == 0 {
			notFoundError := status.Errorf(codes.NotFound, "baton-ipa: no such object")
			return nil, notFoundError
		}
		if len(ldapRules) > 1 {
			l.Error("baton-ipa: multiple hbac rules found", zap.String("hbac_rule_dn", hbacRuleDN), zap.Error(err))
			return nil, fmt.Errorf("baton-ipa: multiple hbac rules found")
		}
		return ldapRules[0], nil
	}

	return nil, err
}

func newHbacRuleGrantFromEntry(hbacRuleResource *v2.Resource, entry *ldap3.Entry) *v2.Grant {
	ipaUniqueID := entry.GetEqualFoldAttributeValue(attrIPAUniqueID)

	for _, objectClass := range entry.GetAttributeValues("objectClass") {
		if resourceType, ok := objectClassesToResourceTypes[objectClass]; ok {
			return newHbacRuleGrantFromDN(hbacRuleResource, ipaUniqueID, resourceType)
		}
	}

	return nil
}

func newHbacRuleGrantFromDN(hbacRuleResource *v2.Resource, ipaUniqueID string, resourceType *v2.ResourceType) *v2.Grant {
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
			Id: hbacRuleResource.Id,
		},
		permissionAssignmentEntitlement,
		// remove user profile from grant so we're not saving repetitive user info in every grant
		&v2.ResourceId{
			ResourceType: resourceType.Id,
			Resource:     ipaUniqueID,
		},
		grantOpts...,
	)
	return g
}

func hbacRuleBuilder(client *ldap.Client, baseDN *ldap3.DN) *hbacRuleResourceType {
	return &hbacRuleResourceType{
		resourceType: resourceTypeHbacRule,
		client:       client,
		baseDN:       baseDN,
	}
}
