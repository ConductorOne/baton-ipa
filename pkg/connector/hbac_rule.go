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
	permissionAssignmentEntitlementName = "assigned"

	hbacRuleFilter = "(&(objectClass=ipahbacrule))"

	attrIPAEnabledFlag = "ipaEnabledFlag"
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
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDisplayName(fmt.Sprintf("%s Permission %s", resource.DisplayName, permissionAssignmentEntitlementName)),
		ent.WithDescription(fmt.Sprintf("Access to %s permission", resource.DisplayName)),
	}

	// create membership entitlement
	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		permissionAssignmentEntitlementName,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

func (r *hbacRuleResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func hbacRuleBuilder(client *ldap.Client, baseDN *ldap3.DN) *hbacRuleResourceType {
	return &hbacRuleResourceType{
		resourceType: resourceTypeHbacRule,
		client:       client,
		baseDN:       baseDN,
	}
}
