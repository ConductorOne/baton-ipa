package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
)

const (
	permissionAssignmentEntitlementName = "assigned"
)

type hbacRuleResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
}

func (r *hbacRuleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

func (r *hbacRuleResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (r *hbacRuleResourceType) Entitlements(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDisplayName(fmt.Sprintf("%s Permission", resource.DisplayName)),
		ent.WithDescription(fmt.Sprintf("Access to %s permission", resource.DisplayName)),
	}

	// create membership entitlement
	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		roleMemberEntitlement,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

func (r *hbacRuleResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func hbacRuleBuilder(client *ldap.Client) *hbacRuleResourceType {
	return &hbacRuleResourceType{
		resourceType: resourceTypeHbacRule,
		client:       client,
	}
}
