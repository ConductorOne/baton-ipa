package connector

import (
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/go-ldap/ldap/v3"
)

var ResourcesPageSize uint32 = 50

const pathProfileProperty = "path"

// getDNFromResource resolves the LDAP DN for a resource. Resource.ExternalId is
// no longer used by baton-sdk and is not persisted by c1, so it is nil for
// resources provided in service mode. The DN is reliably carried in the resource
// profile "path" field, which is the source of truth here. ExternalId is still
// checked first because it carries the unmodified DN in standalone CLI runs.
//
// The ExternalId read is deprecated upstream but not yet removed; dropping it is
// part of the DN-resolution rework in #49 rather than this change.
func getDNFromResource(resource *v2.Resource) (string, error) {
	if eid := resource.GetExternalId(); eid != nil && eid.Id != "" { //nolint:staticcheck // removing this read belongs to the DN-resolution rework in #49, not here
		return eid.Id, nil
	}
	if dn, ok := dnFromProfilePath(resource); ok && dn != "" {
		return dn, nil
	}
	return "", fmt.Errorf("baton-ipa: resource %s missing DN", resource.Id.Resource)
}

// dnFromProfilePath reads the DN out of the resource-level profile. baton-sdk
// v0.20.x moved profile off the individual traits and onto Resource itself, and
// the resource builders here write it through rs.WithResourceProfile.
func dnFromProfilePath(resource *v2.Resource) (string, bool) {
	return rs.GetProfileStringValue(resource.GetProfile(), pathProfileProperty)
}

func splitFullName(fullName string) (string, string) {
	parts := strings.Split(fullName, " ")

	return parts[0], strings.Join(parts[1:], " ")
}

func parsePageToken(i string, resourceID *v2.ResourceId) (*pagination.Bag, string, error) {
	b := &pagination.Bag{}
	err := b.Unmarshal(i)
	if err != nil {
		return nil, "", err
	}

	if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceID.ResourceType,
			ResourceID:     resourceID.Resource,
		})
	}

	return b, b.PageToken(), nil
}

// Parses the values of targetted attributes from an LDAP entry.
func parseValues(entry *ldap.Entry, targetAttrs []string) mapset.Set[string] {
	rv := mapset.NewSet[string]()

	for _, targetAttr := range targetAttrs {
		payload := entry.GetAttributeValues(targetAttr)

		for _, v := range payload {
			rv.Add(v)
		}
	}

	return rv
}

func parseValue(entry *ldap.Entry, targetAttrs []string) string {
	for _, targetAttr := range targetAttrs {
		payload := entry.GetEqualFoldAttributeValue(targetAttr)

		if payload != "" {
			return payload
		}
	}

	return ""
}

func containsRDN(dn *ldap.DN, targetRDN *ldap.RelativeDN) bool {
	for _, rdn := range dn.RDNs {
		if rdn.Equal(targetRDN) {
			return true
		}
	}
	return false
}
