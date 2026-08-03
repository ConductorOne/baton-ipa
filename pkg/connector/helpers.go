package connector

import (
	"context"
	"fmt"
	"strings"

	ipaldap "github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/go-ldap/ldap/v3"
)

var ResourcesPageSize uint32 = 50

const pathProfileProperty = "path"

// getDNFromResource resolves the LDAP DN for a resource from its profile "path"
// field, which every resource this connector builds carries.
//
// The profile is the only DN carrier c1 persists, so it is the only one present
// when c1 hands a resource back to Entitlements() or Grants() in service mode.
// Resource.ExternalId is deprecated in baton-sdk and never survives that round
// trip - it exists only on the in-memory resource this connector builds during
// its own List()/Get() - so nothing reads or writes it any more.
func getDNFromResource(resource *v2.Resource) (string, error) {
	if dn, ok := dnFromProfilePath(resource); ok && dn != "" {
		return dn, nil
	}
	return "", fmt.Errorf("baton-ipa: resource %s missing DN", resource.GetId().GetResource())
}

// principalFilterByResourceType narrows an ipaUniqueID search to the object class
// a principal of that resource type must have.
var principalFilterByResourceType = map[string]string{
	resourceTypeUser.Id:      userFilter,
	resourceTypeGroup.Id:     groupFilter,
	resourceTypeHost.Id:      hostFilter,
	resourceTypeHostGroup.Id: hostGroupFilter,
}

// resolvePrincipalDN resolves the DN of a provisioning principal.
//
// baton-sdk's local provisioner rebuilds the principal resource field by field
// and omits the profile - it still copies the deprecated ExternalId instead - so
// a `--grant-entitlement` / `--revoke-grant` run hands us a principal carrying no
// DN. c1 passes the stored resource through intact, so this only bites standalone
// runs. Either way the DN is recoverable from the identifier the connector uses
// as the resource ID.
func resolvePrincipalDN(ctx context.Context, cache *ipaObjectCache, principal *v2.Resource) (string, error) {
	if dn, err := getDNFromResource(principal); err == nil {
		return dn, nil
	}

	id := principal.GetId().GetResource()
	switch id {
	case internalAnyoneGroupID, internalAnyHostID:
		return "", fmt.Errorf("baton-ipa: %s is virtual and does not support provisioning", id)
	}

	filter, ok := principalFilterByResourceType[principal.GetId().GetResourceType()]
	if !ok {
		return "", fmt.Errorf("baton-ipa: cannot resolve a DN for %s principals", principal.GetId().GetResourceType())
	}

	dn, err := cache.dnByIPAUniqueID(ctx, filter, id)
	if err != nil {
		return "", fmt.Errorf("baton-ipa: failed to resolve DN for principal %s: %w", id, err)
	}

	return dn, nil
}

// sameDN reports whether two distinguished names refer to the same directory
// object, per the RFC 4517 distinguishedNameMatch rule. Comparing structurally
// rather than byte-wise matters because the DN a resource carries is
// canonicalized while the values LDAP returns are not.
func sameDN(a string, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}

	adn, err := ipaldap.CanonicalizeDN(a)
	if err != nil {
		return false
	}
	bdn, err := ipaldap.CanonicalizeDN(b)
	if err != nil {
		return false
	}

	return adn.EqualFold(bdn)
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
