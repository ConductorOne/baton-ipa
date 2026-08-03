package connector

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ldap3 "github.com/go-ldap/ldap/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ipaObjectCache struct {
	client *ldap.Client
	baseDN *ldap3.DN

	entries map[string]*ipaObject
	mu      sync.RWMutex

	// DN by ipaUniqueID, for principals that reach Grant/Revoke without one.
	// Keyed by "<filter>:<ipaUniqueID>" so two object classes cannot collide on
	// a shared identifier.
	dns   map[string]string
	dnsMu sync.RWMutex
}

type ipaObject struct {
	ipaUniqueID  string
	dn           string
	cn           string
	resourceType *v2.ResourceType
}

func (c *ipaObjectCache) get(ctx context.Context, dn string) (*ipaObject, error) {
	c.mu.RLock()

	m, ok := c.entries[dn]
	if ok {
		c.mu.RUnlock()
		return m, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	m, ok = c.entries[dn]
	if ok {
		return m, nil
	}

	entry, err := c.client.LdapGetWithStringDN(ctx, dn, "", []string{attrIPAUniqueID, attrObjectClass, attrCommonName})
	if err != nil {
		return nil, fmt.Errorf("baton-ipa: failed to search for entry %s: %w", dn, err)
	}

	ipaUniqueID := entry.GetEqualFoldAttributeValue(attrIPAUniqueID)
	cn := entry.GetEqualFoldAttributeValue(attrCommonName)

	var resourceType *v2.ResourceType
	for _, objectClass := range entry.GetAttributeValues(attrObjectClass) {
		if rt, ok := objectClassesToResourceTypes[objectClass]; ok {
			resourceType = rt
			break
		}
	}

	if resourceType == nil {
		return nil, fmt.Errorf("baton-ipa: unsupported object class for entry %s: %s", dn, strings.Join(entry.GetAttributeValues("objectClass"), ", "))
	}

	m = &ipaObject{
		ipaUniqueID:  ipaUniqueID,
		dn:           dn,
		cn:           cn,
		resourceType: resourceType,
	}

	c.entries[dn] = m
	return m, nil
}

// dnByIPAUniqueID looks a DN up by the object's ipaUniqueID, which is what the
// connector uses as the resource ID. objectFilter narrows the search to the
// expected object class, e.g. hostFilter.
//
// Only resolvePrincipalDN calls this, so the caller is always a Grant or Revoke.
// An object that is not in the directory therefore fails that one provisioning
// call - it is not a sync the SDK could warn on and skip. The NotFound status is
// still worth carrying so a caller can tell "no such principal" from a directory
// error.
func (c *ipaObjectCache) dnByIPAUniqueID(ctx context.Context, objectFilter string, ipaUniqueID string) (string, error) {
	if ipaUniqueID == "" {
		return "", fmt.Errorf("baton-ipa: cannot resolve a DN without an ipaUniqueID")
	}

	key := fmt.Sprintf("%s:%s", objectFilter, ipaUniqueID)

	c.dnsMu.RLock()
	dn, ok := c.dns[key]
	c.dnsMu.RUnlock()
	if ok {
		return dn, nil
	}

	filter := fmt.Sprintf("(&%s%s)", objectFilter, fmt.Sprintf(ipaUniqueIDFilter, ldap3.EscapeFilter(ipaUniqueID)))
	entries, _, err := c.client.LdapSearch(ctx, ldap3.ScopeWholeSubtree, c.baseDN, filter, []string{attrIPAUniqueID}, "", 2)
	if err != nil {
		return "", fmt.Errorf("baton-ipa: failed to search for ipaUniqueID %s: %w", ipaUniqueID, err)
	}
	switch len(entries) {
	case 0:
		return "", status.Errorf(codes.NotFound, "baton-ipa: no object with ipaUniqueID %s", ipaUniqueID)
	case 1:
	default:
		return "", fmt.Errorf("baton-ipa: multiple objects with ipaUniqueID %s", ipaUniqueID)
	}
	dn = entries[0].DN

	c.dnsMu.Lock()
	c.dns[key] = dn
	c.dnsMu.Unlock()

	return dn, nil
}

func newIPAObjectCache(client *ldap.Client, baseDN *ldap3.DN) *ipaObjectCache {
	return &ipaObjectCache{
		client:  client,
		baseDN:  baseDN,
		entries: make(map[string]*ipaObject),
		dns:     make(map[string]string),
	}
}
