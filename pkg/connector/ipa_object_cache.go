package connector

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/conductorone/baton-ipa/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ldap3 "github.com/go-ldap/ldap/v3"
)

type ipaObjectCache struct {
	client *ldap.Client
	baseDN *ldap3.DN

	entries map[string]*ipaObject
	mu      sync.RWMutex
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

func newIPAObjectCache(client *ldap.Client, baseDN *ldap3.DN) *ipaObjectCache {
	return &ipaObjectCache{
		client:  client,
		baseDN:  baseDN,
		entries: make(map[string]*ipaObject),
	}
}
