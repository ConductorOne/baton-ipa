package connector

import (
	"context"
	"fmt"
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
	resourceType *v2.ResourceType
}

func (c *ipaObjectCache) get(ctx context.Context, dn string) (*ipaObject, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	m, ok := c.entries[dn]
	if ok {
		return m, nil
	}

	memberEntry, err := c.client.LdapGetWithStringDN(ctx, dn, "", []string{attrIPAUniqueID, attrObjectClass})
	if err != nil {
		return nil, fmt.Errorf("baton-ipa: failed to search for member %s: %w", dn, err)
	}

	ipaUniqueID := memberEntry.GetEqualFoldAttributeValue(attrIPAUniqueID)

	var resourceType *v2.ResourceType
	for _, objectClass := range memberEntry.GetAttributeValues(attrObjectClass) {
		if rt, ok := objectClassesToResourceTypes[objectClass]; ok {
			resourceType = rt
			break
		}
	}

	m = &ipaObject{
		ipaUniqueID:  ipaUniqueID,
		dn:           dn,
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
