package connector

import v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"

const (
	// LDAP filter to exclude the compat schema, which is for backward compatibility with older LDAP clients.
	excludeCompatFilter = "(!(cn:dn:=compat))"
	ipaUniqueIDFilter   = "(ipaUniqueID=%s)"
	entryUUIDFilter     = "(entryUUID=%s)"

	attrIPAUniqueID        = "ipaUniqueID"
	attrCommonName         = "cn"
	attrDescription        = "description"
	attrObjectClass        = "objectClass"
	attrEntryUUID          = "entryUUID"
	attrHBACRuleMemberUser = "memberUser"
	attrHBACRuleMemberHost = "memberHost"
)

var objectClassesToResourceTypes = map[string]*v2.ResourceType{
	"ipausergroup": resourceTypeGroup,
	"posixaccount": resourceTypeUser,
	"ipahost":      resourceTypeHost,
	"ipahostgroup": resourceTypeHostGroup,
}
