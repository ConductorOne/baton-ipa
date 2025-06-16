package connector

import v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"

const (
	excludeCompatFilter = "(!(cn:dn:=compat))"
	ipaUniqueIDFilter   = "(ipaUniqueID=%s)"

	attrIPAUniqueID = "ipaUniqueID"
	attrCommonName  = "cn"
)

var objectClassesToResourceTypes = map[string]*v2.ResourceType{
	"ipausergroup": resourceTypeGroup,
	"posixaccount": resourceTypeUser,
}
