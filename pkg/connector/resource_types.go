package connector

import v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
	}
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
	}
	resourceTypeHost = &v2.ResourceType{
		Id:          "host",
		DisplayName: "Host",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_UNSPECIFIED,
		},
	}
	resourceTypeHostGroup = &v2.ResourceType{
		Id:          "host_group",
		DisplayName: "Host Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_UNSPECIFIED,
		},
	}
)
