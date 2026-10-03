package goradius

// CienaVendorDefinition defines the Ciena vendor (ID 1271) and its platform
// authorization attributes. Ported from FreeRADIUS dictionary.ciena; the raw
// names carry Ciena product-line prefixes (CN4200 optical, CES/SAOS carrier
// ethernet, BP Blue Planet, OC, NCS, CS) and are prefixed with ciena- here.
//
// The Ciena MCP security guide documents ID 220 (named Ciena-Roles there) as
// a multi-valued attribute for inclusion in Access-Accept messages; no other
// attribute has an official packet placement, so the rest stay unrestricted.
var CienaVendorDefinition = &VendorDefinition{
	ID:   1271,
	Name: "ciena",
	Attributes: []*AttributeDefinition{
		{
			ID:       1,
			Name:     "ciena-cn4200-priv-level",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"limited":    1,
				"admin":      2,
				"super-user": 3,
				"diag":       4,
			},
		},
		{
			ID:       10,
			Name:     "ciena-ces-priv-level",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"limited":    1,
				"admin":      2,
				"super-user": 3,
				"diag":       4,
			},
		},
		{ID: 11, Name: "ciena-ces-nacm-groups", DataType: DataTypeString},
		{
			ID:       220,
			Name:     "ciena-bp-role",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{ID: 230, Name: "ciena-oc-mgmt-role", DataType: DataTypeString},
		{ID: 231, Name: "ciena-oc-p1-role", DataType: DataTypeString},
		{ID: 232, Name: "ciena-oc-p2-role", DataType: DataTypeString},
		{ID: 233, Name: "ciena-oc-p3-role", DataType: DataTypeString},
		{ID: 234, Name: "ciena-oc-p4-role", DataType: DataTypeString},
		{ID: 235, Name: "ciena-oc-p5-role", DataType: DataTypeString},
		{ID: 236, Name: "ciena-oc-p6-role", DataType: DataTypeString},
		{ID: 237, Name: "ciena-oc-p7-role", DataType: DataTypeString},
		{ID: 238, Name: "ciena-oc-p8-role", DataType: DataTypeString},
		{ID: 239, Name: "ciena-oc-p9-role", DataType: DataTypeString},
		{
			ID:       240,
			Name:     "ciena-ncs-role",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"security": 1,
				"admin":    2,
				"general":  3,
			},
		},
		{ID: 250, Name: "ciena-oc-role", DataType: DataTypeString},
		{ID: 253, Name: "ciena-cs-client-ip", DataType: DataTypeIPAddr},
		{
			ID:       254,
			Name:     "ciena-cs-acc-level",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"multi": 1,
				"craft": 2,
				"shell": 3,
				"ems":   4,
			},
		},
		{
			ID:       255,
			Name:     "ciena-cs-priv-level",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"read-only":        1,
				"read-write":       2,
				"laser-read-write": 3,
				"admin":            4,
				"debug":            5,
				"ne-config":        8,
				"ne-admin":         9,
			},
		},
	},
}
