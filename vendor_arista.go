package goradius

// AristaVendorDefinition defines the Arista Networks vendor (ID 30065) used by
// EOS switches. Ported from FreeRADIUS dictionary.arista, which sources the
// Arista "Common AAA requirements" article. The Arista WiFi access points use
// a separate vendor ID (16901, from Mojo Networks), covered by
// AristaWiFiVendorDefinition.
//
// The EOS user security guide documents only arista-avpair (authorization
// values such as "shell:priv-lvl=15" and "shell:roles=..." in Access-Accept,
// and dynamic ACL updates via CoA); no attribute has an official per-packet
// placement table, so all attributes stay unrestricted.
var AristaVendorDefinition = &VendorDefinition{
	ID:   30065,
	Name: "arista",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "arista-avpair", DataType: DataTypeString},
		{ID: 2, Name: "arista-user-priv-level", DataType: DataTypeInteger},
		{ID: 3, Name: "arista-user-role", DataType: DataTypeString},
		{ID: 4, Name: "arista-cvp-role", DataType: DataTypeString},
		{ID: 5, Name: "arista-command", DataType: DataTypeString},
		{
			ID:       6,
			Name:     "arista-webauth",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"start":    1,
				"complete": 2,
			},
		},
		{ID: 7, Name: "arista-blockmac", DataType: DataTypeString},
		{ID: 8, Name: "arista-unblockmac", DataType: DataTypeString},
		{ID: 9, Name: "arista-portflap", DataType: DataTypeInteger},
		{ID: 10, Name: "arista-captive-portal", DataType: DataTypeString},
	},
}
