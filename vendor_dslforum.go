package goradius

// DSLForumVendorDefinition defines the DSL Forum / Broadband Forum vendor (ID 3561)
// and its access-line attributes (RFC 4679 plus the Broadband Forum PON and G.fast
// extensions). BNGs exchange these for access-loop identification (DHCP option 82 and
// PPPoE intermediate agent data) and access-line rate reporting.
//
// Attributes marked RFC4679 match the FreeRADIUS dictionary.rfc4679. Attributes
// marked BBF are Broadband Forum extensions not present in FreeRADIUS; they are taken
// from the Juniper AAA Service Framework table "DSL Forum VSAs (Vendor ID 3561)":
// https://www.juniper.net/documentation/us/en/software/junos/subscriber-mgmt-sessions/topics/topic-map/radius-std-attributes-vsas-support.html
var DSLForumVendorDefinition = &VendorDefinition{
	ID:   3561,
	Name: "dslforum",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "adsl-agent-circuit-id", DataType: DataTypeString},                          // RFC4679
		{ID: 2, Name: "adsl-agent-remote-id", DataType: DataTypeString},                           // RFC4679
		{ID: 3, Name: "adsl-access-aggregation-circuit-id-ascii", DataType: DataTypeString},       // BBF
		{ID: 6, Name: "adsl-access-aggregation-circuit-id-binary", DataType: DataTypeOctets},      // BBF
		{ID: 129, Name: "adsl-actual-data-rate-upstream", DataType: DataTypeInteger},              // RFC4679
		{ID: 130, Name: "adsl-actual-data-rate-downstream", DataType: DataTypeInteger},            // RFC4679
		{ID: 131, Name: "adsl-minimum-data-rate-upstream", DataType: DataTypeInteger},             // RFC4679
		{ID: 132, Name: "adsl-minimum-data-rate-downstream", DataType: DataTypeInteger},           // RFC4679
		{ID: 133, Name: "adsl-attainable-data-rate-upstream", DataType: DataTypeInteger},          // RFC4679
		{ID: 134, Name: "adsl-attainable-data-rate-downstream", DataType: DataTypeInteger},        // RFC4679
		{ID: 135, Name: "adsl-maximum-data-rate-upstream", DataType: DataTypeInteger},             // RFC4679
		{ID: 136, Name: "adsl-maximum-data-rate-downstream", DataType: DataTypeInteger},           // RFC4679
		{ID: 137, Name: "adsl-minimum-data-rate-upstream-low-power", DataType: DataTypeInteger},   // RFC4679
		{ID: 138, Name: "adsl-minimum-data-rate-downstream-low-power", DataType: DataTypeInteger}, // RFC4679
		{ID: 139, Name: "adsl-maximum-interleaving-delay-upstream", DataType: DataTypeInteger},    // RFC4679
		{ID: 140, Name: "adsl-actual-interleaving-delay-upstream", DataType: DataTypeInteger},     // RFC4679
		{ID: 141, Name: "adsl-maximum-interleaving-delay-downstream", DataType: DataTypeInteger},  // RFC4679
		{ID: 142, Name: "adsl-actual-interleaving-delay-downstream", DataType: DataTypeInteger},   // RFC4679
		{ID: 144, Name: "adsl-access-loop-encapsulation", DataType: DataTypeOctets},               // RFC4679
		{ // BBF
			ID:       145,
			Name:     "adsl-dsl-type",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"other":                0,
				"adsl1":                1,
				"adsl2":                2,
				"adsl2-plus":           3,
				"vdsl1":                4,
				"vdsl2":                5,
				"sdsl":                 6,
				"g.fast":               8,
				"vdsl2-annex-q":        9,
				"sdsl-bonded":          10,
				"vdsl2-bonded":         11,
				"g.fast-bonded":        12,
				"vdsl2-annex-q-bonded": 13,
			},
		},
		{ // BBF
			ID:       146,
			Name:     "adsl-pon-access-type",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"other":    0,
				"gpon":     1,
				"xg-pon1":  2,
				"twdm-pon": 3,
				"xgs-pon":  4,
				"wdm-pon":  5,
				"unknown":  7,
			},
		},
		{ID: 147, Name: "adsl-ont-onu-average-data-rate-downstream", DataType: DataTypeInteger},      // BBF
		{ID: 148, Name: "adsl-ont-onu-peak-data-rate-downstream", DataType: DataTypeInteger},         // BBF
		{ID: 149, Name: "adsl-ont-onu-maximum-data-rate-upstream", DataType: DataTypeInteger},        // BBF
		{ID: 150, Name: "adsl-ont-onu-assured-data-rate-upstream", DataType: DataTypeInteger},        // BBF
		{ID: 151, Name: "adsl-pon-tree-maximum-data-rate-upstream", DataType: DataTypeInteger},       // BBF
		{ID: 152, Name: "adsl-pon-tree-maximum-data-rate-downstream", DataType: DataTypeInteger},     // BBF
		{ID: 155, Name: "adsl-expected-throughput-upstream", DataType: DataTypeInteger},              // BBF
		{ID: 156, Name: "adsl-expected-throughput-downstream", DataType: DataTypeInteger},            // BBF
		{ID: 157, Name: "adsl-attainable-expected-throughput-upstream", DataType: DataTypeInteger},   // BBF
		{ID: 158, Name: "adsl-attainable-expected-throughput-downstream", DataType: DataTypeInteger}, // BBF
		{ID: 159, Name: "adsl-gamma-data-rate-upstream", DataType: DataTypeInteger},                  // BBF
		{ID: 160, Name: "adsl-gamma-data-rate-downstream", DataType: DataTypeInteger},                // BBF
		{ID: 161, Name: "adsl-attainable-gamma-data-rate-upstream", DataType: DataTypeInteger},       // BBF
		{ID: 162, Name: "adsl-attainable-gamma-data-rate-downstream", DataType: DataTypeInteger},     // BBF
		{ID: 254, Name: "adsl-iwf-session", DataType: DataTypeOctets},                                // RFC4679
	},
}
