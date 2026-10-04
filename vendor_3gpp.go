package goradius

// ThreeGPPVendorDefinition defines the 3GPP vendor (ID 10415) as specified in
// 3GPP TS 29.061. Ported from FreeRADIUS dictionary.3gpp. Used by the mobile
// packet core (GGSN/PGW/SMF) for charging and session attributes.
//
// Two attributes use wire structures this library cannot model faithfully and
// are carried as raw octets, documented inline: User-Location-Info (22), whose
// payload is a Type-keyed union of location sub-structures, and
// Secondary-RAT-Usage (31), which packs bit-fields. MS-TimeZone (23) and
// Packet-Filter (25) are modeled as fixed-layout structs with a trailing
// variable member. The dictionary carries no per-packet placement data, so all
// attributes stay unrestricted.
var ThreeGPPVendorDefinition = &VendorDefinition{
	ID:   10415,
	Name: "3gpp",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "3gpp-imsi", DataType: DataTypeString},
		{ID: 2, Name: "3gpp-charging-id", DataType: DataTypeInteger},
		{
			ID:       3,
			Name:     "3gpp-pdp-type",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"ipv4":         0,
				"ppp":          1,
				"ipv6":         2,
				"ipv4v6":       3,
				"non-ip":       4,
				"unstructured": 5,
				"ethernet":     6,
			},
		},
		{ID: 4, Name: "3gpp-cg-address", DataType: DataTypeIPAddr},
		{ID: 5, Name: "3gpp-gprs-negotiated-qos-profile", DataType: DataTypeString},
		{ID: 6, Name: "3gpp-sgsn-address", DataType: DataTypeIPAddr},
		{ID: 7, Name: "3gpp-ggsn-address", DataType: DataTypeIPAddr},
		{ID: 8, Name: "3gpp-imsi-mcc-mnc", DataType: DataTypeString},
		{ID: 9, Name: "3gpp-ggsn-mcc-mnc", DataType: DataTypeString},
		{ID: 10, Name: "3gpp-nsapi", DataType: DataTypeString},
		{
			ID:       11,
			Name:     "3gpp-session-stop-indicator",
			DataType: DataTypeByte,
			Values: map[string]uint32{
				"stop": 255,
			},
		},
		// Selection-Mode is a single-octet text field (string[1]).
		{ID: 12, Name: "3gpp-selection-mode", DataType: DataTypeString},
		{ID: 13, Name: "3gpp-charging-characteristics", DataType: DataTypeString},
		{ID: 14, Name: "3gpp-cg-ipv6-address", DataType: DataTypeIPv6Addr},
		{ID: 15, Name: "3gpp-sgsn-ipv6-address", DataType: DataTypeIPv6Addr},
		{ID: 16, Name: "3gpp-ggsn-ipv6-address", DataType: DataTypeIPv6Addr},
		{ID: 17, Name: "3gpp-ipv6-dns-servers", DataType: DataTypeIPv6Addr, Array: true},
		{ID: 18, Name: "3gpp-sgsn-mcc-mnc", DataType: DataTypeString},
		{
			ID:       19,
			Name:     "3gpp-teardown-indicator",
			DataType: DataTypeByte,
			Values: map[string]uint32{
				"this-ip-can": 0,
				"all-ip-can":  1,
			},
		},
		{ID: 20, Name: "3gpp-imeisv", DataType: DataTypeString},
		{
			ID:       21,
			Name:     "3gpp-rat-type",
			DataType: DataTypeByte,
			Values: map[string]uint32{
				"utran":                 1,
				"geran":                 2,
				"wlan":                  3,
				"gan":                   4,
				"hspa-evolution":        5,
				"eutran":                6,
				"virtual":               7,
				"eutran-nb-iot":         8,
				"lte-m":                 9,
				"nr":                    51,
				"nr-unlicensed":         52,
				"trusted-wlan":          53,
				"trusted-non-3gpp":      54,
				"wireline-access":       55,
				"wireline-cable-access": 56,
				"wireline-bpf-access":   57,
				"ieee-802.16e":          101,
				"3gpp2-ehrpd":           102,
				"3gpp2-hrpd":            103,
				"3gpp2-1xrtt":           104,
				"3gpp2-umb":             105,
			},
		},
		// User-Location-Info is Type(1) + PLMN-ID(3) + a Type-keyed union of
		// location sub-structures (TS 29.061 / 29.274).
		{
			ID:       22,
			Name:     "3gpp-user-location-info",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "3gpp-uli-type", DataType: DataTypeByte},
				{ID: 2, Name: "3gpp-uli-plmn-id", DataType: DataTypeOctets, Size: 3},
				{
					ID:       3,
					Name:     "3gpp-uli-data",
					DataType: DataTypeUnion,
					UnionKey: "3gpp-uli-type",
					Children: []*AttributeDefinition{
						{
							ID:       0,
							Name:     "3gpp-uli-cgi",
							DataType: DataTypeStruct,
							Children: []*AttributeDefinition{
								{ID: 1, Name: "3gpp-uli-cgi-lac", DataType: DataTypeShort},
								{ID: 2, Name: "3gpp-uli-cgi-cai", DataType: DataTypeShort},
							},
						},
						{
							ID:       1,
							Name:     "3gpp-uli-sai",
							DataType: DataTypeStruct,
							Children: []*AttributeDefinition{
								{ID: 1, Name: "3gpp-uli-sai-lac", DataType: DataTypeShort},
								{ID: 2, Name: "3gpp-uli-sai-sac", DataType: DataTypeShort},
							},
						},
						{
							ID:       2,
							Name:     "3gpp-uli-rai",
							DataType: DataTypeStruct,
							Children: []*AttributeDefinition{
								{ID: 1, Name: "3gpp-uli-rai-rai", DataType: DataTypeShort},
								{ID: 2, Name: "3gpp-uli-rai-rac", DataType: DataTypeShort},
							},
						},
						{
							ID:       32,
							Name:     "3gpp-uli-lai",
							DataType: DataTypeStruct,
							Children: []*AttributeDefinition{
								{ID: 1, Name: "3gpp-uli-lai-lai", DataType: DataTypeShort},
							},
						},
						{
							ID:       128,
							Name:     "3gpp-uli-tai",
							DataType: DataTypeStruct,
							Children: []*AttributeDefinition{
								{ID: 1, Name: "3gpp-uli-tai-tac", DataType: DataTypeShort},
							},
						},
						{
							ID:       129,
							Name:     "3gpp-uli-ecgi",
							DataType: DataTypeStruct,
							Children: []*AttributeDefinition{
								{ID: 1, Name: "3gpp-uli-ecgi-eci", DataType: DataTypeOctets, Size: 4},
							},
						},
						{
							ID:       130,
							Name:     "3gpp-uli-tai-ecgi",
							DataType: DataTypeStruct,
							Children: []*AttributeDefinition{
								{ID: 1, Name: "3gpp-uli-tai-ecgi-tac", DataType: DataTypeShort},
								{ID: 2, Name: "3gpp-uli-tai-ecgi-plmn-id", DataType: DataTypeOctets, Size: 3},
								{ID: 3, Name: "3gpp-uli-tai-ecgi-eci", DataType: DataTypeOctets, Size: 4},
							},
						},
					},
				},
			},
		},
		{
			ID:       23,
			Name:     "3gpp-ms-timezone",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "3gpp-ms-timezone-tz", DataType: DataTypeByte},
				{ID: 2, Name: "3gpp-ms-timezone-daylight-savings", DataType: DataTypeOctets},
			},
		},
		{ID: 24, Name: "3gpp-camel-charging-info", DataType: DataTypeOctets},
		{
			ID:       25,
			Name:     "3gpp-packet-filter",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "3gpp-packet-filter-identifier", DataType: DataTypeByte},
				{ID: 2, Name: "3gpp-packet-filter-precedence", DataType: DataTypeByte},
				{ID: 3, Name: "3gpp-packet-filter-length", DataType: DataTypeByte},
				{
					ID:       4,
					Name:     "3gpp-packet-filter-direction",
					DataType: DataTypeByte,
					Values: map[string]uint32{
						"downlink": 0,
						"uplink":   1,
					},
				},
				{ID: 5, Name: "3gpp-packet-filter-data", DataType: DataTypeOctets},
			},
		},
		{ID: 26, Name: "3gpp-negotiated-dscp", DataType: DataTypeByte},
		{
			ID:       27,
			Name:     "3gpp-allocate-ip-type",
			DataType: DataTypeByte,
			Values: map[string]uint32{
				"do-not-allocate":        0,
				"allocate-ipv4-address":  1,
				"allocate-ipv6-prefix":   2,
				"allocate-ipv4-and-ipv6": 3,
			},
		},
		{ID: 28, Name: "3gpp-external-identifier", DataType: DataTypeOctets},
		{ID: 29, Name: "3gpp-twan-identifier", DataType: DataTypeOctets},
		{ID: 30, Name: "3gpp-user-location-info-time", DataType: DataTypeDate},
		// Secondary-RAT-Usage packs a bit-field octet (Spare/SESS/RAT) ahead of
		// two dates and two uint64 counters.
		{
			ID:       31,
			Name:     "3gpp-secondary-rat-usage",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "3gpp-secondary-rat-usage-spare", DataType: DataTypeBits, Bits: 3},
				{ID: 2, Name: "3gpp-secondary-rat-usage-sess", DataType: DataTypeBits, Bits: 1},
				{
					ID:       3,
					Name:     "3gpp-secondary-rat-usage-rat",
					DataType: DataTypeBits,
					Bits:     4,
					Values: map[string]uint32{
						"nr":                  0,
						"nr-u":                1,
						"eutra":               3,
						"eutra-u":             4,
						"unlicensed-spectrum": 5,
					},
				},
				{ID: 4, Name: "3gpp-secondary-rat-usage-ran-start-time", DataType: DataTypeDate},
				{ID: 5, Name: "3gpp-secondary-rat-usage-ran-end-time", DataType: DataTypeDate},
				{ID: 6, Name: "3gpp-secondary-rat-usage-usage-data-dl", DataType: DataTypeInteger64},
				{ID: 7, Name: "3gpp-secondary-rat-usage-usage-data-ul", DataType: DataTypeInteger64},
			},
		},
	},
}
