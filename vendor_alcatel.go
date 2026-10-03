package goradius

// AlcatelVendorDefinition defines the Alcatel vendor (ID 3041) for the Alcatel
// Broadband Access Server. Ported from FreeRADIUS dictionary.alcatel; the raw
// attribute names carry the "AAT-" prefix (Alcatel Access Terminal), preserved
// here under the aat- namespace. This is the classic BRAS vendor and is
// distinct from the Alcatel-Lucent Service Router (Nokia TiMOS, vendor 6527)
// and Alcatel-Lucent Enterprise OmniSwitch (vendor 800).
//
// The dictionary carries no per-packet placement information, so all
// attributes stay unrestricted.
var AlcatelVendorDefinition = &VendorDefinition{
	ID:   3041,
	Name: "alcatel",
	Attributes: []*AttributeDefinition{
		{ID: 5, Name: "aat-client-primary-dns", DataType: DataTypeIPAddr},
		{ID: 6, Name: "aat-client-primary-wins-nbns", DataType: DataTypeIPAddr},
		{ID: 7, Name: "aat-client-secondary-wins-nbns", DataType: DataTypeIPAddr},
		{ID: 8, Name: "aat-client-secondary-dns", DataType: DataTypeIPAddr},
		{ID: 9, Name: "aat-ppp-address", DataType: DataTypeIPAddr},
		{ID: 10, Name: "aat-ppp-netmask", DataType: DataTypeIPAddr},
		{ID: 12, Name: "aat-primary-home-agent", DataType: DataTypeString},
		{ID: 13, Name: "aat-secondary-home-agent", DataType: DataTypeString},
		{ID: 14, Name: "aat-home-agent-password", DataType: DataTypeString},
		{ID: 15, Name: "aat-home-network-name", DataType: DataTypeString},
		{ID: 16, Name: "aat-home-agent-udp-port", DataType: DataTypeInteger},
		{ID: 17, Name: "aat-ip-direct", DataType: DataTypeIPAddr},
		{
			ID:       18,
			Name:     "aat-fr-direct",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"no":  0,
				"yes": 1,
			},
		},
		{ID: 19, Name: "aat-fr-direct-profile", DataType: DataTypeString},
		{ID: 20, Name: "aat-fr-direct-dlci", DataType: DataTypeInteger},
		{ID: 21, Name: "aat-atm-direct", DataType: DataTypeString},
		{
			ID:       22,
			Name:     "aat-ip-tos",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"ip-tos-normal":      0,
				"ip-tos-disabled":    1,
				"ip-tos-cost":        2,
				"ip-tos-reliability": 4,
				"ip-tos-throughput":  8,
				"ip-tos-latency":     16,
			},
		},
		{
			ID:       23,
			Name:     "aat-ip-tos-precedence",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"ip-tos-precedence-pri-normal": 0,
				"ip-tos-precedence-pri-one":    32,
				"ip-tos-precedence-pri-two":    64,
				"ip-tos-precedence-pri-three":  96,
				"ip-tos-precedence-pri-four":   128,
				"ip-tos-precedence-pri-five":   160,
				"ip-tos-precedence-pri-six":    192,
				"ip-tos-precedence-pri-seven":  224,
			},
		},
		{
			ID:       24,
			Name:     "aat-ip-tos-apply-to",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"ip-tos-apply-to-incoming": 1024,
				"ip-tos-apply-to-outgoing": 2048,
				"ip-tos-apply-to-both":     3072,
			},
		},
		{
			ID:       27,
			Name:     "aat-mcast-client",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"multicast-no":  0,
				"multicast-yes": 1,
			},
		},
		{ID: 28, Name: "aat-modem-port-no", DataType: DataTypeInteger},
		{ID: 29, Name: "aat-modem-slot-no", DataType: DataTypeInteger},
		{ID: 30, Name: "aat-modem-shelf-no", DataType: DataTypeInteger},
		{ID: 60, Name: "aat-filter", DataType: DataTypeString},
		{ID: 61, Name: "aat-vrouter-name", DataType: DataTypeString},
		{
			ID:       62,
			Name:     "aat-require-auth",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"not-require-auth": 0,
				"require-auth":     1,
			},
		},
		{ID: 63, Name: "aat-ip-pool-definition", DataType: DataTypeString},
		{ID: 64, Name: "aat-assign-ip-pool", DataType: DataTypeInteger},
		{ID: 65, Name: "aat-data-filter", DataType: DataTypeString},
		{
			ID:       66,
			Name:     "aat-source-ip-check",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"source-ip-check-no":  0,
				"source-ip-check-yes": 1,
			},
		},
		{ID: 67, Name: "aat-modem-answer-string", DataType: DataTypeString},
		{
			ID:       68,
			Name:     "aat-auth-type",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"aat-auth-none":    0,
				"aat-auth-default": 1,
				"aat-auth-any":     2,
				"aat-auth-pap":     3,
				"aat-auth-chap":    4,
				"aat-auth-ms-chap": 5,
			},
		},
		{ID: 70, Name: "aat-qos", DataType: DataTypeInteger},
		{ID: 71, Name: "aat-qoa", DataType: DataTypeInteger},
		{
			ID:       72,
			Name:     "aat-client-assign-dns",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"dns-assign-no":  0,
				"dns-assign-yes": 1,
			},
		},
		{ID: 128, Name: "aat-atm-vpi", DataType: DataTypeInteger},
		{ID: 129, Name: "aat-atm-vci", DataType: DataTypeInteger},
		{ID: 130, Name: "aat-input-octets-diff", DataType: DataTypeInteger},
		{ID: 131, Name: "aat-output-octets-diff", DataType: DataTypeInteger},
		{ID: 132, Name: "aat-user-mac-address", DataType: DataTypeString},
		{ID: 133, Name: "aat-atm-traffic-profile", DataType: DataTypeString},
	},
}
