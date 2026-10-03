package goradius

// JuniperVendorDefinition contains the Juniper vendor definition with all its attributes.
// Usage masks follow the Juniper user-access RADIUS documentation, which states the
// packet type per attribute ("This attribute is used only in Access-Accept packets"),
// and the Junos 802.1X topic map for the switching attributes 48-50 and 52:
// https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/user-access-radius-authentication.html
// https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/802-1x-authentication-switching-devices.html
// Attributes without a documented packet placement stay unrestricted.
var JuniperVendorDefinition = &VendorDefinition{
	ID:   2636,
	Name: "juniper",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "juniper-local-user-name", DataType: DataTypeString, Usage: UsageAccessAccept},
		{ID: 2, Name: "juniper-allow-commands", DataType: DataTypeString, Usage: UsageAccessAccept, Multiline: true},
		{ID: 3, Name: "juniper-deny-commands", DataType: DataTypeString, Usage: UsageAccessAccept, Multiline: true},
		{ID: 4, Name: "juniper-allow-configuration", DataType: DataTypeString, Usage: UsageAccessAccept, Multiline: true},
		{ID: 5, Name: "juniper-deny-configuration", DataType: DataTypeString, Usage: UsageAccessAccept, Multiline: true},
		{ID: 8, Name: "juniper-interactive-command", DataType: DataTypeString, Usage: UsageAccountingRequest},
		{ID: 9, Name: "juniper-configuration-change", DataType: DataTypeString, Usage: UsageAccountingRequest},
		{ID: 10, Name: "juniper-user-permissions", DataType: DataTypeString, Usage: UsageAccessAccept, Multiline: true},
		{ID: 11, Name: "juniper-authentication-type", DataType: DataTypeString},
		// IDs 12-14 are not present in the FreeRADIUS dictionary. Source: Juniper
		// "Juniper Networks Vendor-Specific RADIUS Attributes" user-access docs,
		// https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/user-access-radius-authentication.html
		{ID: 12, Name: "juniper-session-port", DataType: DataTypeInteger},
		{ID: 13, Name: "juniper-allow-configuration-regexps", DataType: DataTypeString, Usage: UsageAccessAccept, Multiline: true},
		{ID: 14, Name: "juniper-deny-configuration-regexps", DataType: DataTypeString, Usage: UsageAccessAccept, Multiline: true},
		// IDs 21-23 are CTP/CTPView authorization groups; the CTPView server docs
		// configure them on the RADIUS "Return List", i.e. returned in Access-Accept.
		{
			ID:       21,
			Name:     "juniper-ctp-group",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"read_only":        1,
				"admin":            2,
				"privileged_admin": 3,
				"auditor":          4,
			},
		},
		{
			ID:       22,
			Name:     "juniper-ctpview-app-group",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"net_view":     1,
				"net_admin":    2,
				"global_admin": 3,
			},
		},
		{
			ID:       23,
			Name:     "juniper-ctpview-os-group",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"web_manager":  1,
				"system_admin": 2,
				"auditor":      3,
			},
		},
		{ID: 31, Name: "juniper-primary-dns", DataType: DataTypeIPAddr},
		{ID: 32, Name: "juniper-primary-wins", DataType: DataTypeIPAddr},
		{ID: 33, Name: "juniper-secondary-dns", DataType: DataTypeIPAddr},
		{ID: 34, Name: "juniper-secondary-wins", DataType: DataTypeIPAddr},
		{ID: 35, Name: "juniper-interface-id", DataType: DataTypeString},
		{ID: 36, Name: "juniper-ip-pool-name", DataType: DataTypeString},
		{ID: 37, Name: "juniper-keep-alive", DataType: DataTypeInteger},
		{ID: 38, Name: "juniper-cos-traffic-control-profile", DataType: DataTypeString},
		{ID: 39, Name: "juniper-cos-parameter", DataType: DataTypeString},
		{ID: 40, Name: "juniper-encapsulation-overhead", DataType: DataTypeInteger},
		{ID: 41, Name: "juniper-cell-overhead", DataType: DataTypeInteger},
		{ID: 42, Name: "juniper-tx-connect-speed", DataType: DataTypeInteger},
		{ID: 43, Name: "juniper-rx-connect-speed", DataType: DataTypeInteger},
		{ID: 44, Name: "juniper-firewall-filter-name", DataType: DataTypeString},
		{ID: 45, Name: "juniper-policer-parameter", DataType: DataTypeString},
		{ID: 46, Name: "juniper-local-group-name", DataType: DataTypeString},
		{ID: 47, Name: "juniper-local-interface", DataType: DataTypeString},
		{ID: 48, Name: "juniper-switching-filter", DataType: DataTypeString, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 49, Name: "juniper-voip-vlan", DataType: DataTypeString, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 50, Name: "juniper-cwa-redirect", DataType: DataTypeString, Usage: UsageAccessAccept},
		{ID: 52, Name: "juniper-av-pair", DataType: DataTypeString, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 55, Name: "juniper-dhcpv4-options", DataType: DataTypeOctets},
		{ID: 207, Name: "juniper-dhcpv6-options", DataType: DataTypeOctets},
		{ID: 208, Name: "juniper-dhcpv4-packet-header", DataType: DataTypeOctets},
		{ID: 209, Name: "juniper-dhcpv6-packet-header", DataType: DataTypeOctets},
		{
			ID:       210,
			Name:     "juniper-acct-request-reason",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"ipv4-active":    0x0004,
				"ipv6-active":    0x0010,
				"session-active": 0x0040,
			},
		},
	},
}
