package goradius

// MikrotikVendorDefinition defines the Mikrotik vendor and its attributes.
// Usage masks follow the RouterOS RADIUS documentation packet sections
// (https://help.mikrotik.com/docs/display/ROS/RADIUS) and the Wireless Interface
// page for the access-point attributes. The accounting request carries the same
// vendor attributes as the access request, so Access-Request masks include
// Accounting-Request. Attributes without a documented placement stay unrestricted.
var MikrotikVendorDefinition = &VendorDefinition{
	ID:   14988,
	Name: "mikrotik",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "mikrotik-recv-limit", DataType: DataTypeInteger, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 2, Name: "mikrotik-xmit-limit", DataType: DataTypeInteger, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 3, Name: "mikrotik-group", DataType: DataTypeString, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 4, Name: "mikrotik-wireless-forward", DataType: DataTypeInteger, Usage: UsageAccessAccept},
		{ID: 5, Name: "mikrotik-wireless-skip-dot1x", DataType: DataTypeInteger, Usage: UsageAccessAccept},
		{
			ID:       6,
			Name:     "mikrotik-wireless-enc-algo",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"no-encryption": 0,
				"40-bit-wep":    1,
				"104-bit-wep":   2,
				"aes-ccm":       3,
				"tkip":          4,
			},
		},
		{ID: 7, Name: "mikrotik-wireless-enc-key", DataType: DataTypeString, Usage: UsageAccessAccept},
		{ID: 8, Name: "mikrotik-rate-limit", DataType: DataTypeString, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 9, Name: "mikrotik-realm", DataType: DataTypeString, Usage: UsageAccessRequest | UsageAccountingRequest},
		{ID: 10, Name: "mikrotik-host-ip", DataType: DataTypeIPAddr, Usage: UsageAccessRequest | UsageAccountingRequest},
		{ID: 11, Name: "mikrotik-mark-id", DataType: DataTypeString, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 12, Name: "mikrotik-advertise-url", DataType: DataTypeString, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 13, Name: "mikrotik-advertise-interval", DataType: DataTypeInteger, Usage: UsageAccessAccept | UsageCoARequest},
		{ID: 14, Name: "mikrotik-recv-limit-gigawords", DataType: DataTypeInteger, Usage: UsageAccessAccept},
		{ID: 15, Name: "mikrotik-xmit-limit-gigawords", DataType: DataTypeInteger, Usage: UsageAccessAccept},
		{ID: 16, Name: "mikrotik-wireless-psk", DataType: DataTypeString, Usage: UsageAccessAccept},
		{ID: 17, Name: "mikrotik-total-limit", DataType: DataTypeInteger},
		{ID: 18, Name: "mikrotik-total-limit-gigawords", DataType: DataTypeInteger},
		{ID: 19, Name: "mikrotik-address-list", DataType: DataTypeString},
		{ID: 20, Name: "mikrotik-wireless-mpkey", DataType: DataTypeString, Usage: UsageAccessAccept},
		{ID: 21, Name: "mikrotik-wireless-comment", DataType: DataTypeString},
		{ID: 22, Name: "mikrotik-delegated-ipv6-pool", DataType: DataTypeString, Usage: UsageAccessAccept},
		{ID: 23, Name: "mikrotik-dhcp-option-set", DataType: DataTypeString},
		{ID: 24, Name: "mikrotik-dhcp-option-param-str1", DataType: DataTypeString},
		{ID: 25, Name: "mikrotik-dhcp-option-param-str2", DataType: DataTypeString},
		{ID: 26, Name: "mikrotik-wireless-vlanid", DataType: DataTypeInteger, Usage: UsageAccessAccept},
		{
			ID:       27,
			Name:     "mikrotik-wireless-vlanid-type",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"802.1q":  0,
				"802.1ad": 1,
			},
		},
		{ID: 28, Name: "mikrotik-wireless-minsignal", DataType: DataTypeString},
		{ID: 29, Name: "mikrotik-wireless-maxsignal", DataType: DataTypeString},
		{ID: 30, Name: "mikrotik-switching-filter", DataType: DataTypeString, Usage: UsageAccessAccept},
	},
}
