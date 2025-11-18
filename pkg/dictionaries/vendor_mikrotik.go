package dictionaries

import "github.com/vitalvas/goradius/pkg/dictionary"

// MikrotikVendorDefinition defines the Mikrotik vendor and its attributes
var MikrotikVendorDefinition = &dictionary.VendorDefinition{
	ID:          14988,
	Name:        "Mikrotik",
	Description: "Mikrotik RouterOS RADIUS attributes",
	Attributes: []*dictionary.AttributeDefinition{
		{ID: 1, Name: "Mikrotik-Recv-Limit", DataType: dictionary.DataTypeInteger},
		{ID: 2, Name: "Mikrotik-Xmit-Limit", DataType: dictionary.DataTypeInteger},
		{ID: 3, Name: "Mikrotik-Group", DataType: dictionary.DataTypeString},
		{ID: 4, Name: "Mikrotik-Wireless-Forward", DataType: dictionary.DataTypeInteger},
		{ID: 5, Name: "Mikrotik-Wireless-Skip-Dot1x", DataType: dictionary.DataTypeInteger},
		{
			ID:       6,
			Name:     "Mikrotik-Wireless-Enc-Algo",
			DataType: dictionary.DataTypeInteger,
			Values: map[string]uint32{
				"No-encryption": 0,
				"40-bit-WEP":    1,
				"104-bit-WEP":   2,
				"AES-CCM":       3,
				"TKIP":          4,
			},
		},
		{ID: 7, Name: "Mikrotik-Wireless-Enc-Key", DataType: dictionary.DataTypeString},
		{ID: 8, Name: "Mikrotik-Rate-Limit", DataType: dictionary.DataTypeString},
		{ID: 9, Name: "Mikrotik-Realm", DataType: dictionary.DataTypeString},
		{ID: 10, Name: "Mikrotik-Host-IP", DataType: dictionary.DataTypeIPAddr},
		{ID: 11, Name: "Mikrotik-Mark-Id", DataType: dictionary.DataTypeString},
		{ID: 12, Name: "Mikrotik-Advertise-URL", DataType: dictionary.DataTypeString},
		{ID: 13, Name: "Mikrotik-Advertise-Interval", DataType: dictionary.DataTypeInteger},
		{ID: 14, Name: "Mikrotik-Recv-Limit-Gigawords", DataType: dictionary.DataTypeInteger},
		{ID: 15, Name: "Mikrotik-Xmit-Limit-Gigawords", DataType: dictionary.DataTypeInteger},
		{ID: 16, Name: "Mikrotik-Wireless-PSK", DataType: dictionary.DataTypeString},
		{ID: 17, Name: "Mikrotik-Total-Limit", DataType: dictionary.DataTypeInteger},
		{ID: 18, Name: "Mikrotik-Total-Limit-Gigawords", DataType: dictionary.DataTypeInteger},
		{ID: 19, Name: "Mikrotik-Address-List", DataType: dictionary.DataTypeString},
		{ID: 20, Name: "Mikrotik-Wireless-MPKey", DataType: dictionary.DataTypeString},
		{ID: 21, Name: "Mikrotik-Wireless-Comment", DataType: dictionary.DataTypeString},
		{ID: 22, Name: "Mikrotik-Delegated-IPv6-Pool", DataType: dictionary.DataTypeString},
		{ID: 23, Name: "Mikrotik-DHCP-Option-Set", DataType: dictionary.DataTypeString},
		{ID: 24, Name: "Mikrotik-DHCP-Option-Param-STR1", DataType: dictionary.DataTypeString},
		{ID: 25, Name: "Mikrotik-DHCP-Option-ParamSTR2", DataType: dictionary.DataTypeString},
		{ID: 26, Name: "Mikrotik-Wireless-VLANID", DataType: dictionary.DataTypeInteger},
		{ID: 27, Name: "Mikrotik-Wireless-VLANID-Type", DataType: dictionary.DataTypeInteger},
		{ID: 28, Name: "Mikrotik-Wireless-Minsignal", DataType: dictionary.DataTypeString},
		{ID: 29, Name: "Mikrotik-Wireless-Maxsignal", DataType: dictionary.DataTypeString},
	},
}
