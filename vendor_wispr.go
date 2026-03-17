package goradius

// WISPrVendorDefinition defines the WISPr vendor and its attributes
var WISPrVendorDefinition = &VendorDefinition{
	ID:          14122,
	Name:        "wispr",
	Description: "WISPr (Wireless Internet Service Provider roaming)",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "wispr-location-id", DataType: DataTypeString},
		{ID: 2, Name: "wispr-location-name", DataType: DataTypeString},
		{ID: 3, Name: "wispr-logoff-url", DataType: DataTypeString},
		{ID: 4, Name: "wispr-redirection-url", DataType: DataTypeString},
		{ID: 5, Name: "wispr-bandwidth-min-up", DataType: DataTypeInteger},
		{ID: 6, Name: "wispr-bandwidth-min-down", DataType: DataTypeInteger},
		{ID: 7, Name: "wispr-bandwidth-max-up", DataType: DataTypeInteger},
		{ID: 8, Name: "wispr-bandwidth-max-down", DataType: DataTypeInteger},
		{ID: 9, Name: "wispr-session-terminate-time", DataType: DataTypeString},
	},
}
