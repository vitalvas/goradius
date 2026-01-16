package goradius

// WISPrVendorDefinition defines the WISPr vendor and its attributes
var WISPrVendorDefinition = &VendorDefinition{
	ID:          14122,
	Name:        "WISPr",
	Description: "WISPr (Wireless Internet Service Provider roaming)",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "WISPr-Location-Id", DataType: DataTypeString},
		{ID: 2, Name: "WISPr-Location-Name", DataType: DataTypeString},
		{ID: 3, Name: "WISPr-Logoff-URL", DataType: DataTypeString},
		{ID: 4, Name: "WISPr-Redirection-URL", DataType: DataTypeString},
		{ID: 5, Name: "WISPr-Bandwidth-Min-Up", DataType: DataTypeInteger},
		{ID: 6, Name: "WISPr-Bandwidth-Min-Down", DataType: DataTypeInteger},
		{ID: 7, Name: "WISPr-Bandwidth-Max-Up", DataType: DataTypeInteger},
		{ID: 8, Name: "WISPr-Bandwidth-Max-Down", DataType: DataTypeInteger},
		{ID: 9, Name: "WISPr-Session-Terminate-Time", DataType: DataTypeString},
	},
}
