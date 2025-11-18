package dictionaries

import "github.com/vitalvas/goradius/pkg/dictionary"

// WISPrVendorDefinition defines the WISPr vendor and its attributes
var WISPrVendorDefinition = &dictionary.VendorDefinition{
	ID:          14122,
	Name:        "WISPr",
	Description: "WISPr (Wireless Internet Service Provider roaming)",
	Attributes: []*dictionary.AttributeDefinition{
		{ID: 1, Name: "WISPr-Location-Id", DataType: dictionary.DataTypeString},
		{ID: 2, Name: "WISPr-Location-Name", DataType: dictionary.DataTypeString},
		{ID: 3, Name: "WISPr-Logoff-URL", DataType: dictionary.DataTypeString},
		{ID: 4, Name: "WISPr-Redirection-URL", DataType: dictionary.DataTypeString},
		{ID: 5, Name: "WISPr-Bandwidth-Min-Up", DataType: dictionary.DataTypeInteger},
		{ID: 6, Name: "WISPr-Bandwidth-Min-Down", DataType: dictionary.DataTypeInteger},
		{ID: 7, Name: "WISPr-Bandwidth-Max-Up", DataType: dictionary.DataTypeInteger},
		{ID: 8, Name: "WISPr-Bandwidth-Max-Down", DataType: dictionary.DataTypeInteger},
		{ID: 9, Name: "WISPr-Session-Terminate-Time", DataType: dictionary.DataTypeString},
	},
}
