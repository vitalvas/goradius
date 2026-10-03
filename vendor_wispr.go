package goradius

// WISPrVendorDefinition defines the WISPr vendor and its attributes
var WISPrVendorDefinition = &VendorDefinition{
	ID:   14122,
	Name: "wispr",
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
		{ID: 10, Name: "wispr-session-terminate-end-of-day", DataType: DataTypeString},
		{ID: 11, Name: "wispr-billing-class-of-service", DataType: DataTypeString},
		{ID: 12, Name: "wispr-wba-offered-service", DataType: DataTypeString},
		{ID: 13, Name: "wispr-wba-financial-clearing-provider", DataType: DataTypeString},
		{ID: 14, Name: "wispr-wba-data-clearing-provider", DataType: DataTypeString},
		{ID: 15, Name: "wispr-wba-linear-volume-rate", DataType: DataTypeOctets},
		{ID: 16, Name: "wispr-wba-identity-provider", DataType: DataTypeString},
		{ID: 17, Name: "wispr-wba-custom-sla", DataType: DataTypeString},
	},
}
