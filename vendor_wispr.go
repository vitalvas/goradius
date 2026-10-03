package goradius

// WISPrVendorDefinition defines the WISPr vendor and its attributes.
// Usage masks follow the Wireless Broadband Alliance RADIUS-VSA tables
// (https://github.com/wireless-broadband-alliance/RADIUS-VSA). The bandwidth
// attributes 5-8 additionally allow Access-Accept: the current WBA table marks
// them request-side only, but legacy WISPr 1.0 deployments universally return
// them in Access-Accept.
var WISPrVendorDefinition = &VendorDefinition{
	ID:   14122,
	Name: "wispr",
	Attributes: []*AttributeDefinition{
		{
			ID:       1,
			Name:     "wispr-location-id",
			DataType: DataTypeString,
			Usage:    UsageAccessRequest | UsageAccountingRequest,
		},
		{
			ID:       2,
			Name:     "wispr-location-name",
			DataType: DataTypeString,
			Usage:    UsageAccessRequest | UsageAccountingRequest,
		},
		{
			ID:       3,
			Name:     "wispr-logoff-url",
			DataType: DataTypeString,
			Usage:    UsageAccessRequest,
		},
		{
			ID:       4,
			Name:     "wispr-redirection-url",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       5,
			Name:     "wispr-bandwidth-min-up",
			DataType: DataTypeInteger,
			Usage:    UsageAccessRequest | UsageAccessAccept | UsageAccountingRequest,
		},
		{
			ID:       6,
			Name:     "wispr-bandwidth-min-down",
			DataType: DataTypeInteger,
			Usage:    UsageAccessRequest | UsageAccessAccept | UsageAccountingRequest,
		},
		{
			ID:       7,
			Name:     "wispr-bandwidth-max-up",
			DataType: DataTypeInteger,
			Usage:    UsageAccessRequest | UsageAccessAccept | UsageAccountingRequest,
		},
		{
			ID:       8,
			Name:     "wispr-bandwidth-max-down",
			DataType: DataTypeInteger,
			Usage:    UsageAccessRequest | UsageAccessAccept | UsageAccountingRequest,
		},
		{
			ID:       9,
			Name:     "wispr-session-terminate-time",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       10,
			Name:     "wispr-session-terminate-end-of-day",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       11,
			Name:     "wispr-billing-class-of-service",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       12,
			Name:     "wispr-wba-offered-service",
			DataType: DataTypeString,
			Usage:    UsageAccessRequest | UsageAccountingRequest,
		},
		{
			ID:       13,
			Name:     "wispr-wba-financial-clearing-provider",
			DataType: DataTypeString,
			Usage:    UsageAccessRequest | UsageAccessAccept | UsageAccountingRequest,
		},
		{
			ID:       14,
			Name:     "wispr-wba-data-clearing-provider",
			DataType: DataTypeString,
			Usage:    UsageAccessRequest | UsageAccessAccept | UsageAccountingRequest,
		},
		{
			ID:       15,
			Name:     "wispr-wba-linear-volume-rate",
			DataType: DataTypeOctets,
			Usage:    UsageAccessRequest | UsageAccessAccept | UsageAccountingRequest,
		},
		{
			ID:       16,
			Name:     "wispr-wba-identity-provider",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       17,
			Name:     "wispr-wba-custom-sla",
			DataType: DataTypeString,
			Usage:    UsageAccessRequest,
		},
	},
}
