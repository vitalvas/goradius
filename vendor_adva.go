package goradius

// AdvaVendorDefinition defines the ADVA vendor (ID 2544) for the ADVA Optical
// Networking Fiber Service Platform (FSP). Ported from FreeRADIUS
// dictionary.adva. These are management-plane authorization attributes
// returned to the NE on administrative login.
//
// The dictionary carries no per-packet placement information, so all
// attributes stay unrestricted.
var AdvaVendorDefinition = &VendorDefinition{
	ID:   2544,
	Name: "adva",
	Attributes: []*AttributeDefinition{
		{
			ID:       100,
			Name:     "adva-user-level",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"retrieve":        0,
				"reserved":        1,
				"operate-control": 2,
				"provision":       3,
				"admin":           4,
				"super":           5,
			},
		},
		{
			ID:       101,
			Name:     "adva-auth-level-nm",
			DataType: DataTypeString,
		},
		{
			ID:       102,
			Name:     "adva-uum-user-level",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"monitor":   0,
				"reserved":  1,
				"operator":  2,
				"provision": 3,
				"admin":     4,
				"root":      5,
				"crypto":    6,
				"ftponly":   7,
				"sudoadmin": 8,
			},
		},
	},
}
