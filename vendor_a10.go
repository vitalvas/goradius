package goradius

// A10VendorDefinition defines the A10 Networks vendor (ID 22610) and its ACOS
// admin authorization attributes. FreeRADIUS ships no A10 dictionary; the
// attribute set follows the dictionary A10 publishes for RADIUS admin
// authentication (mirrored in the ClearPass community dictionary), and the
// privilege values follow the ACOS access role mapping from the A10 manual.
// The admin attributes are returned by the server on successful login
// (Access-Accept); a10-app-name has no documented packet placement and stays
// unrestricted.
var A10VendorDefinition = &VendorDefinition{
	ID:   22610,
	Name: "a10",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "a10-app-name", DataType: DataTypeString},
		{
			ID:       2,
			Name:     "a10-admin-privilege",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"read-only-admin":             1,
				"read-write-admin":            2,
				"system-admin":                3,
				"network-admin":               4,
				"network-operator":            5,
				"slb-service-admin":           6,
				"slb-service-operator":        7,
				"partition-read-write":        8,
				"partition-network-operator":  9,
				"partition-slb-service-admin": 10,
			},
		},
		// Multiple instances authorize the admin for multiple partitions.
		{
			ID:       3,
			Name:     "a10-admin-partition",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       4,
			Name:     "a10-admin-access-type",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       5,
			Name:     "a10-admin-role",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
	},
}
