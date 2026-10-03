package goradius

// F5VendorDefinition defines the F5 Networks vendor (ID 3375) and its BIG-IP
// remote-role attributes. Ported from FreeRADIUS dictionary.f5. Usage masks
// follow F5 K14324 (the remote-role attributes are returned by the RADIUS
// server in Access-Accept) and K13762 (audit messages are sent to a RADIUS
// accounting server).
var F5VendorDefinition = &VendorDefinition{
	ID:   3375,
	Name: "f5",
	Attributes: []*AttributeDefinition{
		{
			ID:       1,
			Name:     "f5-ltm-user-role",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"administrator":                          0,
				"resource-admin":                         20,
				"user-manager":                           40,
				"auditor":                                80,
				"manager":                                100,
				"app-editor":                             300,
				"advanced-operator":                      350,
				"operator":                               400,
				"firewall-manager":                       450,
				"fraud-protection-manager":               480,
				"certificate-manager":                    500,
				"irule-manager":                          510,
				"guest":                                  700,
				"web-application-security-administrator": 800,
				"web-application-security-editor":        810,
				"acceleration-policy-editor":             850,
				"no-access":                              900,
			},
		},
		{
			ID:       2,
			Name:     "f5-ltm-user-role-universal",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"disabled": 0,
				"enabled":  1,
			},
		},
		{
			ID:       3,
			Name:     "f5-ltm-user-partition",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       4,
			Name:     "f5-ltm-user-console",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
			Values: map[string]uint32{
				"disabled": 0,
				"enabled":  1,
			},
		},
		// Supported shell values are disable, tmsh, and bpsh.
		{
			ID:       5,
			Name:     "f5-ltm-user-shell",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       10,
			Name:     "f5-ltm-user-context-1",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       11,
			Name:     "f5-ltm-user-context-2",
			DataType: DataTypeInteger,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       12,
			Name:     "f5-ltm-user-info-1",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       13,
			Name:     "f5-ltm-user-info-2",
			DataType: DataTypeString,
			Usage:    UsageAccessAccept,
		},
		{
			ID:       14,
			Name:     "f5-ltm-audit-msg",
			DataType: DataTypeString,
			Usage:    UsageAccountingRequest,
		},
	},
}
