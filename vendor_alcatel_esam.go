package goradius

// AlcatelESAMVendorDefinition defines the Alcatel-ESAM vendor (ID 637) for the
// 7302/7330 ISAM DSLAM. Ported from FreeRADIUS dictionary.alcatel.esam.
//
// The ESAM VSA uses a non-standard header: a 2-octet Vendor-Type and a 1-octet
// Vendor-Length (FreeRADIUS "format=2,1"). The high octet of the type is the
// project ID (0x07 = 7302 ISAM, 0x06 = operator-auth), the low octet the
// attribute. TypeOctets/LengthOctets below drive the wide-format encoder.
//
// The dictionary carries no per-packet placement information, so all
// attributes stay unrestricted.
var AlcatelESAMVendorDefinition = &VendorDefinition{
	ID:           637,
	Name:         "alcatel-esam",
	TypeOctets:   2,
	LengthOctets: 1,
	Attributes: []*AttributeDefinition{
		{ID: 0x0700, Name: "alcatel-esam-vrf-name", DataType: DataTypeString},
		{ID: 0x0701, Name: "alcatel-esam-vlan-id", DataType: DataTypeInteger},
		{ID: 0x0702, Name: "alcatel-esam-qos-profile-name", DataType: DataTypeString},
		{ID: 0x0703, Name: "alcatel-esam-qos-params", DataType: DataTypeString},
		{
			ID:       0x0704,
			Name:     "alcatel-esam-termination-cause",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"unknown-vrf":           1,
				"no-vrf":                2,
				"unknown-vlan":          3,
				"no-vlan":               4,
				"unknown-pool-id":       5,
				"pool-admin-locked":     6,
				"no-pool-id":            7,
				"pool-vrf-inconsistent": 8,
				"unknown-qos-profile":   9,
				"qos-params-syntax-err": 10,
				"ip-addr-in-use":        11,
				"no-ip-addr-available":  12,
				"no-user-ip-addr":       13,
				"missing-attributes":    14,
			},
		},
		// Operator authentication privilege levels (project ID 0x06).
		{ID: 0x0600, Name: "alcatel-esam-a-al-maintenance", DataType: DataTypeInteger, Values: esamPrivLevelValues()},
		{ID: 0x0601, Name: "alcatel-esam-a-al-provisioning", DataType: DataTypeInteger, Values: esamPrivLevelValues()},
		{ID: 0x0602, Name: "alcatel-esam-a-al-tl1-security", DataType: DataTypeInteger},
		{ID: 0x0603, Name: "alcatel-esam-a-al-test", DataType: DataTypeInteger, Values: esamPrivLevelValues()},
		{ID: 0x0705, Name: "alcatel-esam-a-al-maintenance-backward", DataType: DataTypeInteger},
		{ID: 0x0706, Name: "alcatel-esam-a-al-provisioning-backward", DataType: DataTypeInteger},
		{ID: 0x0707, Name: "alcatel-esam-a-al-tl1-security-backward", DataType: DataTypeInteger},
		{ID: 0x0708, Name: "alcatel-esam-a-al-test-backward", DataType: DataTypeInteger},
		{ID: 0x0709, Name: "alcatel-esam-a-al-aaa", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x070A, Name: "alcatel-esam-a-al-atm", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x070B, Name: "alcatel-esam-a-al-alarm", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x070C, Name: "alcatel-esam-a-al-dhcp", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x070D, Name: "alcatel-esam-a-al-eqp", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x070E, Name: "alcatel-esam-a-al-igmp", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x070F, Name: "alcatel-esam-a-al-cpeproxy", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0710, Name: "alcatel-esam-a-al-ip", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0711, Name: "alcatel-esam-a-al-pppoe", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0712, Name: "alcatel-esam-a-al-qos", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0713, Name: "alcatel-esam-a-al-swmgt", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0714, Name: "alcatel-esam-a-al-transport", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0715, Name: "alcatel-esam-a-al-vlan", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0716, Name: "alcatel-esam-a-al-xdsl", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0717, Name: "alcatel-esam-a-al-security", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0718, Name: "alcatel-esam-a-al-cluster", DataType: DataTypeInteger, Values: esamRWPrivValues()},
		{ID: 0x0719, Name: "alcatel-esam-a-al-prompt", DataType: DataTypeString},
		{ID: 0x071A, Name: "alcatel-esam-a-al-pwd-timeout", DataType: DataTypeInteger},
		{ID: 0x071B, Name: "alcatel-esam-a-al-description", DataType: DataTypeString},
		{
			ID:       0x071C,
			Name:     "alcatel-esam-a-al-slot-numbering",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"slot-numbering-type":     1,
				"slot-numbering-position": 2,
				"slot-numbering-legacy":   3,
			},
		},
	},
}

// esamPrivLevelValues returns the 0-7 maintenance privilege levels shared by
// the A-AL-Maintenance/Provisioning/Test attributes.
func esamPrivLevelValues() map[string]uint32 {
	return map[string]uint32{
		"alcatel-no-maint-priv-level": 0,
		"alcatel-maint-priv-level-1":  1,
		"alcatel-maint-priv-level-2":  2,
		"alcatel-maint-priv-level-3":  3,
		"alcatel-maint-priv-level-4":  4,
		"alcatel-maint-priv-level-5":  5,
		"alcatel-maint-priv-level-6":  6,
		"alcatel-maint-priv-level-7":  7,
	}
}

// esamRWPrivValues returns the no/read/write/read-write privilege set shared by
// the per-subsystem A-AL operator authorization attributes.
func esamRWPrivValues() map[string]uint32 {
	return map[string]uint32{
		"alcatel-no-priv":    0,
		"alcatel-read-priv":  1,
		"alcatel-write-priv": 2,
		"alcatel-rw-priv":    3,
	}
}
