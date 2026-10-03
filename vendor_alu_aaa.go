package goradius

// ALUAAAVendorDefinition defines the Alcatel-Lucent AAA vendor (ID 831).
// Ported from FreeRADIUS dictionary.alcatel-lucent.aaa. This is the ALU AAA
// server VSA set (femtocell/SIM authentication, lawful intercept, and the
// generic scratch attributes) and is distinct from the Alcatel BRAS vendor
// (3041) and the Alcatel-ESAM ISAM vendor (637).
//
// The dictionary carries no per-packet placement information, so all
// attributes stay unrestricted. The library models only the standard 1-octet
// VSA header, so the byte (lawful-intercept-status), short (df-cc-port), and
// combo-ip (address-0..3) attributes are carried as raw octets, preserving
// their on-wire width. The key-0..3 attributes use Tunnel-Password salted
// encryption.
var ALUAAAVendorDefinition = &VendorDefinition{
	ID:   831,
	Name: "alu-aaa",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "alu-aaa-access-rule", DataType: DataTypeString},
		{ID: 2, Name: "alu-aaa-av-pair", DataType: DataTypeString},
		{ID: 3, Name: "alu-aaa-gsm-triplets-needed", DataType: DataTypeInteger},
		{ID: 4, Name: "alu-aaa-gsm-triplet", DataType: DataTypeOctets},
		{ID: 5, Name: "alu-aaa-aka-quintets-needed", DataType: DataTypeInteger},
		{ID: 6, Name: "alu-aaa-aka-quintet", DataType: DataTypeOctets},
		{ID: 7, Name: "alu-aaa-aka-rand", DataType: DataTypeOctets},
		{ID: 8, Name: "alu-aaa-aka-auts", DataType: DataTypeOctets},
		{ID: 9, Name: "alu-aaa-service-profile", DataType: DataTypeString},
		// byte in the dictionary; carried as a single octet.
		{ID: 10, Name: "alu-aaa-lawful-intercept-status", DataType: DataTypeOctets},
		{ID: 11, Name: "alu-aaa-df-cc-address", DataType: DataTypeIPAddr},
		// short in the dictionary; carried as two octets.
		{ID: 12, Name: "alu-aaa-df-cc-port", DataType: DataTypeOctets},
		{ID: 13, Name: "alu-aaa-client-program", DataType: DataTypeString},
		{
			ID:       14,
			Name:     "alu-aaa-client-error-action",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"ignore":     1,
				"disconnect": 2,
			},
		},
		{ID: 15, Name: "alu-aaa-client-os", DataType: DataTypeString},
		{ID: 16, Name: "alu-aaa-client-version", DataType: DataTypeString},
		{ID: 17, Name: "alu-aaa-nonce", DataType: DataTypeOctets},
		{ID: 18, Name: "alu-aaa-femto-public-key-hash", DataType: DataTypeOctets},
		{ID: 19, Name: "alu-aaa-femto-associated-user-name", DataType: DataTypeString},
		{ID: 100, Name: "alu-aaa-string-0", DataType: DataTypeString},
		{ID: 101, Name: "alu-aaa-string-1", DataType: DataTypeString},
		{ID: 102, Name: "alu-aaa-string-2", DataType: DataTypeString},
		{ID: 103, Name: "alu-aaa-string-3", DataType: DataTypeString},
		{ID: 104, Name: "alu-aaa-integer-0", DataType: DataTypeInteger},
		{ID: 105, Name: "alu-aaa-integer-1", DataType: DataTypeInteger},
		{ID: 106, Name: "alu-aaa-integer-2", DataType: DataTypeInteger},
		{ID: 107, Name: "alu-aaa-integer-3", DataType: DataTypeInteger},
		// combo-ip in the dictionary (IPv4 or IPv6); carried as raw octets.
		{ID: 108, Name: "alu-aaa-address-0", DataType: DataTypeOctets},
		{ID: 109, Name: "alu-aaa-address-1", DataType: DataTypeOctets},
		{ID: 110, Name: "alu-aaa-address-2", DataType: DataTypeOctets},
		{ID: 111, Name: "alu-aaa-address-3", DataType: DataTypeOctets},
		{ID: 112, Name: "alu-aaa-value-0", DataType: DataTypeOctets},
		{ID: 113, Name: "alu-aaa-value-1", DataType: DataTypeOctets},
		{ID: 114, Name: "alu-aaa-value-2", DataType: DataTypeOctets},
		{ID: 115, Name: "alu-aaa-value-3", DataType: DataTypeOctets},
		{
			ID:         116,
			Name:       "alu-aaa-key-0",
			DataType:   DataTypeOctets,
			Encryption: EncryptionTunnelPassword,
		},
		{
			ID:         117,
			Name:       "alu-aaa-key-1",
			DataType:   DataTypeOctets,
			Encryption: EncryptionTunnelPassword,
		},
		{
			ID:         118,
			Name:       "alu-aaa-key-2",
			DataType:   DataTypeOctets,
			Encryption: EncryptionTunnelPassword,
		},
		{
			ID:         119,
			Name:       "alu-aaa-key-3",
			DataType:   DataTypeOctets,
			Encryption: EncryptionTunnelPassword,
		},
		{ID: 120, Name: "alu-aaa-opaque-0", DataType: DataTypeOctets},
		{ID: 121, Name: "alu-aaa-opaque-1", DataType: DataTypeOctets},
		{ID: 122, Name: "alu-aaa-opaque-2", DataType: DataTypeOctets},
		{ID: 123, Name: "alu-aaa-opaque-3", DataType: DataTypeOctets},
		{ID: 124, Name: "alu-aaa-eval-0", DataType: DataTypeString},
		{ID: 125, Name: "alu-aaa-eval-1", DataType: DataTypeString},
		{ID: 126, Name: "alu-aaa-eval-2", DataType: DataTypeString},
		{ID: 127, Name: "alu-aaa-eval-3", DataType: DataTypeString},
		{ID: 128, Name: "alu-aaa-exec-0", DataType: DataTypeString},
		{ID: 129, Name: "alu-aaa-exec-1", DataType: DataTypeString},
		{ID: 130, Name: "alu-aaa-exec-2", DataType: DataTypeString},
		{ID: 131, Name: "alu-aaa-exec-3", DataType: DataTypeString},
		{ID: 199, Name: "alu-aaa-original-receipt-time", DataType: DataTypeOctets},
		{ID: 201, Name: "alu-aaa-reply-message", DataType: DataTypeString},
		{ID: 202, Name: "alu-aaa-called-station-id", DataType: DataTypeString},
		{ID: 203, Name: "alu-aaa-nas-ip-address", DataType: DataTypeIPAddr},
		{ID: 204, Name: "alu-aaa-nas-port", DataType: DataTypeInteger},
		{ID: 205, Name: "alu-aaa-old-state", DataType: DataTypeString},
		{ID: 206, Name: "alu-aaa-new-state", DataType: DataTypeString},
		{ID: 207, Name: "alu-aaa-event", DataType: DataTypeString},
		{ID: 208, Name: "alu-aaa-old-timestamp", DataType: DataTypeDate},
		{ID: 209, Name: "alu-aaa-new-timestamp", DataType: DataTypeDate},
		{
			ID:       210,
			Name:     "alu-aaa-delta-session",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"false": 0,
				"true":  1,
			},
		},
		{ID: 211, Name: "alu-aaa-civic-location", DataType: DataTypeOctets},
		{ID: 212, Name: "alu-aaa-geospatial-location", DataType: DataTypeOctets},
	},
}
