package goradius

// StandardRFCAttributes contains all RFC standard attributes
var StandardRFCAttributes = []*AttributeDefinition{
	{ID: 1, Name: "User-Name", DataType: DataTypeString},                                         // RFC2865
	{ID: 2, Name: "User-Password", DataType: DataTypeString, Encryption: EncryptionUserPassword}, // RFC2865
	{ID: 3, Name: "CHAP-Password", DataType: DataTypeOctets},                                     // RFC2865
	{ID: 4, Name: "NAS-IP-Address", DataType: DataTypeIPAddr},                                    // RFC2865
	{ID: 5, Name: "NAS-Port", DataType: DataTypeInteger},                                         // RFC2865
	{ // RFC2865
		ID:       6,
		Name:     "Service-Type",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Login-User":              1,  // RFC2865
			"Framed-User":             2,  // RFC2865
			"Callback-Login-User":     3,  // RFC2865
			"Callback-Framed-User":    4,  // RFC2865
			"Outbound-User":           5,  // RFC2865
			"Administrative-User":     6,  // RFC2865
			"NAS-Prompt-User":         7,  // RFC2865
			"Authenticate-Only":       8,  // RFC2865
			"Callback-NAS-Prompt":     9,  // RFC2865
			"Call-Check":              10, // RFC2865
			"Callback-Administrative": 11, // RFC2865
			"Authorize-Only":          17, // RFC2865
			"Framed-Management":       18, // RFC2865
		},
	},
	{ // RFC2865
		ID:       7,
		Name:     "Framed-Protocol",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"PPP":               1, // RFC2865
			"SLIP":              2, // RFC2865
			"ARAP":              3, // RFC2865
			"Gandalf-SLML":      4, // RFC2865
			"Xylogics-IPX-SLIP": 5, // RFC2865
			"X.75-Synchronous":  6, // RFC2865
		},
	},
	{ID: 8, Name: "Framed-IP-Address", DataType: DataTypeIPAddr}, // RFC2865
	{ID: 9, Name: "Framed-IP-Netmask", DataType: DataTypeIPAddr}, // RFC2865
	{ // RFC2865
		ID:       10,
		Name:     "Framed-Routing",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"None":             0, // RFC2865
			"Broadcast":        1, // RFC2865
			"Listen":           2, // RFC2865
			"Broadcast-Listen": 3, // RFC2865
		},
	},
	{ID: 11, Name: "Filter-Id", DataType: DataTypeString},   // RFC2865
	{ID: 12, Name: "Framed-MTU", DataType: DataTypeInteger}, // RFC2865
	{ // RFC2865
		ID:       13,
		Name:     "Framed-Compression",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"None":                   0, // RFC2865
			"Van-Jacobson-TCP-IP":    1, // RFC2865
			"IPX-Header-Compression": 2, // RFC2865
			"Stac-LZS":               3, // RFC2865
		},
	},
	{ID: 14, Name: "Login-IP-Host", DataType: DataTypeIPAddr}, // RFC2865
	{ // RFC2865
		ID:       15,
		Name:     "Login-Service",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Telnet":          0, // RFC2865
			"Rlogin":          1, // RFC2865
			"TCP-Clear":       2, // RFC2865
			"PortMaster":      3, // RFC2865
			"LAT":             4, // RFC2865
			"X25-PAD":         5, // RFC2865
			"X25-T3POS":       6, // RFC2865
			"TCP-Clear-Quiet": 8, // RFC2865
		},
	},
	{ // RFC2865
		ID:       16,
		Name:     "Login-TCP-Port",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Telnet": 23,  // RFC2865
			"Rlogin": 513, // RFC2865
			"Rsh":    514, // RFC2865
		},
	},
	{ID: 18, Name: "Reply-Message", DataType: DataTypeString},      // RFC2865
	{ID: 19, Name: "Callback-Number", DataType: DataTypeString},    // RFC2865
	{ID: 20, Name: "Callback-Id", DataType: DataTypeString},        // RFC2865
	{ID: 22, Name: "Framed-Route", DataType: DataTypeString},       // RFC2865
	{ID: 23, Name: "Framed-IPX-Network", DataType: DataTypeIPAddr}, // RFC2865
	{ID: 24, Name: "State", DataType: DataTypeOctets},              // RFC2865
	{ID: 25, Name: "Class", DataType: DataTypeOctets},              // RFC2865
	{ID: 26, Name: "Vendor-Specific", DataType: DataTypeOctets},    // RFC2865
	{ID: 27, Name: "Session-Timeout", DataType: DataTypeInteger},   // RFC2865
	{ID: 28, Name: "Idle-Timeout", DataType: DataTypeInteger},      // RFC2865
	{ // RFC2865
		ID:       29,
		Name:     "Termination-Action",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Default":        0, // RFC2865
			"RADIUS-Request": 1, // RFC2865
		},
	},
	{ID: 30, Name: "Called-Station-Id", DataType: DataTypeString},         // RFC2865
	{ID: 31, Name: "Calling-Station-Id", DataType: DataTypeString},        // RFC2865
	{ID: 32, Name: "NAS-Identifier", DataType: DataTypeString},            // RFC2865
	{ID: 33, Name: "Proxy-State", DataType: DataTypeOctets},               // RFC2865
	{ID: 34, Name: "Login-LAT-Service", DataType: DataTypeString},         // RFC2865
	{ID: 35, Name: "Login-LAT-Node", DataType: DataTypeString},            // RFC2865
	{ID: 36, Name: "Login-LAT-Group", DataType: DataTypeOctets},           // RFC2865
	{ID: 37, Name: "Framed-AppleTalk-Link", DataType: DataTypeInteger},    // RFC2865
	{ID: 38, Name: "Framed-AppleTalk-Network", DataType: DataTypeInteger}, // RFC2865
	{ID: 39, Name: "Framed-AppleTalk-Zone", DataType: DataTypeString},     // RFC2865
	{ // RFC2866
		ID:       40,
		Name:     "Acct-Status-Type",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Start":              1,  // RFC2866
			"Stop":               2,  // RFC2866
			"Alive":              3,  // RFC2866
			"Interim-Update":     3,  // RFC2866
			"Accounting-On":      7,  // RFC2866
			"Accounting-Off":     8,  // RFC2866
			"Tunnel-Start":       9,  // RFC2866
			"Tunnel-Stop":        10, // RFC2866
			"Tunnel-Reject":      11, // RFC2866
			"Tunnel-Link-Start":  12, // RFC2866
			"Tunnel-Link-Stop":   13, // RFC2866
			"Tunnel-Link-Reject": 14, // RFC2866
			"Failed":             15, // RFC2866
		},
	},
	{ID: 41, Name: "Acct-Delay-Time", DataType: DataTypeInteger},    // RFC2866
	{ID: 42, Name: "Acct-Input-Octets", DataType: DataTypeInteger},  // RFC2866
	{ID: 43, Name: "Acct-Output-Octets", DataType: DataTypeInteger}, // RFC2866
	{ID: 44, Name: "Acct-Session-Id", DataType: DataTypeString},     // RFC2866
	{ // RFC2866
		ID:       45,
		Name:     "Acct-Authentic",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"RADIUS":   1, // RFC2866
			"Local":    2, // RFC2866
			"Remote":   3, // RFC2866
			"Diameter": 4, // RFC2866
		},
	},
	{ID: 46, Name: "Acct-Session-Time", DataType: DataTypeInteger},   // RFC2866
	{ID: 47, Name: "Acct-Input-Packets", DataType: DataTypeInteger},  // RFC2866
	{ID: 48, Name: "Acct-Output-Packets", DataType: DataTypeInteger}, // RFC2866
	{ // RFC2866
		ID:       49,
		Name:     "Acct-Terminate-Cause",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"User-Request":             1,  // RFC2866
			"Lost-Carrier":             2,  // RFC2866
			"Lost-Service":             3,  // RFC2866
			"Idle-Timeout":             4,  // RFC2866
			"Session-Timeout":          5,  // RFC2866
			"Admin-Reset":              6,  // RFC2866
			"Admin-Reboot":             7,  // RFC2866
			"Port-Error":               8,  // RFC2866
			"NAS-Error":                9,  // RFC2866
			"NAS-Request":              10, // RFC2866
			"NAS-Reboot":               11, // RFC2866
			"Port-Unneeded":            12, // RFC2866
			"Port-Preempted":           13, // RFC2866
			"Port-Suspended":           14, // RFC2866
			"Service-Unavailable":      15, // RFC2866
			"Callback":                 16, // RFC2866
			"User-Error":               17, // RFC2866
			"Host-Request":             18, // RFC2866
			"Supplicant-Restart":       19, // RFC2866
			"Reauthentication-Failure": 20, // RFC2866
			"Port-Reinit":              21, // RFC2866
			"Port-Disabled":            22, // RFC2866
		},
	},
	{ID: 50, Name: "Acct-Multi-Session-Id", DataType: DataTypeString},  // RFC2866
	{ID: 51, Name: "Acct-Link-Count", DataType: DataTypeInteger},       // RFC2866
	{ID: 52, Name: "Acct-Input-Gigawords", DataType: DataTypeInteger},  // RFC2869
	{ID: 53, Name: "Acct-Output-Gigawords", DataType: DataTypeInteger}, // RFC2869
	{ID: 55, Name: "Event-Timestamp", DataType: DataTypeDate},          // RFC2869
	{ID: 56, Name: "Egress-VLANID", DataType: DataTypeInteger},         // RFC4675
	{ // RFC4675
		ID:       57,
		Name:     "Ingress-Filters",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Enabled":  1, // RFC4675
			"Disabled": 2, // RFC4675
		},
	},
	{ID: 58, Name: "Egress-VLAN-Name", DataType: DataTypeString},    // RFC4675
	{ID: 59, Name: "User-Priority-Table", DataType: DataTypeOctets}, // RFC4675
	{ID: 60, Name: "CHAP-Challenge", DataType: DataTypeOctets},      // RFC2865
	{ // RFC2865
		ID:       61,
		Name:     "NAS-Port-Type",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Async":              0,  // RFC2865
			"Sync":               1,  // RFC2865
			"ISDN":               2,  // RFC2865
			"ISDN-V120":          3,  // RFC2865
			"ISDN-V110":          4,  // RFC2865
			"Virtual":            5,  // RFC2865
			"PIAFS":              6,  // RFC2865
			"HDLC-Clear-Channel": 7,  // RFC2865
			"X.25":               8,  // RFC2865
			"X.75":               9,  // RFC2865
			"G.3-Fax":            10, // RFC2865
			"SDSL":               11, // RFC2865
			"ADSL-CAP":           12, // RFC2865
			"ADSL-DMT":           13, // RFC2865
			"IDSL":               14, // RFC2865
			"Ethernet":           15, // RFC2865
			"xDSL":               16, // RFC2865
			"Cable":              17, // RFC2865
			"Wireless-Other":     18, // RFC2865
			"Wireless-802.11":    19, // RFC2865
			"Token-Ring":         20, // RFC2865
			"FDDI":               21, // RFC2865
			"PPPoA":              30, // RFC2865
			"PPPoEoA":            31, // RFC2865
			"PPPoEoE":            32, // RFC2865
			"PPPoEoVLAN":         33, // RFC2865
			"PPPoEoQinQ":         34, // RFC2865
		},
	},
	{ID: 62, Name: "Port-Limit", DataType: DataTypeInteger},    // RFC2865
	{ID: 63, Name: "Login-LAT-Port", DataType: DataTypeString}, // RFC2865
	{ // RFC2868
		ID:       64,
		Name:     "Tunnel-Type",
		DataType: DataTypeInteger,
		HasTag:   true,
		Values: map[string]uint32{
			"PPTP":     1,  // RFC2868
			"L2F":      2,  // RFC2868
			"L2TP":     3,  // RFC2868
			"ATMP":     4,  // RFC2868
			"VTP":      5,  // RFC2868
			"AH":       6,  // RFC2868
			"IP":       7,  // RFC2868
			"MIN-IP":   8,  // RFC2868
			"ESP":      9,  // RFC2868
			"GRE":      10, // RFC2868
			"DVS":      11, // RFC2868
			"IP-in-IP": 12, // RFC2868
			"VLAN":     13, // RFC2868
		},
	},
	{ // RFC2868
		ID:       65,
		Name:     "Tunnel-Medium-Type",
		DataType: DataTypeInteger,
		HasTag:   true,
		Values: map[string]uint32{
			"IP":           1,  // RFC2868
			"IPv4":         1,  // RFC2868
			"IPv6":         2,  // RFC2868
			"NSAP":         3,  // RFC2868
			"HDLC":         4,  // RFC2868
			"BBN-1822":     5,  // RFC2868
			"IEEE-802":     6,  // RFC2868
			"E.163":        7,  // RFC2868
			"E.164":        8,  // RFC2868
			"F.69":         9,  // RFC2868
			"X.121":        10, // RFC2868
			"IPX":          11, // RFC2868
			"Appletalk":    12, // RFC2868
			"DecNet-IV":    13, // RFC2868
			"Banyan-Vines": 14, // RFC2868
			"E.164-NSAP":   15, // RFC2868
		},
	},
	{ID: 66, Name: "Tunnel-Client-Endpoint", DataType: DataTypeString, HasTag: true},                                // RFC2868
	{ID: 67, Name: "Tunnel-Server-Endpoint", DataType: DataTypeString, HasTag: true},                                // RFC2868
	{ID: 68, Name: "Acct-Tunnel-Connection", DataType: DataTypeString},                                              // RFC2867
	{ID: 69, Name: "Tunnel-Password", DataType: DataTypeString, HasTag: true, Encryption: EncryptionTunnelPassword}, // RFC2868
	{ID: 70, Name: "ARAP-Password", DataType: DataTypeOctets},                                                       // RFC2869
	{ID: 71, Name: "ARAP-Features", DataType: DataTypeOctets},                                                       // RFC2869
	{ // RFC2869
		ID:       72,
		Name:     "ARAP-Zone-Access",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Default-Zone":          1, // RFC2869
			"Zone-Filter-Inclusive": 2, // RFC2869
			"Zone-Filter-Exclusive": 4, // RFC2869
		},
	},
	{ID: 73, Name: "ARAP-Security", DataType: DataTypeInteger},     // RFC2869
	{ID: 74, Name: "ARAP-Security-Data", DataType: DataTypeString}, // RFC2869
	{ID: 75, Name: "Password-Retry", DataType: DataTypeInteger},    // RFC2869
	{ // RFC2869
		ID:       76,
		Name:     "Prompt",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"No-Echo": 0, // RFC2869
			"Echo":    1, // RFC2869
		},
	},
	{ID: 77, Name: "Connect-Info", DataType: DataTypeString},                          // RFC2869
	{ID: 78, Name: "Configuration-Token", DataType: DataTypeString},                   // RFC2869
	{ID: 79, Name: "EAP-Message", DataType: DataTypeOctets},                           // RFC2869
	{ID: 80, Name: "Message-Authenticator", DataType: DataTypeOctets},                 // RFC2869
	{ID: 81, Name: "Tunnel-Private-Group-Id", DataType: DataTypeString, HasTag: true}, // RFC2868
	{ID: 82, Name: "Tunnel-Assignment-Id", DataType: DataTypeString, HasTag: true},    // RFC2868
	{ID: 83, Name: "Tunnel-Preference", DataType: DataTypeInteger, HasTag: true},      // RFC2868
	{ID: 84, Name: "ARAP-Challenge-Response", DataType: DataTypeOctets},               // RFC2869
	{ID: 85, Name: "Acct-Interim-Interval", DataType: DataTypeInteger},                // RFC2869
	{ID: 86, Name: "Acct-Tunnel-Packets-Lost", DataType: DataTypeInteger},             // RFC2867
	{ID: 87, Name: "NAS-Port-Id", DataType: DataTypeString},                           // RFC2869
	{ID: 88, Name: "Framed-Pool", DataType: DataTypeString},                           // RFC2869
	{ID: 89, Name: "Chargeable-User-Identity", DataType: DataTypeOctets},              // RFC4372
	{ID: 90, Name: "Tunnel-Client-Auth-Id", DataType: DataTypeString, HasTag: true},   // RFC2868
	{ID: 91, Name: "Tunnel-Server-Auth-Id", DataType: DataTypeString, HasTag: true},   // RFC2868
	{ID: 92, Name: "NAS-Filter-Rule", DataType: DataTypeString},                       // RFC4849
	{ID: 94, Name: "Originating-Line-Info", DataType: DataTypeOctets},                 // RFC7155
	{ID: 95, Name: "NAS-IPv6-Address", DataType: DataTypeIPv6Addr},                    // RFC3162
	{ID: 96, Name: "Framed-Interface-Id", DataType: DataTypeIfID},                     // RFC3162
	{ID: 97, Name: "Framed-IPv6-Prefix", DataType: DataTypeIPv6Prefix},                // RFC3162
	{ID: 98, Name: "Login-IPv6-Host", DataType: DataTypeIPv6Addr},                     // RFC3162
	{ID: 99, Name: "Framed-IPv6-Route", DataType: DataTypeString},                     // RFC3162
	{ID: 100, Name: "Framed-IPv6-Pool", DataType: DataTypeString},                     // RFC3162
	{ // RFC3576
		ID:       101,
		Name:     "Error-Cause",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Residual-Context-Removed":               201, // RFC3576
			"Invalid-EAP-Packet":                     202, // RFC3576
			"Unsupported-Attribute":                  401, // RFC3576
			"Missing-Attribute":                      402, // RFC3576
			"NAS-Identification-Mismatch":            403, // RFC3576
			"Invalid-Request":                        404, // RFC3576
			"Unsupported-Service":                    405, // RFC3576
			"Unsupported-Extension":                  406, // RFC3576
			"Invalid-Attribute-Value":                407, // RFC3576
			"Administratively-Prohibited":            501, // RFC3576
			"Proxy-Request-Not-Routable":             502, // RFC3576
			"Session-Context-Not-Found":              503, // RFC3576
			"Session-Context-Not-Removable":          504, // RFC3576
			"Proxy-Processing-Error":                 505, // RFC3576
			"Resources-Unavailable":                  506, // RFC3576
			"Request-Initiated":                      507, // RFC3576
			"Multiple-Session-Selection-Unsupported": 508, // RFC3576
		},
	},
	{ID: 102, Name: "EAP-Key-Name", DataType: DataTypeOctets},                   // RFC4072
	{ID: 103, Name: "Digest-Response", DataType: DataTypeString},                // RFC5090
	{ID: 104, Name: "Digest-Realm", DataType: DataTypeString},                   // RFC5090
	{ID: 105, Name: "Digest-Nonce", DataType: DataTypeString},                   // RFC5090
	{ID: 106, Name: "Digest-Response-Auth", DataType: DataTypeString},           // RFC5090
	{ID: 107, Name: "Digest-Nextnonce", DataType: DataTypeString},               // RFC5090
	{ID: 108, Name: "Digest-Method", DataType: DataTypeString},                  // RFC5090
	{ID: 109, Name: "Digest-URI", DataType: DataTypeString},                     // RFC5090
	{ID: 110, Name: "Digest-Qop", DataType: DataTypeString},                     // RFC5090
	{ID: 111, Name: "Digest-Algorithm", DataType: DataTypeString},               // RFC5090
	{ID: 112, Name: "Digest-Entity-Body-Hash", DataType: DataTypeString},        // RFC5090
	{ID: 113, Name: "Digest-CNonce", DataType: DataTypeString},                  // RFC5090
	{ID: 114, Name: "Digest-Nonce-Count", DataType: DataTypeString},             // RFC5090
	{ID: 115, Name: "Digest-Username", DataType: DataTypeString},                // RFC5090
	{ID: 116, Name: "Digest-Opaque", DataType: DataTypeString},                  // RFC5090
	{ID: 117, Name: "Digest-Auth-Param", DataType: DataTypeString},              // RFC5090
	{ID: 118, Name: "Digest-AKA-Auts", DataType: DataTypeString},                // RFC5090
	{ID: 119, Name: "Digest-Domain", DataType: DataTypeString},                  // RFC5090
	{ID: 120, Name: "Digest-Stale", DataType: DataTypeString},                   // RFC5090
	{ID: 121, Name: "Digest-HA1", DataType: DataTypeString},                     // RFC5090
	{ID: 122, Name: "SIP-AOR", DataType: DataTypeString},                        // RFC5090
	{ID: 123, Name: "Delegated-IPv6-Prefix", DataType: DataTypeIPv6Prefix},      // RFC4818
	{ID: 124, Name: "MIP6-Feature-Vector", DataType: DataTypeOctets},            // RFC5447
	{ID: 125, Name: "MIP6-Home-Link-Prefix", DataType: DataTypeOctets},          // RFC5447
	{ID: 126, Name: "Operator-Name", DataType: DataTypeString},                  // RFC5580
	{ID: 127, Name: "Location-Information", DataType: DataTypeOctets},           // RFC5580
	{ID: 128, Name: "Location-Data", DataType: DataTypeOctets},                  // RFC5580
	{ID: 129, Name: "Basic-Location-Policy-Rules", DataType: DataTypeOctets},    // RFC5580
	{ID: 130, Name: "Extended-Location-Policy-Rules", DataType: DataTypeString}, // RFC5580
	{ // RFC5580
		ID:       131,
		Name:     "Location-Capable",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Civic-Location": 1, // RFC5580
			"Geo-Location":   2, // RFC5580
			"Users-Location": 4, // RFC5580
			"NAS-Location":   8, // RFC5580
		},
	},
	{ // RFC5580
		ID:       132,
		Name:     "Requested-Location-Info",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Civic-Location":  1,  // RFC5580
			"Geo-Location":    2,  // RFC5580
			"Users-Location":  4,  // RFC5580
			"NAS-Location":    8,  // RFC5580
			"Future-Requests": 16, // RFC5580
			"None":            32, // RFC5580
		},
	},
	{ // RFC5607
		ID:       133,
		Name:     "Framed-Management",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"SNMP":      1, // RFC5607
			"Web-Based": 2, // RFC5607
			"Netconf":   3, // RFC5607
			"FTP":       4, // RFC5607
			"TFTP":      5, // RFC5607
			"SFTP":      6, // RFC5607
			"RCP":       7, // RFC5607
			"SCP":       8, // RFC5607
		},
	},
	{ // RFC5607
		ID:       134,
		Name:     "Management-Transport-Protection",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"No-Protection":                        1, // RFC5607
			"Integrity-Protection":                 2, // RFC5607
			"Integrity-Confidentiality-Protection": 3, // RFC5607
		},
	},
	{ID: 135, Name: "Management-Policy-Id", DataType: DataTypeString},                 // RFC5607
	{ID: 136, Name: "Management-Privilege-Level", DataType: DataTypeInteger},          // RFC5607
	{ID: 137, Name: "PKM-SS-Cert", DataType: DataTypeOctets},                          // RFC5904
	{ID: 138, Name: "PKM-CA-Cert", DataType: DataTypeOctets},                          // RFC5904
	{ID: 139, Name: "PKM-Config-Settings", DataType: DataTypeOctets},                  // RFC5904
	{ID: 140, Name: "PKM-Cryptosuite-List", DataType: DataTypeOctets},                 // RFC5904
	{ID: 141, Name: "PKM-SAID", DataType: DataTypeInteger},                            // RFC5904
	{ID: 142, Name: "PKM-SA-Descriptor", DataType: DataTypeOctets},                    // RFC5904
	{ID: 143, Name: "PKM-Auth-Key", DataType: DataTypeOctets},                         // RFC5904
	{ID: 144, Name: "DS-Lite-Tunnel-Name", DataType: DataTypeOctets},                  // RFC6519
	{ID: 145, Name: "Mobile-Node-Identifier", DataType: DataTypeOctets},               // RFC6572
	{ID: 146, Name: "Service-Selection", DataType: DataTypeString},                    // RFC6572
	{ID: 147, Name: "PMIP6-Home-LMA-IPv6-Address", DataType: DataTypeIPv6Addr},        // RFC6572
	{ID: 148, Name: "PMIP6-Visited-LMA-IPv6-Address", DataType: DataTypeIPv6Addr},     // RFC6572
	{ID: 149, Name: "PMIP6-Home-LMA-IPv4-Address", DataType: DataTypeIPAddr},          // RFC6572
	{ID: 150, Name: "PMIP6-Visited-LMA-IPv4-Address", DataType: DataTypeIPAddr},       // RFC6572
	{ID: 151, Name: "PMIP6-Home-HN-Prefix", DataType: DataTypeIPv6Prefix},             // RFC6572
	{ID: 152, Name: "PMIP6-Visited-HN-Prefix", DataType: DataTypeIPv6Prefix},          // RFC6572
	{ID: 153, Name: "PMIP6-Home-Interface-ID", DataType: DataTypeIfID},                // RFC6572
	{ID: 154, Name: "PMIP6-Visited-Interface-ID", DataType: DataTypeIfID},             // RFC6572
	{ID: 155, Name: "PMIP6-Home-IPv4-HoA", DataType: DataTypeOctets},                  // RFC6572
	{ID: 156, Name: "PMIP6-Visited-IPv4-HoA", DataType: DataTypeOctets},               // RFC6572
	{ID: 157, Name: "PMIP6-Home-DHCP4-Server-Address", DataType: DataTypeIPAddr},      // RFC6572
	{ID: 158, Name: "PMIP6-Visited-DHCP4-Server-Address", DataType: DataTypeIPAddr},   // RFC6572
	{ID: 159, Name: "PMIP6-Home-DHCP6-Server-Address", DataType: DataTypeIPv6Addr},    // RFC6572
	{ID: 160, Name: "PMIP6-Visited-DHCP6-Server-Address", DataType: DataTypeIPv6Addr}, // RFC6572
	{ID: 161, Name: "PMIP6-Home-IPv4-Gateway", DataType: DataTypeIPAddr},              // RFC6572
	{ID: 162, Name: "PMIP6-Visited-IPv4-Gateway", DataType: DataTypeIPAddr},           // RFC6572
	{ // RFC6677
		ID:       163,
		Name:     "EAP-Lower-Layer",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Wired-IEEE-802.1X":      1, // RFC6677
			"IEEE-802.1X-No-Preauth": 2, // RFC6677
			"IEEE-802.1X-Preauth":    3, // RFC6677
			"IEEE-802.16e":           4, // RFC6677
			"IKEv2":                  5, // RFC6677
			"PPP":                    6, // RFC6677
			"PANA-No-Preauth":        7, // RFC6677
			"GSS-API":                8, // RFC6677
			"PANA-Preauth":           9, // RFC6677
		},
	},
	{ID: 164, Name: "GSS-Acceptor-Service-Name", DataType: DataTypeString},      // RFC7055
	{ID: 165, Name: "GSS-Acceptor-Host-Name", DataType: DataTypeString},         // RFC7055
	{ID: 166, Name: "GSS-Acceptor-Service-Specifics", DataType: DataTypeString}, // RFC7055
	{ID: 167, Name: "GSS-Acceptor-Realm-Name", DataType: DataTypeString},        // RFC7055
	{ID: 168, Name: "Framed-IPv6-Address", DataType: DataTypeIPv6Addr},          // RFC6911
	{ID: 169, Name: "DNS-Server-IPv6-Address", DataType: DataTypeIPv6Addr},      // RFC6911
	{ID: 170, Name: "Route-IPv6-Information", DataType: DataTypeIPv6Prefix},     // RFC6911
	{ID: 171, Name: "Delegated-IPv6-Prefix-Pool", DataType: DataTypeString},     // RFC6911
	{ID: 172, Name: "Stateful-IPv6-Address-Pool", DataType: DataTypeString},     // RFC6911
	{ID: 173, Name: "IPv6-6rd-Configuration", DataType: DataTypeTLV},            // RFC6930
	{ID: 174, Name: "Allowed-Called-Station-Id", DataType: DataTypeString},      // RFC7268
	{ID: 175, Name: "EAP-Peer-Id", DataType: DataTypeOctets},                    // RFC7268
	{ID: 176, Name: "EAP-Server-Id", DataType: DataTypeOctets},                  // RFC7268
	{ID: 177, Name: "Mobility-Domain-Id", DataType: DataTypeInteger},            // RFC7268
	{ID: 178, Name: "Preauth-Timeout", DataType: DataTypeInteger},               // RFC7268
	{ID: 179, Name: "Network-Id-Name", DataType: DataTypeOctets},                // RFC7268
	{ID: 180, Name: "EAPoL-Announcement", DataType: DataTypeOctets},             // RFC7268
	{ID: 181, Name: "WLAN-HESSID", DataType: DataTypeString},                    // RFC7268
	{ID: 182, Name: "WLAN-Venue-Info", DataType: DataTypeInteger},               // RFC7268
	{ID: 183, Name: "WLAN-Venue-Language", DataType: DataTypeOctets},            // RFC7268
	{ID: 184, Name: "WLAN-Venue-Name", DataType: DataTypeString},                // RFC7268
	{ID: 185, Name: "WLAN-Reason-Code", DataType: DataTypeInteger},              // RFC7268
	{ID: 186, Name: "WLAN-Pairwise-Cipher", DataType: DataTypeInteger},          // RFC7268
	{ID: 187, Name: "WLAN-Group-Cipher", DataType: DataTypeInteger},             // RFC7268
	{ID: 188, Name: "WLAN-AKM-Suite", DataType: DataTypeInteger},                // RFC7268
	{ID: 189, Name: "WLAN-Group-Mgmt-Cipher", DataType: DataTypeInteger},        // RFC7268
	{ID: 190, Name: "WLAN-RF-Band", DataType: DataTypeInteger},                  // RFC7268
	{ID: 241, Name: "Extended-Attribute-1", DataType: DataTypeOctets},           // RFC6929
	{ID: 242, Name: "Extended-Attribute-2", DataType: DataTypeOctets},           // RFC6929
	{ID: 243, Name: "Extended-Attribute-3", DataType: DataTypeOctets},           // RFC6929
	{ID: 244, Name: "Extended-Attribute-4", DataType: DataTypeOctets},           // RFC6929
	{ID: 245, Name: "Extended-Attribute-5", DataType: DataTypeOctets},           // RFC6929
	{ID: 246, Name: "Extended-Attribute-6", DataType: DataTypeOctets},           // RFC6929
}
