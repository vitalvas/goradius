package goradius

// StandardRFCAttributes contains all RFC standard attributes
var StandardRFCAttributes = []*AttributeDefinition{
	{ID: 1, Name: "user-name", DataType: DataTypeString},                                         // RFC2865
	{ID: 2, Name: "user-password", DataType: DataTypeString, Encryption: EncryptionUserPassword}, // RFC2865
	{ID: 3, Name: "chap-password", DataType: DataTypeOctets},                                     // RFC2865
	{ID: 4, Name: "nas-ip-address", DataType: DataTypeIPAddr},                                    // RFC2865
	{ID: 5, Name: "nas-port", DataType: DataTypeInteger},                                         // RFC2865
	{ // RFC2865
		ID:       6,
		Name:     "service-type",
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
			"framed-management":       18, // RFC2865
		},
	},
	{ // RFC2865
		ID:       7,
		Name:     "framed-protocol",
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
	{ID: 8, Name: "framed-ip-address", DataType: DataTypeIPAddr}, // RFC2865
	{ID: 9, Name: "framed-ip-netmask", DataType: DataTypeIPAddr}, // RFC2865
	{ // RFC2865
		ID:       10,
		Name:     "framed-routing",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"None":             0, // RFC2865
			"Broadcast":        1, // RFC2865
			"Listen":           2, // RFC2865
			"Broadcast-Listen": 3, // RFC2865
		},
	},
	{ID: 11, Name: "filter-id", DataType: DataTypeString},   // RFC2865
	{ID: 12, Name: "framed-mtu", DataType: DataTypeInteger}, // RFC2865
	{ // RFC2865
		ID:       13,
		Name:     "framed-compression",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"None":                   0, // RFC2865
			"Van-Jacobson-TCP-IP":    1, // RFC2865
			"IPX-Header-Compression": 2, // RFC2865
			"Stac-LZS":               3, // RFC2865
		},
	},
	{ID: 14, Name: "login-ip-host", DataType: DataTypeIPAddr}, // RFC2865
	{ // RFC2865
		ID:       15,
		Name:     "login-service",
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
		Name:     "login-tcp-port",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Telnet": 23,  // RFC2865
			"Rlogin": 513, // RFC2865
			"Rsh":    514, // RFC2865
		},
	},
	{ID: 18, Name: "reply-message", DataType: DataTypeString},      // RFC2865
	{ID: 19, Name: "callback-number", DataType: DataTypeString},    // RFC2865
	{ID: 20, Name: "callback-id", DataType: DataTypeString},        // RFC2865
	{ID: 22, Name: "framed-route", DataType: DataTypeString},       // RFC2865
	{ID: 23, Name: "framed-ipx-network", DataType: DataTypeIPAddr}, // RFC2865
	{ID: 24, Name: "state", DataType: DataTypeOctets},              // RFC2865
	{ID: 25, Name: "class", DataType: DataTypeOctets},              // RFC2865
	{ID: 26, Name: "vendor-specific", DataType: DataTypeOctets},    // RFC2865
	{ID: 27, Name: "session-timeout", DataType: DataTypeInteger},   // RFC2865
	{ID: 28, Name: "idle-timeout", DataType: DataTypeInteger},      // RFC2865
	{ // RFC2865
		ID:       29,
		Name:     "termination-action",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Default":        0, // RFC2865
			"RADIUS-Request": 1, // RFC2865
		},
	},
	{ID: 30, Name: "called-station-id", DataType: DataTypeString},         // RFC2865
	{ID: 31, Name: "calling-station-id", DataType: DataTypeString},        // RFC2865
	{ID: 32, Name: "nas-identifier", DataType: DataTypeString},            // RFC2865
	{ID: 33, Name: "proxy-state", DataType: DataTypeOctets},               // RFC2865
	{ID: 34, Name: "login-lat-service", DataType: DataTypeString},         // RFC2865
	{ID: 35, Name: "login-lat-node", DataType: DataTypeString},            // RFC2865
	{ID: 36, Name: "login-lat-group", DataType: DataTypeOctets},           // RFC2865
	{ID: 37, Name: "framed-appletalk-link", DataType: DataTypeInteger},    // RFC2865
	{ID: 38, Name: "framed-appletalk-network", DataType: DataTypeInteger}, // RFC2865
	{ID: 39, Name: "framed-appletalk-zone", DataType: DataTypeString},     // RFC2865
	{ // RFC2866
		ID:       40,
		Name:     "acct-status-type",
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
	{ID: 41, Name: "acct-delay-time", DataType: DataTypeInteger},    // RFC2866
	{ID: 42, Name: "acct-input-octets", DataType: DataTypeInteger},  // RFC2866
	{ID: 43, Name: "acct-output-octets", DataType: DataTypeInteger}, // RFC2866
	{ID: 44, Name: "acct-session-id", DataType: DataTypeString},     // RFC2866
	{ // RFC2866
		ID:       45,
		Name:     "acct-authentic",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"RADIUS":   1, // RFC2866
			"Local":    2, // RFC2866
			"Remote":   3, // RFC2866
			"Diameter": 4, // RFC2866
		},
	},
	{ID: 46, Name: "acct-session-time", DataType: DataTypeInteger},   // RFC2866
	{ID: 47, Name: "acct-input-packets", DataType: DataTypeInteger},  // RFC2866
	{ID: 48, Name: "acct-output-packets", DataType: DataTypeInteger}, // RFC2866
	{ // RFC2866
		ID:       49,
		Name:     "acct-terminate-cause",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"User-Request":             1,  // RFC2866
			"Lost-Carrier":             2,  // RFC2866
			"Lost-Service":             3,  // RFC2866
			"idle-timeout":             4,  // RFC2866
			"session-timeout":          5,  // RFC2866
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
	{ID: 50, Name: "acct-multi-session-id", DataType: DataTypeString},  // RFC2866
	{ID: 51, Name: "acct-link-count", DataType: DataTypeInteger},       // RFC2866
	{ID: 52, Name: "acct-input-gigawords", DataType: DataTypeInteger},  // RFC2869
	{ID: 53, Name: "acct-output-gigawords", DataType: DataTypeInteger}, // RFC2869
	{ID: 55, Name: "event-timestamp", DataType: DataTypeDate},          // RFC2869
	{ID: 56, Name: "egress-vlanid", DataType: DataTypeInteger},         // RFC4675
	{ // RFC4675
		ID:       57,
		Name:     "ingress-filters",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Enabled":  1, // RFC4675
			"Disabled": 2, // RFC4675
		},
	},
	{ID: 58, Name: "egress-vlan-name", DataType: DataTypeString},    // RFC4675
	{ID: 59, Name: "user-priority-table", DataType: DataTypeOctets}, // RFC4675
	{ID: 60, Name: "chap-challenge", DataType: DataTypeOctets},      // RFC2865
	{ // RFC2865
		ID:       61,
		Name:     "nas-port-type",
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
	{ID: 62, Name: "port-limit", DataType: DataTypeInteger},    // RFC2865
	{ID: 63, Name: "login-lat-port", DataType: DataTypeString}, // RFC2865
	{ // RFC2868
		ID:       64,
		Name:     "tunnel-type",
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
		Name:     "tunnel-medium-type",
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
	{ID: 66, Name: "tunnel-client-endpoint", DataType: DataTypeString, HasTag: true},                                // RFC2868
	{ID: 67, Name: "tunnel-server-endpoint", DataType: DataTypeString, HasTag: true},                                // RFC2868
	{ID: 68, Name: "acct-tunnel-connection", DataType: DataTypeString},                                              // RFC2867
	{ID: 69, Name: "tunnel-password", DataType: DataTypeString, HasTag: true, Encryption: EncryptionTunnelPassword}, // RFC2868
	{ID: 70, Name: "arap-password", DataType: DataTypeOctets},                                                       // RFC2869
	{ID: 71, Name: "arap-features", DataType: DataTypeOctets},                                                       // RFC2869
	{ // RFC2869
		ID:       72,
		Name:     "arap-zone-access",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Default-Zone":          1, // RFC2869
			"Zone-Filter-Inclusive": 2, // RFC2869
			"Zone-Filter-Exclusive": 4, // RFC2869
		},
	},
	{ID: 73, Name: "arap-security", DataType: DataTypeInteger},     // RFC2869
	{ID: 74, Name: "arap-security-data", DataType: DataTypeString}, // RFC2869
	{ID: 75, Name: "password-retry", DataType: DataTypeInteger},    // RFC2869
	{ // RFC2869
		ID:       76,
		Name:     "prompt",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"No-Echo": 0, // RFC2869
			"Echo":    1, // RFC2869
		},
	},
	{ID: 77, Name: "connect-info", DataType: DataTypeString},                          // RFC2869
	{ID: 78, Name: "configuration-token", DataType: DataTypeString},                   // RFC2869
	{ID: 79, Name: "eap-message", DataType: DataTypeOctets},                           // RFC2869
	{ID: 80, Name: "message-authenticator", DataType: DataTypeOctets},                 // RFC2869
	{ID: 81, Name: "tunnel-private-group-id", DataType: DataTypeString, HasTag: true}, // RFC2868
	{ID: 82, Name: "tunnel-assignment-id", DataType: DataTypeString, HasTag: true},    // RFC2868
	{ID: 83, Name: "tunnel-preference", DataType: DataTypeInteger, HasTag: true},      // RFC2868
	{ID: 84, Name: "arap-challenge-response", DataType: DataTypeOctets},               // RFC2869
	{ID: 85, Name: "acct-interim-interval", DataType: DataTypeInteger},                // RFC2869
	{ID: 86, Name: "acct-tunnel-packets-lost", DataType: DataTypeInteger},             // RFC2867
	{ID: 87, Name: "nas-port-id", DataType: DataTypeString},                           // RFC2869
	{ID: 88, Name: "framed-pool", DataType: DataTypeString},                           // RFC2869
	{ID: 89, Name: "chargeable-user-identity", DataType: DataTypeOctets},              // RFC4372
	{ID: 90, Name: "tunnel-client-auth-id", DataType: DataTypeString, HasTag: true},   // RFC2868
	{ID: 91, Name: "tunnel-server-auth-id", DataType: DataTypeString, HasTag: true},   // RFC2868
	{ID: 92, Name: "nas-filter-rule", DataType: DataTypeString},                       // RFC4849
	{ID: 94, Name: "originating-line-info", DataType: DataTypeOctets},                 // RFC7155
	{ID: 95, Name: "nas-ipv6-address", DataType: DataTypeIPv6Addr},                    // RFC3162
	{ID: 96, Name: "framed-interface-id", DataType: DataTypeIfID},                     // RFC3162
	{ID: 97, Name: "framed-ipv6-prefix", DataType: DataTypeIPv6Prefix},                // RFC3162
	{ID: 98, Name: "login-ipv6-host", DataType: DataTypeIPv6Addr},                     // RFC3162
	{ID: 99, Name: "framed-ipv6-route", DataType: DataTypeString},                     // RFC3162
	{ID: 100, Name: "framed-ipv6-pool", DataType: DataTypeString},                     // RFC3162
	{ // RFC3576
		ID:       101,
		Name:     "error-cause",
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
	{ID: 102, Name: "eap-key-name", DataType: DataTypeOctets},                   // RFC4072
	{ID: 103, Name: "digest-response", DataType: DataTypeString},                // RFC5090
	{ID: 104, Name: "digest-realm", DataType: DataTypeString},                   // RFC5090
	{ID: 105, Name: "digest-nonce", DataType: DataTypeString},                   // RFC5090
	{ID: 106, Name: "digest-response-auth", DataType: DataTypeString},           // RFC5090
	{ID: 107, Name: "digest-nextnonce", DataType: DataTypeString},               // RFC5090
	{ID: 108, Name: "digest-method", DataType: DataTypeString},                  // RFC5090
	{ID: 109, Name: "digest-uri", DataType: DataTypeString},                     // RFC5090
	{ID: 110, Name: "digest-qop", DataType: DataTypeString},                     // RFC5090
	{ID: 111, Name: "digest-algorithm", DataType: DataTypeString},               // RFC5090
	{ID: 112, Name: "digest-entity-body-hash", DataType: DataTypeString},        // RFC5090
	{ID: 113, Name: "digest-cnonce", DataType: DataTypeString},                  // RFC5090
	{ID: 114, Name: "digest-nonce-count", DataType: DataTypeString},             // RFC5090
	{ID: 115, Name: "digest-username", DataType: DataTypeString},                // RFC5090
	{ID: 116, Name: "digest-opaque", DataType: DataTypeString},                  // RFC5090
	{ID: 117, Name: "digest-auth-param", DataType: DataTypeString},              // RFC5090
	{ID: 118, Name: "digest-aka-auts", DataType: DataTypeString},                // RFC5090
	{ID: 119, Name: "digest-domain", DataType: DataTypeString},                  // RFC5090
	{ID: 120, Name: "digest-stale", DataType: DataTypeString},                   // RFC5090
	{ID: 121, Name: "digest-ha1", DataType: DataTypeString},                     // RFC5090
	{ID: 122, Name: "sip-aor", DataType: DataTypeString},                        // RFC5090
	{ID: 123, Name: "delegated-ipv6-prefix", DataType: DataTypeIPv6Prefix},      // RFC4818
	{ID: 124, Name: "mip6-feature-vector", DataType: DataTypeOctets},            // RFC5447
	{ID: 125, Name: "mip6-home-link-prefix", DataType: DataTypeOctets},          // RFC5447
	{ID: 126, Name: "operator-name", DataType: DataTypeString},                  // RFC5580
	{ID: 127, Name: "location-information", DataType: DataTypeOctets},           // RFC5580
	{ID: 128, Name: "location-data", DataType: DataTypeOctets},                  // RFC5580
	{ID: 129, Name: "basic-location-policy-rules", DataType: DataTypeOctets},    // RFC5580
	{ID: 130, Name: "extended-location-policy-rules", DataType: DataTypeString}, // RFC5580
	{ // RFC5580
		ID:       131,
		Name:     "location-capable",
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
		Name:     "requested-location-info",
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
		Name:     "framed-management",
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
		Name:     "management-transport-protection",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"No-Protection":                        1, // RFC5607
			"Integrity-Protection":                 2, // RFC5607
			"Integrity-Confidentiality-Protection": 3, // RFC5607
		},
	},
	{ID: 135, Name: "management-policy-id", DataType: DataTypeString},                 // RFC5607
	{ID: 136, Name: "management-privilege-level", DataType: DataTypeInteger},          // RFC5607
	{ID: 137, Name: "pkm-ss-cert", DataType: DataTypeOctets},                          // RFC5904
	{ID: 138, Name: "pkm-ca-cert", DataType: DataTypeOctets},                          // RFC5904
	{ID: 139, Name: "pkm-config-settings", DataType: DataTypeOctets},                  // RFC5904
	{ID: 140, Name: "pkm-cryptosuite-list", DataType: DataTypeOctets},                 // RFC5904
	{ID: 141, Name: "pkm-said", DataType: DataTypeInteger},                            // RFC5904
	{ID: 142, Name: "pkm-sa-descriptor", DataType: DataTypeOctets},                    // RFC5904
	{ID: 143, Name: "pkm-auth-key", DataType: DataTypeOctets},                         // RFC5904
	{ID: 144, Name: "ds-lite-tunnel-name", DataType: DataTypeOctets},                  // RFC6519
	{ID: 145, Name: "mobile-node-identifier", DataType: DataTypeOctets},               // RFC6572
	{ID: 146, Name: "service-selection", DataType: DataTypeString},                    // RFC6572
	{ID: 147, Name: "pmip6-home-lma-ipv6-address", DataType: DataTypeIPv6Addr},        // RFC6572
	{ID: 148, Name: "pmip6-visited-lma-ipv6-address", DataType: DataTypeIPv6Addr},     // RFC6572
	{ID: 149, Name: "pmip6-home-lma-ipv4-address", DataType: DataTypeIPAddr},          // RFC6572
	{ID: 150, Name: "pmip6-visited-lma-ipv4-address", DataType: DataTypeIPAddr},       // RFC6572
	{ID: 151, Name: "pmip6-home-hn-prefix", DataType: DataTypeIPv6Prefix},             // RFC6572
	{ID: 152, Name: "pmip6-visited-hn-prefix", DataType: DataTypeIPv6Prefix},          // RFC6572
	{ID: 153, Name: "pmip6-home-interface-id", DataType: DataTypeIfID},                // RFC6572
	{ID: 154, Name: "pmip6-visited-interface-id", DataType: DataTypeIfID},             // RFC6572
	{ID: 155, Name: "pmip6-home-ipv4-hoa", DataType: DataTypeOctets},                  // RFC6572
	{ID: 156, Name: "pmip6-visited-ipv4-hoa", DataType: DataTypeOctets},               // RFC6572
	{ID: 157, Name: "pmip6-home-dhcp4-server-address", DataType: DataTypeIPAddr},      // RFC6572
	{ID: 158, Name: "pmip6-visited-dhcp4-server-address", DataType: DataTypeIPAddr},   // RFC6572
	{ID: 159, Name: "pmip6-home-dhcp6-server-address", DataType: DataTypeIPv6Addr},    // RFC6572
	{ID: 160, Name: "pmip6-visited-dhcp6-server-address", DataType: DataTypeIPv6Addr}, // RFC6572
	{ID: 161, Name: "pmip6-home-ipv4-gateway", DataType: DataTypeIPAddr},              // RFC6572
	{ID: 162, Name: "pmip6-visited-ipv4-gateway", DataType: DataTypeIPAddr},           // RFC6572
	{ // RFC6677
		ID:       163,
		Name:     "eap-lower-layer",
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
	{ID: 164, Name: "gss-acceptor-service-name", DataType: DataTypeString},      // RFC7055
	{ID: 165, Name: "gss-acceptor-host-name", DataType: DataTypeString},         // RFC7055
	{ID: 166, Name: "gss-acceptor-service-specifics", DataType: DataTypeString}, // RFC7055
	{ID: 167, Name: "gss-acceptor-realm-name", DataType: DataTypeString},        // RFC7055
	{ID: 168, Name: "framed-ipv6-address", DataType: DataTypeIPv6Addr},          // RFC6911
	{ID: 169, Name: "dns-server-ipv6-address", DataType: DataTypeIPv6Addr},      // RFC6911
	{ID: 170, Name: "route-ipv6-information", DataType: DataTypeIPv6Prefix},     // RFC6911
	{ID: 171, Name: "delegated-ipv6-prefix-pool", DataType: DataTypeString},     // RFC6911
	{ID: 172, Name: "stateful-ipv6-address-pool", DataType: DataTypeString},     // RFC6911
	{ID: 173, Name: "ipv6-6rd-configuration", DataType: DataTypeTLV},            // RFC6930
	{ID: 174, Name: "allowed-called-station-id", DataType: DataTypeString},      // RFC7268
	{ID: 175, Name: "eap-peer-id", DataType: DataTypeOctets},                    // RFC7268
	{ID: 176, Name: "eap-server-id", DataType: DataTypeOctets},                  // RFC7268
	{ID: 177, Name: "mobility-domain-id", DataType: DataTypeInteger},            // RFC7268
	{ID: 178, Name: "preauth-timeout", DataType: DataTypeInteger},               // RFC7268
	{ID: 179, Name: "network-id-name", DataType: DataTypeOctets},                // RFC7268
	{ID: 180, Name: "eapol-announcement", DataType: DataTypeOctets},             // RFC7268
	{ID: 181, Name: "wlan-hessid", DataType: DataTypeString},                    // RFC7268
	{ID: 182, Name: "wlan-venue-info", DataType: DataTypeInteger},               // RFC7268
	{ID: 183, Name: "wlan-venue-language", DataType: DataTypeOctets},            // RFC7268
	{ID: 184, Name: "wlan-venue-name", DataType: DataTypeString},                // RFC7268
	{ID: 185, Name: "wlan-reason-code", DataType: DataTypeInteger},              // RFC7268
	{ID: 186, Name: "wlan-pairwise-cipher", DataType: DataTypeInteger},          // RFC7268
	{ID: 187, Name: "wlan-group-cipher", DataType: DataTypeInteger},             // RFC7268
	{ID: 188, Name: "wlan-akm-suite", DataType: DataTypeInteger},                // RFC7268
	{ID: 189, Name: "wlan-group-mgmt-cipher", DataType: DataTypeInteger},        // RFC7268
	{ID: 190, Name: "wlan-rf-band", DataType: DataTypeInteger},                  // RFC7268
	{ID: 241, Name: "extended-attribute-1", DataType: DataTypeOctets},           // RFC6929
	{ID: 242, Name: "extended-attribute-2", DataType: DataTypeOctets},           // RFC6929
	{ID: 243, Name: "extended-attribute-3", DataType: DataTypeOctets},           // RFC6929
	{ID: 244, Name: "extended-attribute-4", DataType: DataTypeOctets},           // RFC6929
	{ID: 245, Name: "extended-attribute-5", DataType: DataTypeOctets},           // RFC6929
	{ID: 246, Name: "extended-attribute-6", DataType: DataTypeOctets},           // RFC6929
}
