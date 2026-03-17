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
			"login-user":              1,  // RFC2865
			"framed-user":             2,  // RFC2865
			"callback-login-user":     3,  // RFC2865
			"callback-framed-user":    4,  // RFC2865
			"outbound-user":           5,  // RFC2865
			"administrative-user":     6,  // RFC2865
			"nas-prompt-user":         7,  // RFC2865
			"authenticate-only":       8,  // RFC2865
			"callback-nas-prompt":     9,  // RFC2865
			"call-check":              10, // RFC2865
			"callback-administrative": 11, // RFC2865
			"authorize-only":          17, // RFC2865
			"framed-management":       18, // RFC2865
		},
	},
	{ // RFC2865
		ID:       7,
		Name:     "framed-protocol",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"ppp":               1, // RFC2865
			"slip":              2, // RFC2865
			"arap":              3, // RFC2865
			"gandalf-slml":      4, // RFC2865
			"xylogics-ipx-slip": 5, // RFC2865
			"x.75-synchronous":  6, // RFC2865
		},
	},
	{ID: 8, Name: "framed-ip-address", DataType: DataTypeIPAddr}, // RFC2865
	{ID: 9, Name: "framed-ip-netmask", DataType: DataTypeIPAddr}, // RFC2865
	{ // RFC2865
		ID:       10,
		Name:     "framed-routing",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"none":             0, // RFC2865
			"broadcast":        1, // RFC2865
			"listen":           2, // RFC2865
			"broadcast-listen": 3, // RFC2865
		},
	},
	{ID: 11, Name: "filter-id", DataType: DataTypeString},   // RFC2865
	{ID: 12, Name: "framed-mtu", DataType: DataTypeInteger}, // RFC2865
	{ // RFC2865
		ID:       13,
		Name:     "framed-compression",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"none":                   0, // RFC2865
			"van-jacobson-tcp-ip":    1, // RFC2865
			"ipx-header-compression": 2, // RFC2865
			"stac-lzs":               3, // RFC2865
		},
	},
	{ID: 14, Name: "login-ip-host", DataType: DataTypeIPAddr}, // RFC2865
	{ // RFC2865
		ID:       15,
		Name:     "login-service",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"telnet":          0, // RFC2865
			"rlogin":          1, // RFC2865
			"tcp-clear":       2, // RFC2865
			"portmaster":      3, // RFC2865
			"lat":             4, // RFC2865
			"x25-pad":         5, // RFC2865
			"x25-t3pos":       6, // RFC2865
			"tcp-clear-quiet": 8, // RFC2865
		},
	},
	{ // RFC2865
		ID:       16,
		Name:     "login-tcp-port",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"telnet": 23,  // RFC2865
			"rlogin": 513, // RFC2865
			"rsh":    514, // RFC2865
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
			"default":        0, // RFC2865
			"radius-request": 1, // RFC2865
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
			"start":              1,  // RFC2866
			"stop":               2,  // RFC2866
			"alive":              3,  // RFC2866
			"interim-update":     3,  // RFC2866
			"accounting-on":      7,  // RFC2866
			"accounting-off":     8,  // RFC2866
			"tunnel-start":       9,  // RFC2866
			"tunnel-stop":        10, // RFC2866
			"tunnel-reject":      11, // RFC2866
			"tunnel-link-start":  12, // RFC2866
			"tunnel-link-stop":   13, // RFC2866
			"tunnel-link-reject": 14, // RFC2866
			"failed":             15, // RFC2866
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
			"radius":   1, // RFC2866
			"local":    2, // RFC2866
			"remote":   3, // RFC2866
			"diameter": 4, // RFC2866
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
			"user-request":             1,  // RFC2866
			"lost-carrier":             2,  // RFC2866
			"lost-service":             3,  // RFC2866
			"idle-timeout":             4,  // RFC2866
			"session-timeout":          5,  // RFC2866
			"admin-reset":              6,  // RFC2866
			"admin-reboot":             7,  // RFC2866
			"port-error":               8,  // RFC2866
			"nas-error":                9,  // RFC2866
			"nas-request":              10, // RFC2866
			"nas-reboot":               11, // RFC2866
			"port-unneeded":            12, // RFC2866
			"port-preempted":           13, // RFC2866
			"port-suspended":           14, // RFC2866
			"service-unavailable":      15, // RFC2866
			"callback":                 16, // RFC2866
			"user-error":               17, // RFC2866
			"host-request":             18, // RFC2866
			"supplicant-restart":       19, // RFC2866
			"reauthentication-failure": 20, // RFC2866
			"port-reinit":              21, // RFC2866
			"port-disabled":            22, // RFC2866
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
			"enabled":  1, // RFC4675
			"disabled": 2, // RFC4675
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
			"async":              0,  // RFC2865
			"sync":               1,  // RFC2865
			"isdn":               2,  // RFC2865
			"isdn-v120":          3,  // RFC2865
			"isdn-v110":          4,  // RFC2865
			"virtual":            5,  // RFC2865
			"piafs":              6,  // RFC2865
			"hdlc-clear-channel": 7,  // RFC2865
			"x.25":               8,  // RFC2865
			"x.75":               9,  // RFC2865
			"g.3-fax":            10, // RFC2865
			"sdsl":               11, // RFC2865
			"adsl-cap":           12, // RFC2865
			"adsl-dmt":           13, // RFC2865
			"idsl":               14, // RFC2865
			"ethernet":           15, // RFC2865
			"xdsl":               16, // RFC2865
			"cable":              17, // RFC2865
			"wireless-other":     18, // RFC2865
			"wireless-802.11":    19, // RFC2865
			"token-ring":         20, // RFC2865
			"fddi":               21, // RFC2865
			"pppoa":              30, // RFC2865
			"pppoeoa":            31, // RFC2865
			"pppoeoe":            32, // RFC2865
			"pppoeovlan":         33, // RFC2865
			"pppoeoqinq":         34, // RFC2865
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
			"pptp":     1,  // RFC2868
			"l2f":      2,  // RFC2868
			"l2tp":     3,  // RFC2868
			"atmp":     4,  // RFC2868
			"vtp":      5,  // RFC2868
			"ah":       6,  // RFC2868
			"ip":       7,  // RFC2868
			"min-ip":   8,  // RFC2868
			"esp":      9,  // RFC2868
			"gre":      10, // RFC2868
			"dvs":      11, // RFC2868
			"ip-in-ip": 12, // RFC2868
			"vlan":     13, // RFC2868
		},
	},
	{ // RFC2868
		ID:       65,
		Name:     "tunnel-medium-type",
		DataType: DataTypeInteger,
		HasTag:   true,
		Values: map[string]uint32{
			"ip":           1,  // RFC2868
			"ipv4":         1,  // RFC2868
			"ipv6":         2,  // RFC2868
			"nsap":         3,  // RFC2868
			"hdlc":         4,  // RFC2868
			"bbn-1822":     5,  // RFC2868
			"ieee-802":     6,  // RFC2868
			"e.163":        7,  // RFC2868
			"e.164":        8,  // RFC2868
			"f.69":         9,  // RFC2868
			"x.121":        10, // RFC2868
			"ipx":          11, // RFC2868
			"appletalk":    12, // RFC2868
			"decnet-iv":    13, // RFC2868
			"banyan-vines": 14, // RFC2868
			"e.164-nsap":   15, // RFC2868
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
			"default-zone":          1, // RFC2869
			"zone-filter-inclusive": 2, // RFC2869
			"zone-filter-exclusive": 4, // RFC2869
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
			"no-echo": 0, // RFC2869
			"echo":    1, // RFC2869
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
			"residual-context-removed":               201, // RFC3576
			"invalid-eap-packet":                     202, // RFC3576
			"unsupported-attribute":                  401, // RFC3576
			"missing-attribute":                      402, // RFC3576
			"nas-identification-mismatch":            403, // RFC3576
			"invalid-request":                        404, // RFC3576
			"unsupported-service":                    405, // RFC3576
			"unsupported-extension":                  406, // RFC3576
			"invalid-attribute-value":                407, // RFC3576
			"administratively-prohibited":            501, // RFC3576
			"proxy-request-not-routable":             502, // RFC3576
			"session-context-not-found":              503, // RFC3576
			"session-context-not-removable":          504, // RFC3576
			"proxy-processing-error":                 505, // RFC3576
			"resources-unavailable":                  506, // RFC3576
			"request-initiated":                      507, // RFC3576
			"multiple-session-selection-unsupported": 508, // RFC3576
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
			"civic-location": 1, // RFC5580
			"geo-location":   2, // RFC5580
			"users-location": 4, // RFC5580
			"nas-location":   8, // RFC5580
		},
	},
	{ // RFC5580
		ID:       132,
		Name:     "requested-location-info",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"civic-location":  1,  // RFC5580
			"geo-location":    2,  // RFC5580
			"users-location":  4,  // RFC5580
			"nas-location":    8,  // RFC5580
			"future-requests": 16, // RFC5580
			"none":            32, // RFC5580
		},
	},
	{ // RFC5607
		ID:       133,
		Name:     "framed-management",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"snmp":      1, // RFC5607
			"web-based": 2, // RFC5607
			"netconf":   3, // RFC5607
			"ftp":       4, // RFC5607
			"tftp":      5, // RFC5607
			"sftp":      6, // RFC5607
			"rcp":       7, // RFC5607
			"scp":       8, // RFC5607
		},
	},
	{ // RFC5607
		ID:       134,
		Name:     "management-transport-protection",
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"no-protection":                        1, // RFC5607
			"integrity-protection":                 2, // RFC5607
			"integrity-confidentiality-protection": 3, // RFC5607
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
			"wired-ieee-802.1x":      1, // RFC6677
			"ieee-802.1x-no-preauth": 2, // RFC6677
			"ieee-802.1x-preauth":    3, // RFC6677
			"ieee-802.16e":           4, // RFC6677
			"ikev2":                  5, // RFC6677
			"ppp":                    6, // RFC6677
			"pana-no-preauth":        7, // RFC6677
			"gss-api":                8, // RFC6677
			"pana-preauth":           9, // RFC6677
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
