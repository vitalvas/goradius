package goradius

// ZTEVendorDefinition defines the ZTE vendor (ID 3902) used by ZXR10 BRAS and
// M6000 platforms. Ported from FreeRADIUS dictionary.zte (master revision,
// which fixes client-dns-pri/sec to string: ZXR10 sends the DNS address as
// text, while the 3.2.x dictionary had ipaddr). The QoS attributes were
// derived by FreeRADIUS from a ZTE bearer products PDF that is no longer
// online; no official per-packet placement documentation is available, so all
// attributes stay unrestricted. The rate-bust spelling on IDs 191 and 192
// follows the official dictionary.
var ZTEVendorDefinition = &VendorDefinition{
	ID:   3902,
	Name: "zte",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "zte-client-dns-pri", DataType: DataTypeString},
		{ID: 2, Name: "zte-client-dns-sec", DataType: DataTypeString},
		{ID: 4, Name: "zte-context-name", DataType: DataTypeInteger},
		{ID: 21, Name: "zte-tunnel-max-sessions", DataType: DataTypeInteger},
		{ID: 22, Name: "zte-tunnel-max-tunnels", DataType: DataTypeInteger},
		{ID: 24, Name: "zte-tunnel-window", DataType: DataTypeInteger},
		{ID: 25, Name: "zte-tunnel-retransmit", DataType: DataTypeInteger},
		{ID: 26, Name: "zte-tunnel-cmd-timeout", DataType: DataTypeInteger},
		{ID: 27, Name: "zte-pppoe-url", DataType: DataTypeString},
		{ID: 28, Name: "zte-pppoe-motm", DataType: DataTypeString},
		{ID: 31, Name: "zte-tunnel-algorithm", DataType: DataTypeInteger},
		{ID: 32, Name: "zte-tunnel-deadtime", DataType: DataTypeInteger},
		{ID: 33, Name: "zte-mcast-send", DataType: DataTypeInteger},
		{ID: 34, Name: "zte-mcast-receive", DataType: DataTypeInteger},
		{ID: 35, Name: "zte-mcast-maxgroups", DataType: DataTypeInteger},
		{ID: 74, Name: "zte-access-type", DataType: DataTypeInteger},
		{ID: 81, Name: "zte-qos-type", DataType: DataTypeInteger},
		{ID: 82, Name: "zte-qos-profile-down", DataType: DataTypeString},
		{ID: 83, Name: "zte-rate-ctrl-scr-down", DataType: DataTypeInteger},
		{ID: 84, Name: "zte-rate-ctrl-burst-down", DataType: DataTypeInteger},
		{ID: 86, Name: "zte-rate-ctrl-pcr", DataType: DataTypeInteger},
		{ID: 88, Name: "zte-tcp-syn-rate", DataType: DataTypeInteger},
		{ID: 89, Name: "zte-rate-ctrl-scr-up", DataType: DataTypeInteger},
		{ID: 90, Name: "zte-priority-level", DataType: DataTypeInteger},
		{ID: 91, Name: "zte-rate-ctrl-burst-up", DataType: DataTypeInteger},
		{ID: 92, Name: "zte-rate-ctrl-burst-max-down", DataType: DataTypeInteger},
		{ID: 93, Name: "zte-rate-ctrl-burst-max-up", DataType: DataTypeInteger},
		{ID: 94, Name: "zte-qos-profile-up", DataType: DataTypeString},
		{ID: 95, Name: "zte-tcp-limit-num", DataType: DataTypeInteger},
		{ID: 96, Name: "zte-tcp-limit-mode", DataType: DataTypeInteger},
		{ID: 97, Name: "zte-igmp-service-profile-num", DataType: DataTypeInteger},
		{ID: 101, Name: "zte-ppp-sservice-type", DataType: DataTypeInteger},
		// Privilege level 0 (lowest) through 15 (highest).
		{ID: 104, Name: "zte-sw-privilege", DataType: DataTypeInteger},
		{ID: 151, Name: "zte-access-domain", DataType: DataTypeString},
		{ID: 190, Name: "zte-vpn-id", DataType: DataTypeString},
		{ID: 191, Name: "zte-rate-bust-dpir", DataType: DataTypeInteger},
		{ID: 192, Name: "zte-rate-bust-upir", DataType: DataTypeInteger},
		{ID: 202, Name: "zte-rate-ctrl-pbs-down", DataType: DataTypeInteger},
		{ID: 203, Name: "zte-rate-ctrl-pbs-up", DataType: DataTypeInteger},
		{ID: 228, Name: "zte-rate-ctrl-scr-up-v6", DataType: DataTypeInteger},
		{ID: 229, Name: "zte-rate-ctrl-burst-up-v6", DataType: DataTypeInteger},
		{ID: 230, Name: "zte-rate-ctrl-burst-max-up-v6", DataType: DataTypeInteger},
		{ID: 231, Name: "zte-rate-ctrl-pbs-up-v6", DataType: DataTypeInteger},
		{ID: 232, Name: "zte-qos-profile-up-v6", DataType: DataTypeString},
		{ID: 233, Name: "zte-rate-ctrl-scr-down-v6", DataType: DataTypeInteger},
		{ID: 234, Name: "zte-rate-ctrl-burst-down-v6", DataType: DataTypeInteger},
		{ID: 235, Name: "zte-rate-ctrl-burst-max-down-v6", DataType: DataTypeInteger},
		{ID: 236, Name: "zte-rate-ctrl-pbs-down-v6", DataType: DataTypeInteger},
		{ID: 237, Name: "zte-qos-profile-down-v6", DataType: DataTypeString},
	},
}
