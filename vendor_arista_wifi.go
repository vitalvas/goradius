package goradius

// AristaWiFiVendorDefinition defines the Arista WiFi vendor (ID 16901,
// inherited from Mojo Networks) used by Arista access points and CV-CUE.
// Transcribed from the official dictionary.aristanetworks published in the
// Arista community article "RADIUS Dictionary for Arista Networks (WiFi)":
// https://arista.my.site.com/AristaCommunity/s/article/radius-dictionary-for-arista-networks
//
// Attribute names carry the arista-wifi prefix to distinguish them from the
// Arista EOS vendor (ID 30065), which defines clashing raw names such as
// Captive-Portal. IDs 9 and 10 are reserved in the official dictionary and
// carry no data type, so they are omitted. The dictionary documents no
// per-packet placement, so all attributes stay unrestricted.
var AristaWiFiVendorDefinition = &VendorDefinition{
	ID:   16901,
	Name: "arista-wifi",
	Attributes: []*AttributeDefinition{
		{ID: 1, Name: "arista-wifi-cli-access-allowed", DataType: DataTypeString},
		{ID: 2, Name: "arista-wifi-gui-access-allowed", DataType: DataTypeString},
		{ID: 3, Name: "arista-wifi-gui-user-role", DataType: DataTypeString},
		{ID: 4, Name: "arista-wifi-locations-allowed", DataType: DataTypeString},
		{ID: 5, Name: "arista-wifi-download-limit", DataType: DataTypeInteger},
		{ID: 6, Name: "arista-wifi-upload-limit", DataType: DataTypeInteger},
		{ID: 7, Name: "arista-wifi-client-role", DataType: DataTypeString},
		{ID: 8, Name: "arista-wifi-captive-portal", DataType: DataTypeString},
		{ID: 11, Name: "arista-wifi-bssid-mac", DataType: DataTypeString},
		{ID: 12, Name: "arista-wifi-upsk-anonce", DataType: DataTypeString},
		{ID: 13, Name: "arista-wifi-upsk-eapol", DataType: DataTypeString},
		{ID: 14, Name: "arista-wifi-ssid-name", DataType: DataTypeString},
		{ID: 15, Name: "arista-wifi-upsk-client-type", DataType: DataTypeInteger},
		{ID: 16, Name: "arista-wifi-upsk-personal-client", DataType: DataTypeString},
		{ID: 17, Name: "arista-wifi-upsk-shared-client", DataType: DataTypeString},
		{ID: 18, Name: "arista-wifi-upsk-action", DataType: DataTypeInteger},
		{ID: 19, Name: "arista-wifi-client-profiling", DataType: DataTypeString},
		{ID: 20, Name: "arista-wifi-preauth-flag", DataType: DataTypeInteger},
	},
}
