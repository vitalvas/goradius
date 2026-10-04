package goradius

// EricssonPCNVendorDefinition defines the Ericsson Packet Core Networks vendor
// (ID 10923). Ported from FreeRADIUS dictionary.ericsson.packet.core.networks.
// Used by the Ericsson mobile packet core for policy rule-space selection.
//
// The dictionary carries no per-packet placement information, so all
// attributes stay unrestricted.
var EricssonPCNVendorDefinition = &VendorDefinition{
	ID:   10923,
	Name: "ericsson-pcn",
	Attributes: []*AttributeDefinition{
		{ID: 30, Name: "ericsson-pcn-suggested-rule-space", DataType: DataTypeString},
		{ID: 31, Name: "ericsson-pcn-suggested-secondary-rule-space", DataType: DataTypeString},
	},
}
