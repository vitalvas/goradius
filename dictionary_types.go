package goradius

// DataType represents the data type of an attribute per RFC 2865 Section 5
type DataType string

const (
	DataTypeString     DataType = "string"   // Text (RFC 2865 Section 5)
	DataTypeOctets     DataType = "octets"   // Raw bytes (RFC 2865 Section 5)
	DataTypeInteger    DataType = "integer"  // 32-bit unsigned integer (RFC 2865 Section 5)
	DataTypeIPAddr     DataType = "ipaddr"   // IPv4 address (RFC 2865 Section 5)
	DataTypeDate       DataType = "date"     // Unix timestamp (RFC 2865 Section 5)
	DataTypeIPv6Addr   DataType = "ipv6addr" // IPv6 address (RFC 6929)
	DataTypeIPv6Prefix DataType = "ipv6prefix"
	DataTypeIfID       DataType = "ifid"
	DataTypeTLV        DataType = "tlv"
	DataTypeStruct     DataType = "struct" // Fixed-layout sequence of sub-attributes (RFC 6929 struct)
	DataTypeEVS        DataType = "evs"    // Extended-Vendor-Specific container (RFC 6929 Section 2.5)
	DataTypeABinary    DataType = "abinary"

	// Additional FreeRADIUS scalar types, used mostly by vendor dictionaries.
	DataTypeByte      DataType = "byte"       // 8-bit unsigned integer (1 octet)
	DataTypeShort     DataType = "short"      // 16-bit unsigned integer (2 octets)
	DataTypeInteger64 DataType = "integer64"  // 64-bit unsigned integer (8 octets)
	DataTypeSigned    DataType = "signed"     // 32-bit signed integer (4 octets)
	DataTypeComboIP   DataType = "combo-ip"   // IPv4 (4 octets) or IPv6 (16 octets) address
	DataTypeTimeDelta DataType = "time_delta" // Duration in seconds, 32-bit unsigned (4 octets)
)

// EncryptionType represents the encryption type of an attribute
type EncryptionType string

const (
	EncryptionNone           EncryptionType = ""
	EncryptionUserPassword   EncryptionType = "user-password"   // RFC 2865 Section 5.2
	EncryptionTunnelPassword EncryptionType = "tunnel-password" // RFC 2868 Section 3.5
	EncryptionAscendSecret   EncryptionType = "ascend-secret"   // Vendor-specific
)

// AttributeDefinition defines a RADIUS attribute per RFC 2865 Section 5
type AttributeDefinition struct {
	ID         uint32            `yaml:"id" json:"id"`
	Name       string            `yaml:"name" json:"name"`
	DataType   DataType          `yaml:"data_type" json:"data_type"`
	Usage      AttributeUsage    `yaml:"usage,omitempty" json:"usage,omitempty"`
	Encryption EncryptionType    `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	HasTag     bool              `yaml:"has_tag,omitempty" json:"has_tag,omitempty"`
	Array      bool              `yaml:"array,omitempty" json:"array,omitempty"`
	Multiline  bool              `yaml:"multiline,omitempty" json:"multiline,omitempty"`
	Extended   bool              `yaml:"extended,omitempty" json:"extended,omitempty"`
	Size       int               `yaml:"size,omitempty" json:"size,omitempty"`
	Values     map[string]uint32 `yaml:"values,omitempty" json:"values,omitempty"`

	// VendorID and VendorType identify the vendor for an Extended-Vendor-Specific (EVS)
	// attribute (RFC 6929 Section 2.5). They are only meaningful when DataType is evs.
	VendorID   uint32 `yaml:"vendor_id,omitempty" json:"vendor_id,omitempty"`
	VendorType uint8  `yaml:"vendor_type,omitempty" json:"vendor_type,omitempty"`

	// Children holds sub-attributes for complex container types (tlv, struct, evs).
	// For tlv/evs the children are tagged (type+length); for struct they are a fixed
	// ordered layout. Each child is itself an AttributeDefinition so nesting is possible.
	Children []*AttributeDefinition `yaml:"children,omitempty" json:"children,omitempty"`
}

// LookupChildByID returns the child attribute definition with the given ID, or
// (nil, false) if this attribute has no such child. Children are the sub-attributes
// of a tlv/struct/evs container attribute.
func (a *AttributeDefinition) LookupChildByID(id uint32) (*AttributeDefinition, bool) {
	for _, child := range a.Children {
		if child.ID == id {
			return child, true
		}
	}
	return nil, false
}

// LookupChildByName returns the child attribute definition with the given name, or
// (nil, false) if this attribute has no such child.
func (a *AttributeDefinition) LookupChildByName(name string) (*AttributeDefinition, bool) {
	for _, child := range a.Children {
		if child.Name == name {
			return child, true
		}
	}
	return nil, false
}

// VendorDefinition defines a vendor and its attributes per RFC 2865 Section 5.26
type VendorDefinition struct {
	ID         uint32                 `yaml:"id" json:"id"`
	Name       string                 `yaml:"name" json:"name"`
	Attributes []*AttributeDefinition `yaml:"attributes" json:"attributes"`

	// TypeOctets and LengthOctets describe the width of the Vendor-Type and
	// Vendor-Length fields inside the VSA, matching the FreeRADIUS
	// "format=t,l" dictionary flag. RFC 2865 Section 5.26 uses 1,1, which is
	// also the zero value: a VendorDefinition with both fields zero encodes
	// and decodes as standard 1-octet type / 1-octet length. Some vendors use
	// a wider type field (for example Alcatel-ESAM uses format=2,1), and a few
	// use no length field at all (LengthOctets 0 with TypeOctets set).
	TypeOctets   uint8 `yaml:"type_octets,omitempty" json:"type_octets,omitempty"`
	LengthOctets uint8 `yaml:"length_octets,omitempty" json:"length_octets,omitempty"`
}

// vsaTypeOctets returns the configured Vendor-Type width, defaulting to the
// RFC 2865 standard of 1 octet when unset.
func (v *VendorDefinition) vsaTypeOctets() int {
	if v.TypeOctets == 0 {
		return 1
	}
	return int(v.TypeOctets)
}

// vsaLengthOctets returns the configured Vendor-Length width. The zero value
// means the standard 1-octet length field; a vendor with a non-zero TypeOctets
// but a zero LengthOctets explicitly carries no length field.
func (v *VendorDefinition) vsaLengthOctets() int {
	if v.TypeOctets == 0 {
		return 1
	}
	return int(v.LengthOctets)
}

// Extended attribute type range per RFC 6929 Section 2.
// Types 241-246 are reserved for extended attributes; of those, 245-246 use the
// long extended format (with a Flags byte and the More bit for fragmentation).
const (
	// ExtendedTypeMin is the lowest standard type reserved for extended attributes (RFC 6929).
	ExtendedTypeMin uint8 = 241
	// ExtendedTypeMax is the highest standard type reserved for extended attributes (RFC 6929).
	ExtendedTypeMax uint8 = 246
	// LongExtendedTypeMin is the lowest type that uses the long extended format (RFC 6929).
	LongExtendedTypeMin uint8 = 245
	// LongExtendedTypeMax is the highest type that uses the long extended format (RFC 6929).
	LongExtendedTypeMax uint8 = 246
	// ExtendedIDShift is used to pack an extended attribute's base type and extended
	// type into a single uint32 ID as baseType*256 + extendedType.
	ExtendedIDShift uint32 = 256
)

// ExtendedBaseType returns the RFC 6929 base attribute type (241-246) for an
// extended attribute whose ID is encoded as baseType*256 + extendedType.
func (a *AttributeDefinition) ExtendedBaseType() uint8 {
	return uint8(a.ID / ExtendedIDShift)
}

// ExtendedType returns the RFC 6929 extended type (the low byte) for an extended
// attribute whose ID is encoded as baseType*256 + extendedType.
func (a *AttributeDefinition) ExtendedType() uint8 {
	return uint8(a.ID % ExtendedIDShift)
}

// IsExtendedBaseType reports whether the given standard attribute type is reserved
// for the RFC 6929 extended attribute format (241-246).
func IsExtendedBaseType(attrType uint8) bool {
	return attrType >= ExtendedTypeMin && attrType <= ExtendedTypeMax
}

// IsLongExtendedBaseType reports whether the given standard attribute type uses the
// RFC 6929 long extended format (245-246), which carries a Flags byte and supports
// fragmentation via the More bit.
func IsLongExtendedBaseType(attrType uint8) bool {
	return attrType >= LongExtendedTypeMin && attrType <= LongExtendedTypeMax
}
