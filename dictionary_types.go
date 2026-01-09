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
	DataTypeABinary    DataType = "abinary"
)

// EncryptionType represents the encryption type of an attribute
type EncryptionType string

const (
	EncryptionNone           EncryptionType = ""
	EncryptionUserPassword   EncryptionType = "user-password"   // RFC 2865 Section 5.2
	EncryptionTunnelPassword EncryptionType = "tunnel-password" // RFC 2868 Section 3.5
	EncryptionAscendSecret   EncryptionType = "ascend-secret"   // Vendor-specific
)

// AttributeType represents whether an attribute can be used in requests, replies, or both
type AttributeType uint8

const (
	AttributeTypeRequestReply AttributeType = 0 // Can be used in both requests and replies (default)
	AttributeTypeRequest      AttributeType = 1 // Can only be used in requests
	AttributeTypeReply        AttributeType = 2 // Can only be used in replies
)

// AttributeDefinition defines a RADIUS attribute per RFC 2865 Section 5
type AttributeDefinition struct {
	ID          uint32            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	DataType    DataType          `yaml:"data_type" json:"data_type"`
	Type        AttributeType     `yaml:"type,omitempty" json:"type,omitempty"`
	Encryption  EncryptionType    `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	HasTag      bool              `yaml:"has_tag,omitempty" json:"has_tag,omitempty"`
	Array       bool              `yaml:"array,omitempty" json:"array,omitempty"`
	Multiline   bool              `yaml:"multiline,omitempty" json:"multiline,omitempty"`
	Values      map[string]uint32 `yaml:"values,omitempty" json:"values,omitempty"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
}

// VendorDefinition defines a vendor and its attributes per RFC 2865 Section 5.26
type VendorDefinition struct {
	ID          uint32                 `yaml:"id" json:"id"`
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Attributes  []*AttributeDefinition `yaml:"attributes" json:"attributes"`
}
