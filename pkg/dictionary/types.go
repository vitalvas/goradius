package dictionary

// DataType represents the data type of an attribute
type DataType string

const (
	DataTypeString     DataType = "string"
	DataTypeOctets     DataType = "octets"
	DataTypeInteger    DataType = "integer"
	DataTypeIPAddr     DataType = "ipaddr"
	DataTypeDate       DataType = "date"
	DataTypeIPv6Addr   DataType = "ipv6addr"
	DataTypeIPv6Prefix DataType = "ipv6prefix"
	DataTypeIfID       DataType = "ifid"
	DataTypeTLV        DataType = "tlv"
	DataTypeABinary    DataType = "abinary"
)

// EncryptionType represents the encryption type of an attribute
type EncryptionType string

const (
	EncryptionNone           EncryptionType = ""
	EncryptionUserPassword   EncryptionType = "user-password"
	EncryptionTunnelPassword EncryptionType = "tunnel-password"
	EncryptionAscendSecret   EncryptionType = "ascend-secret"
)

// AttributeDefinition defines a RADIUS attribute
type AttributeDefinition struct {
	ID          uint32            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	DataType    DataType          `yaml:"data_type" json:"data_type"`
	Encryption  EncryptionType    `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	HasTag      bool              `yaml:"has_tag,omitempty" json:"has_tag,omitempty"`
	Array       bool              `yaml:"array,omitempty" json:"array,omitempty"`
	Values      map[string]uint32 `yaml:"values,omitempty" json:"values,omitempty"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
}

// VendorDefinition defines a vendor and its attributes
type VendorDefinition struct {
	ID          uint32                 `yaml:"id" json:"id"`
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Attributes  []*AttributeDefinition `yaml:"attributes" json:"attributes"`
}
