package dictionary

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DataType represents the data type of a RADIUS attribute
type DataType string

// EncryptionType represents the encryption method for a RADIUS attribute
type EncryptionType string

// TLVFormat represents the Type-Length-Value format specification
type TLVFormat string

// Supported data types for RADIUS attributes
const (
	DataTypeString     DataType = "string"
	DataTypeOctets     DataType = "octets"
	DataTypeInteger    DataType = "integer"
	DataTypeDate       DataType = "date"
	DataTypeIPAddr     DataType = "ipaddr"
	DataTypeIPv6Addr   DataType = "ipv6addr"
	DataTypeIPv6Prefix DataType = "ipv6prefix"
	DataTypeIfId       DataType = "ifid"
	DataTypeUint32     DataType = "uint32"
	DataTypeUint64     DataType = "uint64"
	DataTypeTLV        DataType = "tlv"
)

// Supported encryption types for RADIUS attributes
const (
	// EncryptionNone means no encryption is applied
	EncryptionNone EncryptionType = ""

	// EncryptionUserPassword uses RFC2865 User-Password encryption method
	EncryptionUserPassword EncryptionType = "User-Password"

	// EncryptionTunnelPassword uses RFC2868 Tunnel-Password encryption method
	EncryptionTunnelPassword EncryptionType = "Tunnel-Password"

	// EncryptionAscendSecret uses Ascend Send-Secret encryption method
	EncryptionAscendSecret EncryptionType = "Ascend-Secret"
)

// Supported TLV formats for RADIUS attributes
const (
	// TLVFormatStandard uses standard 8-bit Type + 8-bit Length format (RFC standard)
	TLVFormatStandard TLVFormat = "standard"

	// TLVFormatIEEE8021X uses 7-bit Type + 9-bit Length format (IEEE 802.1X-2010)
	TLVFormatIEEE8021X TLVFormat = "ieee-802.1x"
)

// TLVSubAttribute defines a sub-attribute within a TLV attribute
type TLVSubAttribute struct {
	Name     string   `yaml:"name" json:"name"`
	Type     uint8    `yaml:"type" json:"type"`
	DataType DataType `yaml:"data_type" json:"data_type"`
	Length   int      `yaml:"length,omitempty" json:"length,omitempty"`
	Optional bool     `yaml:"optional,omitempty" json:"optional,omitempty"`
}

// AttributeDefinition defines a RADIUS attribute in the dictionary
type AttributeDefinition struct {
	Name          string                     `yaml:"name" json:"name"`
	ID            uint8                      `yaml:"id" json:"id"`
	DataType      DataType                   `yaml:"data_type" json:"data_type"`
	Length        int                        `yaml:"length,omitempty" json:"length,omitempty"`
	VendorID      uint32                     `yaml:"vendor_id,omitempty" json:"vendor_id,omitempty"`
	Values        map[string]uint32          `yaml:"values,omitempty" json:"values,omitempty"`
	Array         bool                       `yaml:"array,omitempty" json:"array,omitempty"`
	Optional      bool                       `yaml:"optional,omitempty" json:"optional,omitempty"`
	HasTag        bool                       `yaml:"has_tag,omitempty" json:"has_tag,omitempty"`
	Encryption    EncryptionType             `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	TLVFormat     TLVFormat                  `yaml:"tlv_format,omitempty" json:"tlv_format,omitempty"`
	SubAttributes map[uint8]*TLVSubAttribute `yaml:"sub_attributes,omitempty" json:"sub_attributes,omitempty"`
}

// VendorDefinition defines a vendor in the dictionary
type VendorDefinition struct {
	Name        string `yaml:"name" json:"name"`
	ID          uint32 `yaml:"id" json:"id"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Dictionary represents a complete RADIUS dictionary
type Dictionary struct {
	Vendors    map[uint32]*VendorDefinition              `yaml:"vendors" json:"vendors"`
	Attributes map[uint8]*AttributeDefinition            `yaml:"attributes" json:"attributes"`
	VSAs       map[uint32]map[uint8]*AttributeDefinition `yaml:"vsas,omitempty" json:"vsas,omitempty"`
}

// Source defines the interface for loading dictionaries from various sources
type Source interface {
	// Load loads a dictionary from the source
	Load(ctx context.Context) (*Dictionary, error)

	// Close closes the source and releases any resources
	Close() error
}

// NewDictionary creates a new empty dictionary
func NewDictionary() *Dictionary {
	return &Dictionary{
		Vendors:    make(map[uint32]*VendorDefinition),
		Attributes: make(map[uint8]*AttributeDefinition),
		VSAs:       make(map[uint32]map[uint8]*AttributeDefinition),
	}
}

// AddVendor adds a vendor definition to the dictionary
func (d *Dictionary) AddVendor(vendor *VendorDefinition) error {
	if vendor == nil {
		return fmt.Errorf("vendor definition cannot be nil")
	}

	if vendor.ID == 0 {
		return fmt.Errorf("vendor ID cannot be zero")
	}

	if vendor.Name == "" {
		return fmt.Errorf("vendor name cannot be empty")
	}

	if existing, exists := d.Vendors[vendor.ID]; exists {
		return fmt.Errorf("vendor ID %d already exists with name %s", vendor.ID, existing.Name)
	}

	d.Vendors[vendor.ID] = vendor
	return nil
}

// AddAttribute adds an attribute definition to the dictionary
func (d *Dictionary) AddAttribute(attr *AttributeDefinition) error {
	if attr == nil {
		return fmt.Errorf("attribute definition cannot be nil")
	}

	if attr.Name == "" {
		return fmt.Errorf("attribute name cannot be empty")
	}

	if err := d.validateAttributeDataType(attr); err != nil {
		return fmt.Errorf("invalid attribute data type: %w", err)
	}

	if err := d.validateAttributeEncryption(attr); err != nil {
		return fmt.Errorf("invalid attribute encryption: %w", err)
	}

	if attr.VendorID == 0 {
		// Standard attribute
		if existing, exists := d.Attributes[attr.ID]; exists {
			return fmt.Errorf("attribute type %d already exists with name %s", attr.ID, existing.Name)
		}
		d.Attributes[attr.ID] = attr
	} else {
		// Vendor-Specific Attribute
		if _, exists := d.Vendors[attr.VendorID]; !exists {
			return fmt.Errorf("vendor ID %d not found in dictionary", attr.VendorID)
		}

		if d.VSAs[attr.VendorID] == nil {
			d.VSAs[attr.VendorID] = make(map[uint8]*AttributeDefinition)
		}

		if existing, exists := d.VSAs[attr.VendorID][attr.ID]; exists {
			return fmt.Errorf("VSA type %d for vendor %d already exists with name %s", attr.ID, attr.VendorID, existing.Name)
		}

		d.VSAs[attr.VendorID][attr.ID] = attr
	}

	return nil
}

// GetAttribute retrieves an attribute definition by type
func (d *Dictionary) GetAttribute(attrType uint8) (*AttributeDefinition, bool) {
	attr, exists := d.Attributes[attrType]
	return attr, exists
}

// GetVSA retrieves a vendor-specific attribute definition
func (d *Dictionary) GetVSA(vendorID uint32, attrType uint8) (*AttributeDefinition, bool) {
	if vendorAttrs, exists := d.VSAs[vendorID]; exists {
		if attr, exists := vendorAttrs[attrType]; exists {
			return attr, true
		}
	}
	return nil, false
}

// GetVendor retrieves a vendor definition by ID
func (d *Dictionary) GetVendor(vendorID uint32) (*VendorDefinition, bool) {
	vendor, exists := d.Vendors[vendorID]
	return vendor, exists
}

// GetAttributeByName retrieves an attribute definition by name
func (d *Dictionary) GetAttributeByName(name string) (*AttributeDefinition, bool) {
	for _, attr := range d.Attributes {
		if attr.Name == name {
			return attr, true
		}
	}

	// Search VSAs
	for _, vendorAttrs := range d.VSAs {
		for _, attr := range vendorAttrs {
			if attr.Name == name {
				return attr, true
			}
		}
	}

	return nil, false
}

// validateAttributeDataType validates the data type and associated constraints
func (d *Dictionary) validateAttributeDataType(attr *AttributeDefinition) error {
	switch attr.DataType {
	case DataTypeString:
		if attr.Length > 0 && attr.Length > 253 {
			return fmt.Errorf("string attribute length cannot exceed 253 bytes")
		}
	case DataTypeOctets:
		if attr.Length > 0 && attr.Length > 253 {
			return fmt.Errorf("octets attribute length cannot exceed 253 bytes")
		}
	case DataTypeInteger, DataTypeUint32, DataTypeDate:
		if attr.Length > 0 && attr.Length != 4 {
			return fmt.Errorf("%s attributes must be exactly 4 bytes", attr.DataType)
		}
	case DataTypeUint64:
		if attr.Length > 0 && attr.Length != 8 {
			return fmt.Errorf("uint64 attributes must be exactly 8 bytes")
		}
	case DataTypeIPAddr:
		if attr.Length > 0 && attr.Length != 4 {
			return fmt.Errorf("ipaddr attributes must be exactly 4 bytes")
		}
	case DataTypeIPv6Addr:
		if attr.Length > 0 && attr.Length != 16 {
			return fmt.Errorf("ipv6addr attributes must be exactly 16 bytes")
		}
	case DataTypeIPv6Prefix:
		if attr.Length > 0 && (attr.Length < 2 || attr.Length > 18) {
			return fmt.Errorf("ipv6prefix attributes must be between 2 and 18 bytes")
		}
	case DataTypeIfId:
		if attr.Length > 0 && attr.Length != 8 {
			return fmt.Errorf("ifid attributes must be exactly 8 bytes")
		}
	case DataTypeTLV:
		if attr.Length > 0 && attr.Length > 253 {
			return fmt.Errorf("TLV attribute length cannot exceed 253 bytes")
		}
		// Validate TLV format
		if err := d.validateTLVFormat(attr); err != nil {
			return fmt.Errorf("invalid TLV format: %w", err)
		}
		// Validate sub-attributes for TLV
		if err := d.validateTLVSubAttributes(attr); err != nil {
			return fmt.Errorf("invalid TLV sub-attributes: %w", err)
		}
	default:
		return fmt.Errorf("unsupported data type: %s", attr.DataType)
	}
	return nil
}

// validateAttributeEncryption validates the encryption field
func (d *Dictionary) validateAttributeEncryption(attr *AttributeDefinition) error {
	if attr.Encryption == "" || attr.Encryption == EncryptionNone {
		return nil // No encryption is valid
	}

	if !attr.Encryption.IsValid() {
		return fmt.Errorf("unsupported encryption type: %s", attr.Encryption)
	}

	// All data types can support encryption (FreeRADIUS compatibility)

	return nil
}

// validateTLVFormat validates the TLV format specification
func (d *Dictionary) validateTLVFormat(attr *AttributeDefinition) error {
	if attr.DataType != DataTypeTLV {
		return nil // Only validate for TLV attributes
	}

	// Default to standard format if not specified
	if attr.TLVFormat == "" {
		attr.TLVFormat = TLVFormatStandard
	}

	// Validate supported formats
	switch attr.TLVFormat {
	case TLVFormatStandard, TLVFormatIEEE8021X:
		return nil
	default:
		return fmt.Errorf("unsupported TLV format: %s", attr.TLVFormat)
	}
}

// validateTLVSubAttributes validates sub-attributes for TLV attributes
func (d *Dictionary) validateTLVSubAttributes(attr *AttributeDefinition) error {
	if attr.DataType != DataTypeTLV {
		return nil // Only validate for TLV attributes
	}

	if attr.SubAttributes == nil || len(attr.SubAttributes) == 0 {
		return nil // Empty sub-attributes are allowed
	}

	for subType, subAttr := range attr.SubAttributes {
		if subAttr == nil {
			return fmt.Errorf("sub-attribute type %d is nil", subType)
		}

		if subAttr.Type != subType {
			return fmt.Errorf("sub-attribute type mismatch: expected %d, got %d", subType, subAttr.Type)
		}

		// Validate sub-attribute data type
		if err := d.validateSubAttributeDataType(subAttr); err != nil {
			return fmt.Errorf("invalid sub-attribute %s: %w", subAttr.Name, err)
		}
	}

	return nil
}

// validateSubAttributeDataType validates sub-attribute data types (similar to main validation but simpler)
func (d *Dictionary) validateSubAttributeDataType(subAttr *TLVSubAttribute) error {
	switch subAttr.DataType {
	case DataTypeString, DataTypeOctets:
		if subAttr.Length > 0 && subAttr.Length > 253 {
			return fmt.Errorf("%s sub-attribute length cannot exceed 253 bytes", subAttr.DataType)
		}
	case DataTypeInteger, DataTypeUint32, DataTypeDate, DataTypeIPAddr:
		if subAttr.Length > 0 && subAttr.Length != 4 {
			return fmt.Errorf("%s sub-attributes must be exactly 4 bytes", subAttr.DataType)
		}
	case DataTypeUint64, DataTypeIfId:
		if subAttr.Length > 0 && subAttr.Length != 8 {
			return fmt.Errorf("%s sub-attributes must be exactly 8 bytes", subAttr.DataType)
		}
	case DataTypeIPv6Addr:
		if subAttr.Length > 0 && subAttr.Length != 16 {
			return fmt.Errorf("ipv6addr sub-attributes must be exactly 16 bytes")
		}
	case DataTypeIPv6Prefix:
		if subAttr.Length > 0 && (subAttr.Length < 2 || subAttr.Length > 18) {
			return fmt.Errorf("ipv6prefix sub-attributes must be between 2 and 18 bytes")
		}
	case DataTypeTLV:
		return fmt.Errorf("nested TLV sub-attributes are not supported")
	default:
		return fmt.Errorf("unsupported sub-attribute data type: %s", subAttr.DataType)
	}
	return nil
}

// IsFixedLength returns true if the attribute has a fixed length constraint
func (attr *AttributeDefinition) IsFixedLength() bool {
	return attr.Length > 0
}

// GetFixedLength returns the fixed length if specified, or 0 if variable length
func (attr *AttributeDefinition) GetFixedLength() int {
	return attr.Length
}

// HasValues returns true if the attribute has named values (enumeration)
func (attr *AttributeDefinition) HasValues() bool {
	return len(attr.Values) > 0
}

// IsTagged returns true if the attribute supports tags (RFC 2868)
func (attr *AttributeDefinition) IsTagged() bool {
	return attr.HasTag
}

// IsEncrypted returns true if the attribute requires encryption
func (attr *AttributeDefinition) IsEncrypted() bool {
	return attr.Encryption != EncryptionNone && attr.Encryption != ""
}

// GetEncryptionType returns the encryption type for the attribute
func (attr *AttributeDefinition) GetEncryptionType() EncryptionType {
	return attr.Encryption
}

// ParseEncryptionType parses an encryption type from string or numeric format
// Supports FreeRADIUS formats: "1", "2", "3", "User-Password", "Tunnel-Password", "Ascend-Secret"
func ParseEncryptionType(value string) (EncryptionType, error) {
	if value == "" {
		return EncryptionNone, nil
	}

	// Handle numeric formats (FreeRADIUS compatibility)
	switch value {
	case "1":
		return EncryptionUserPassword, nil
	case "2":
		return EncryptionTunnelPassword, nil
	case "3":
		return EncryptionAscendSecret, nil
	}

	// Handle string formats
	switch EncryptionType(value) {
	case EncryptionUserPassword, EncryptionTunnelPassword, EncryptionAscendSecret:
		return EncryptionType(value), nil
	default:
		return EncryptionNone, fmt.Errorf("unsupported encryption type: %s", value)
	}
}

// ToNumeric returns the numeric representation of the encryption type (FreeRADIUS compatibility)
func (et EncryptionType) ToNumeric() string {
	switch et {
	case EncryptionUserPassword:
		return "1"
	case EncryptionTunnelPassword:
		return "2"
	case EncryptionAscendSecret:
		return "3"
	default:
		return ""
	}
}

// String returns the string representation of the encryption type
func (et EncryptionType) String() string {
	return string(et)
}

// IsValid returns true if the encryption type is valid
func (et EncryptionType) IsValid() bool {
	switch et {
	case EncryptionNone, EncryptionUserPassword, EncryptionTunnelPassword, EncryptionAscendSecret:
		return true
	default:
		return false
	}
}

// GetValueName returns the name for a given value, or empty string if not found
func (attr *AttributeDefinition) GetValueName(value uint32) string {
	for name, val := range attr.Values {
		if val == value {
			return name
		}
	}
	return ""
}

// GetValueByName returns the value for a given name, or 0 and false if not found
func (attr *AttributeDefinition) GetValueByName(name string) (uint32, bool) {
	value, exists := attr.Values[name]
	return value, exists
}

// ValidateValue validates a value according to the attribute's data type and constraints
func (attr *AttributeDefinition) ValidateValue(value []byte) error {
	actualValue := value
	expectedLength := attr.Length

	// For tagged attributes, the first byte is the tag field
	if attr.HasTag {
		if len(value) == 0 {
			return fmt.Errorf("tagged attribute cannot be empty")
		}
		tag := value[0]
		if tag == 0 || tag > 0x1F {
			return fmt.Errorf("invalid tag value: 0x%02X (must be 0x01-0x1F)", tag)
		}
		actualValue = value[1:]
		if expectedLength > 0 {
			expectedLength-- // Account for tag byte
		}
	}

	if attr.IsFixedLength() && len(actualValue) != expectedLength {
		return fmt.Errorf("value length %d does not match required length %d", len(actualValue), expectedLength)
	}

	switch attr.DataType {
	case DataTypeString:
		// String validation - ensure valid UTF-8
		if !isValidUTF8(actualValue) {
			return fmt.Errorf("invalid UTF-8 string")
		}

	case DataTypeOctets:
		// Octets can be any byte sequence - no additional validation needed

	case DataTypeInteger, DataTypeUint32:
		if len(actualValue) != 4 {
			return fmt.Errorf("integer value must be 4 bytes")
		}

	case DataTypeUint64:
		if len(actualValue) != 8 {
			return fmt.Errorf("uint64 value must be 8 bytes")
		}

	case DataTypeDate:
		if len(actualValue) != 4 {
			return fmt.Errorf("date value must be 4 bytes")
		}

	case DataTypeIPAddr:
		if len(actualValue) != 4 {
			return fmt.Errorf("IP address must be 4 bytes")
		}

	case DataTypeIPv6Addr:
		if len(actualValue) != 16 {
			return fmt.Errorf("IPv6 address must be 16 bytes")
		}
	case DataTypeIfId:
		if len(actualValue) != 8 {
			return fmt.Errorf("interface ID must be 8 bytes")
		}

	case DataTypeIPv6Prefix:
		if len(actualValue) < 2 || len(actualValue) > 18 {
			return fmt.Errorf("IPv6 prefix must be between 2 and 18 bytes")
		}
		// First byte is the prefix length (0-128)
		prefixLen := actualValue[0]
		if prefixLen > 128 {
			return fmt.Errorf("IPv6 prefix length must be 0-128, got %d", prefixLen)
		}

	default:
		return fmt.Errorf("unsupported data type: %s", attr.DataType)
	}

	return nil
}

// ParseValue parses a string representation into the appropriate binary format
func (attr *AttributeDefinition) ParseValue(valueStr string) ([]byte, error) {
	switch attr.DataType {
	case DataTypeString:
		return []byte(valueStr), nil

	case DataTypeOctets:
		// Handle hex string format (e.g., "0x01020304")
		if strings.HasPrefix(valueStr, "0x") {
			return parseHexString(valueStr[2:])
		}
		return []byte(valueStr), nil

	case DataTypeInteger, DataTypeUint32:
		val, err := strconv.ParseUint(valueStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid integer value: %w", err)
		}
		return uint32ToBytes(uint32(val)), nil

	case DataTypeUint64:
		val, err := strconv.ParseUint(valueStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid uint64 value: %w", err)
		}
		return uint64ToBytes(val), nil

	case DataTypeDate:
		// Parse as Unix timestamp
		val, err := strconv.ParseInt(valueStr, 10, 64)
		if err != nil {
			// Try parsing as RFC3339 format
			t, err := time.Parse(time.RFC3339, valueStr)
			if err != nil {
				return nil, fmt.Errorf("invalid date value: %w", err)
			}
			val = t.Unix()
		}
		return uint32ToBytes(uint32(val)), nil

	case DataTypeIPAddr:
		ip := net.ParseIP(valueStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", valueStr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("not an IPv4 address: %s", valueStr)
		}
		return ipv4, nil

	case DataTypeIPv6Addr:
		ip := net.ParseIP(valueStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", valueStr)
		}
		ipv6 := ip.To16()
		if ipv6 == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", valueStr)
		}
		return ipv6, nil

	case DataTypeIfId:
		// Interface ID is 8 bytes, can be in hex format like "00:11:22:33:44:55:66:77"
		if len(valueStr) == 23 && strings.Count(valueStr, ":") == 7 {
			// Parse colon-separated hex format
			parts := strings.Split(valueStr, ":")
			if len(parts) != 8 {
				return nil, fmt.Errorf("invalid interface ID format: %s", valueStr)
			}
			result := make([]byte, 8)
			for i, part := range parts {
				b, err := strconv.ParseUint(part, 16, 8)
				if err != nil {
					return nil, fmt.Errorf("invalid hex byte in interface ID: %s", part)
				}
				result[i] = byte(b)
			}
			return result, nil
		}
		// Try parsing as 16-character hex string
		if len(valueStr) == 16 {
			bytes, err := hex.DecodeString(valueStr)
			if err != nil {
				return nil, fmt.Errorf("invalid hex string for interface ID: %s", valueStr)
			}
			return bytes, nil
		}
		return nil, fmt.Errorf("invalid interface ID format: %s (expected 8 hex bytes)", valueStr)

	case DataTypeIPv6Prefix:
		// Parse IPv6 prefix in CIDR format (e.g., "2001:db8::/64")
		_, ipNet, err := net.ParseCIDR(valueStr)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv6 prefix: %s", valueStr)
		}

		// Ensure this is an IPv6 prefix, not IPv4
		if ipNet.IP.To4() != nil {
			return nil, fmt.Errorf("not an IPv6 prefix: %s", valueStr)
		}

		// IPv6 prefix format: 1 byte prefix length + up to 16 bytes of prefix
		prefixLen, _ := ipNet.Mask.Size()
		if prefixLen > 128 {
			return nil, fmt.Errorf("IPv6 prefix length cannot exceed 128")
		}

		// Calculate how many bytes we need for the prefix
		prefixBytes := (prefixLen + 7) / 8
		if prefixBytes == 0 {
			prefixBytes = 1 // At least 1 byte for the length
		}

		result := make([]byte, 1+prefixBytes)
		result[0] = byte(prefixLen)

		// Copy the relevant prefix bytes
		ipv6 := ipNet.IP.To16()
		copy(result[1:], ipv6[:prefixBytes])

		return result, nil

	default:
		return nil, fmt.Errorf("unsupported data type: %s", attr.DataType)
	}
}

// Helper functions

func isValidUTF8(data []byte) bool {
	for len(data) > 0 {
		r, size := decodeRune(data)
		if r == '\uFFFD' && size == 1 {
			return false
		}
		data = data[size:]
	}
	return true
}

func decodeRune(data []byte) (rune, int) {
	if len(data) == 0 {
		return '\uFFFD', 0
	}

	b := data[0]
	if b < 0x80 {
		return rune(b), 1
	}

	// Simplified UTF-8 validation - for production use a proper UTF-8 library
	if len(data) >= 2 && b&0xE0 == 0xC0 {
		return rune(b&0x1F)<<6 | rune(data[1]&0x3F), 2
	}
	if len(data) >= 3 && b&0xF0 == 0xE0 {
		return rune(b&0x0F)<<12 | rune(data[1]&0x3F)<<6 | rune(data[2]&0x3F), 3
	}
	if len(data) >= 4 && b&0xF8 == 0xF0 {
		return rune(b&0x07)<<18 | rune(data[1]&0x3F)<<12 | rune(data[2]&0x3F)<<6 | rune(data[3]&0x3F), 4
	}

	return '\uFFFD', 1
}

func parseHexString(hex string) ([]byte, error) {
	if len(hex)%2 != 0 {
		return nil, fmt.Errorf("hex string must have even length")
	}

	result := make([]byte, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		val, err := strconv.ParseUint(hex[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex digit: %s", hex[i:i+2])
		}
		result[i/2] = byte(val)
	}
	return result, nil
}

func uint32ToBytes(val uint32) []byte {
	return []byte{
		byte(val >> 24),
		byte(val >> 16),
		byte(val >> 8),
		byte(val),
	}
}

func uint64ToBytes(val uint64) []byte {
	return []byte{
		byte(val >> 56),
		byte(val >> 48),
		byte(val >> 40),
		byte(val >> 32),
		byte(val >> 24),
		byte(val >> 16),
		byte(val >> 8),
		byte(val),
	}
}

// AddSubAttribute adds a sub-attribute to a TLV attribute
func (attr *AttributeDefinition) AddSubAttribute(subAttr *TLVSubAttribute) error {
	if attr.DataType != DataTypeTLV {
		return fmt.Errorf("can only add sub-attributes to TLV attributes")
	}

	if subAttr == nil {
		return fmt.Errorf("sub-attribute cannot be nil")
	}

	if attr.SubAttributes == nil {
		attr.SubAttributes = make(map[uint8]*TLVSubAttribute)
	}

	if existing, exists := attr.SubAttributes[subAttr.Type]; exists {
		return fmt.Errorf("sub-attribute type %d already exists with name %s", subAttr.Type, existing.Name)
	}

	attr.SubAttributes[subAttr.Type] = subAttr
	return nil
}

// GetSubAttribute retrieves a sub-attribute by type
func (attr *AttributeDefinition) GetSubAttribute(subType uint8) (*TLVSubAttribute, bool) {
	if attr.DataType != DataTypeTLV || attr.SubAttributes == nil {
		return nil, false
	}

	subAttr, exists := attr.SubAttributes[subType]
	return subAttr, exists
}

// GetSubAttributeByName retrieves a sub-attribute by name
func (attr *AttributeDefinition) GetSubAttributeByName(name string) (*TLVSubAttribute, bool) {
	if attr.DataType != DataTypeTLV || attr.SubAttributes == nil {
		return nil, false
	}

	for _, subAttr := range attr.SubAttributes {
		if subAttr.Name == name {
			return subAttr, true
		}
	}
	return nil, false
}

// HasSubAttributes returns true if the TLV attribute has sub-attributes defined
func (attr *AttributeDefinition) HasSubAttributes() bool {
	return attr.DataType == DataTypeTLV && len(attr.SubAttributes) > 0
}

// IsTLV returns true if the attribute is a TLV attribute
func (attr *AttributeDefinition) IsTLV() bool {
	return attr.DataType == DataTypeTLV
}

// GetTLVFormat returns the TLV format, defaulting to standard if not specified
func (attr *AttributeDefinition) GetTLVFormat() TLVFormat {
	if attr.DataType != DataTypeTLV {
		return ""
	}
	if attr.TLVFormat == "" {
		return TLVFormatStandard
	}
	return attr.TLVFormat
}

// IsStandardTLV returns true if the attribute uses standard TLV format
func (attr *AttributeDefinition) IsStandardTLV() bool {
	return attr.IsTLV() && attr.GetTLVFormat() == TLVFormatStandard
}

// IsIEEE8021XTLV returns true if the attribute uses IEEE 802.1X TLV format
func (attr *AttributeDefinition) IsIEEE8021XTLV() bool {
	return attr.IsTLV() && attr.GetTLVFormat() == TLVFormatIEEE8021X
}

// IsValid returns true if the TLV format is supported
func (f TLVFormat) IsValid() bool {
	switch f {
	case TLVFormatStandard, TLVFormatIEEE8021X:
		return true
	default:
		return false
	}
}

// String returns the string representation of the TLV format
func (f TLVFormat) String() string {
	return string(f)
}

// GetTypeBits returns the number of bits used for the Type field
func (f TLVFormat) GetTypeBits() int {
	switch f {
	case TLVFormatStandard:
		return 8 // Standard 8-bit Type
	case TLVFormatIEEE8021X:
		return 7 // IEEE 802.1X 7-bit Type
	default:
		return 8 // Default to standard
	}
}

// GetLengthBits returns the number of bits used for the Length field
func (f TLVFormat) GetLengthBits() int {
	switch f {
	case TLVFormatStandard:
		return 8 // Standard 8-bit Length
	case TLVFormatIEEE8021X:
		return 9 // IEEE 802.1X 9-bit Length
	default:
		return 8 // Default to standard
	}
}

// GetMaxTypeValue returns the maximum value for the Type field
func (f TLVFormat) GetMaxTypeValue() uint16 {
	switch f {
	case TLVFormatStandard:
		return 255 // 2^8 - 1
	case TLVFormatIEEE8021X:
		return 127 // 2^7 - 1
	default:
		return 255 // Default to standard
	}
}

// GetMaxLengthValue returns the maximum value for the Length field
func (f TLVFormat) GetMaxLengthValue() uint16 {
	switch f {
	case TLVFormatStandard:
		return 255 // 2^8 - 1
	case TLVFormatIEEE8021X:
		return 511 // 2^9 - 1
	default:
		return 255 // Default to standard
	}
}
