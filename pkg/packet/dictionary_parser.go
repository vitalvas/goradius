package packet

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vitalvas/goradius/pkg/dictionary"
)

// DictionaryParser provides dictionary-aware packet parsing and building
type DictionaryParser struct {
	dict *dictionary.Dictionary
}

// NewDictionaryParser creates a new dictionary-aware parser
func NewDictionaryParser(dict *dictionary.Dictionary) *DictionaryParser {
	return &DictionaryParser{
		dict: dict,
	}
}

// ParseAttributeValue parses an attribute value based on its dictionary definition
func (dp *DictionaryParser) ParseAttributeValue(attr Attribute) (interface{}, error) {
	if dp.dict == nil {
		return attr.Value, nil
	}

	// Look up attribute definition
	var attrDef *dictionary.AttributeDefinition
	var found bool
	valueToProcess := attr.Value

	// Check for VSA first
	if attr.Type == AttrVendorSpecific {
		vendorID, vendorType, err := dp.parseVSAHeader(attr.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VSA header: %w", err)
		}

		if vendorAttrs, exists := dp.dict.VSAs[vendorID]; exists {
			if def, exists := vendorAttrs[vendorType]; exists {
				attrDef = def
				found = true
			}
		}

		// For VSAs, always skip the header (6 bytes: vendor-id(4) + vendor-type(1) + vendor-length(1))
		// regardless of whether we have a definition or not
		valueToProcess = attr.Value[6:]

		if !found {
			// Return raw value without VSA header for unknown VSAs
			return valueToProcess, nil
		}
	} else {
		// Standard attribute
		if def, exists := dp.dict.Attributes[attr.Type]; exists {
			attrDef = def
			found = true
		}

		if !found {
			// Return raw value if no dictionary definition
			return attr.Value, nil
		}
	}

	// Handle tagged attributes
	if found && attrDef.IsTagged() {
		if len(valueToProcess) == 0 {
			return nil, fmt.Errorf("tagged attribute cannot be empty")
		}

		tag := valueToProcess[0]
		if tag == 0 || tag > 0x1F {
			return nil, fmt.Errorf("invalid tag value: 0x%02X (must be 0x01-0x1F)", tag)
		}

		actualValue := valueToProcess[1:]

		// Return a TaggedValue structure
		return &TaggedValue{
			Tag:   tag,
			Value: actualValue,
		}, nil
	}

	return dp.parseValueByType(valueToProcess, attrDef)
}

// BuildAttributeValue builds an attribute value based on dictionary definition
func (dp *DictionaryParser) BuildAttributeValue(attrType uint8, value interface{}) ([]byte, error) {
	if dp.dict == nil {
		// Without dictionary, assume it's raw bytes
		if data, ok := value.([]byte); ok {
			return data, nil
		}
		return nil, fmt.Errorf("unsupported value type for raw encoding")
	}

	var attrDef *dictionary.AttributeDefinition
	var found bool

	if def, exists := dp.dict.Attributes[attrType]; exists {
		attrDef = def
		found = true
	}

	if !found {
		// Return raw value if no dictionary definition
		if data, ok := value.([]byte); ok {
			return data, nil
		}
		return nil, fmt.Errorf("unknown attribute type %d and value is not []byte", attrType)
	}

	// Handle tagged attributes
	if attrDef.IsTagged() {
		if taggedValue, ok := value.(*TaggedValue); ok {
			// Validate tag
			if taggedValue.Tag == 0 || taggedValue.Tag > 0x1F {
				return nil, fmt.Errorf("invalid tag value: 0x%02X (must be 0x01-0x1F)", taggedValue.Tag)
			}

			// Build the tagged value: tag byte + actual value
			result := make([]byte, 1+len(taggedValue.Value))
			result[0] = taggedValue.Tag
			copy(result[1:], taggedValue.Value)
			return result, nil
		}
		return nil, fmt.Errorf("tagged attribute requires TaggedValue, got %T", value)
	}

	return dp.encodeValueByType(value, attrDef)
}

// BuildVSAValue builds a VSA attribute value
func (dp *DictionaryParser) BuildVSAValue(vendorID uint32, vendorType uint8, value interface{}) ([]byte, error) {
	if dp.dict == nil {
		return nil, fmt.Errorf("dictionary required for VSA encoding")
	}

	var attrDef *dictionary.AttributeDefinition
	var found bool

	if vendorAttrs, exists := dp.dict.VSAs[vendorID]; exists {
		if def, exists := vendorAttrs[vendorType]; exists {
			attrDef = def
			found = true
		}
	}

	if !found {
		// Assume raw bytes if no definition
		if data, ok := value.([]byte); ok {
			return dp.buildVSAHeader(vendorID, vendorType, data), nil
		}
		return nil, fmt.Errorf("unknown VSA %d:%d and value is not []byte", vendorID, vendorType)
	}

	valueBytes, err := dp.encodeValueByType(value, attrDef)
	if err != nil {
		return nil, err
	}

	return dp.buildVSAHeader(vendorID, vendorType, valueBytes), nil
}

// BuildTaggedAttributeValue builds a tagged attribute value
func (dp *DictionaryParser) BuildTaggedAttributeValue(attrType uint8, tag uint8, value interface{}) ([]byte, error) {
	if dp.dict == nil {
		return nil, fmt.Errorf("dictionary required for tagged attribute encoding")
	}

	// Validate tag
	if tag == 0 || tag > 0x1F {
		return nil, fmt.Errorf("invalid tag value: 0x%02X (must be 0x01-0x1F)", tag)
	}

	var attrDef *dictionary.AttributeDefinition
	var found bool

	if def, exists := dp.dict.Attributes[attrType]; exists {
		attrDef = def
		found = true
	}

	if !found {
		return nil, fmt.Errorf("unknown attribute type %d", attrType)
	}

	if !attrDef.IsTagged() {
		return nil, fmt.Errorf("attribute type %d is not tagged", attrType)
	}

	// Encode the actual value
	valueBytes, err := dp.encodeValueByType(value, attrDef)
	if err != nil {
		return nil, err
	}

	// Build tagged value: tag byte + actual value
	result := make([]byte, 1+len(valueBytes))
	result[0] = tag
	copy(result[1:], valueBytes)

	return result, nil
}

// GetAttributeName returns the name of an attribute based on its type
func (dp *DictionaryParser) GetAttributeName(attrType uint8) string {
	if dp.dict == nil {
		return fmt.Sprintf("Attr-%d", attrType)
	}

	if def, exists := dp.dict.Attributes[attrType]; exists {
		return def.Name
	}

	return fmt.Sprintf("Attr-%d", attrType)
}

// GetVSAName returns the name of a VSA attribute
func (dp *DictionaryParser) GetVSAName(vendorID uint32, vendorType uint8) string {
	if dp.dict == nil {
		return fmt.Sprintf("VSA-%d:%d", vendorID, vendorType)
	}

	if vendorAttrs, exists := dp.dict.VSAs[vendorID]; exists {
		if def, exists := vendorAttrs[vendorType]; exists {
			return def.Name
		}
	}

	// Try to get vendor name
	if vendor, exists := dp.dict.Vendors[vendorID]; exists {
		return fmt.Sprintf("%s-Attr-%d", vendor.Name, vendorType)
	}

	return fmt.Sprintf("VSA-%d:%d", vendorID, vendorType)
}

// ValidateAttribute validates an attribute according to its dictionary definition
func (dp *DictionaryParser) ValidateAttribute(attr Attribute) error {
	if dp.dict == nil {
		return nil // No validation without dictionary
	}

	var attrDef *dictionary.AttributeDefinition
	var found bool

	// Handle VSA
	if attr.Type == AttrVendorSpecific {
		vendorID, vendorType, err := dp.parseVSAHeader(attr.Value)
		if err != nil {
			return fmt.Errorf("invalid VSA header: %w", err)
		}

		if vendorAttrs, exists := dp.dict.VSAs[vendorID]; exists {
			if def, exists := vendorAttrs[vendorType]; exists {
				attrDef = def
				found = true
			}
		}
	} else {
		// Standard attribute
		if def, exists := dp.dict.Attributes[attr.Type]; exists {
			attrDef = def
			found = true
		}
	}

	if !found {
		return nil // Unknown attributes are allowed
	}

	// Validate length constraints
	valueLength := len(attr.Value)
	if attr.Type == AttrVendorSpecific {
		valueLength -= 6 // Subtract VSA header
	}

	if attrDef.Length > 0 && valueLength != attrDef.Length {
		return fmt.Errorf("attribute %s length mismatch: expected %d, got %d",
			attrDef.Name, attrDef.Length, valueLength)
	}

	return nil
}

// parseValueByType parses a value according to its data type
func (dp *DictionaryParser) parseValueByType(value []byte, attrDef *dictionary.AttributeDefinition) (interface{}, error) {
	dataType := attrDef.DataType

	// Handle fixed-length types (string[n], octets[n])
	if strings.Contains(string(dataType), "[") && strings.Contains(string(dataType), "]") {
		baseType := strings.Split(string(dataType), "[")[0]
		dataType = dictionary.DataType(baseType)
	}

	switch dataType {
	case dictionary.DataTypeString:
		return string(value), nil

	case dictionary.DataTypeOctets:
		return value, nil

	case dictionary.DataTypeInteger, dictionary.DataTypeUint32:
		if len(value) != 4 {
			return nil, fmt.Errorf("integer attribute must be 4 bytes, got %d", len(value))
		}
		val := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])

		// Check for named values
		if attrDef.Values != nil {
			for name, namedVal := range attrDef.Values {
				if namedVal == val {
					return name, nil
				}
			}
		}

		return val, nil

	case dictionary.DataTypeUint64:
		if len(value) != 8 {
			return nil, fmt.Errorf("uint64 attribute must be 8 bytes, got %d", len(value))
		}
		val := uint64(value[0])<<56 | uint64(value[1])<<48 | uint64(value[2])<<40 | uint64(value[3])<<32 |
			uint64(value[4])<<24 | uint64(value[5])<<16 | uint64(value[6])<<8 | uint64(value[7])
		return val, nil

	case dictionary.DataTypeDate:
		if len(value) != 4 {
			return nil, fmt.Errorf("date attribute must be 4 bytes, got %d", len(value))
		}
		timestamp := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
		return time.Unix(int64(timestamp), 0), nil

	case dictionary.DataTypeIPAddr:
		if len(value) != 4 {
			return nil, fmt.Errorf("ipaddr attribute must be 4 bytes, got %d", len(value))
		}
		return net.IP(value), nil

	case dictionary.DataTypeIPv6Addr:
		if len(value) != 16 {
			return nil, fmt.Errorf("ipv6addr attribute must be 16 bytes, got %d", len(value))
		}
		return net.IP(value), nil

	default:
		return value, nil
	}
}

// encodeValueByType encodes a value according to its data type
func (dp *DictionaryParser) encodeValueByType(value interface{}, attrDef *dictionary.AttributeDefinition) ([]byte, error) {
	dataType, fixedLength := dp.parseDataType(attrDef)

	switch dataType {
	case dictionary.DataTypeString:
		return dp.encodeStringValue(value, fixedLength)
	case dictionary.DataTypeOctets:
		return dp.encodeOctetsValue(value, fixedLength)
	case dictionary.DataTypeInteger, dictionary.DataTypeUint32:
		return dp.encodeIntegerValue(value, attrDef.Values)
	case dictionary.DataTypeUint64:
		return dp.encodeUint64Value(value)
	case dictionary.DataTypeDate:
		return dp.encodeDateValue(value)
	case dictionary.DataTypeIPAddr:
		return dp.encodeIPAddrValue(value)
	case dictionary.DataTypeIPv6Addr:
		return dp.encodeIPv6AddrValue(value)
	default:
		return dp.encodeRawValue(value, dataType)
	}
}

// parseDataType extracts the base data type and fixed length from attribute definition
func (dp *DictionaryParser) parseDataType(attrDef *dictionary.AttributeDefinition) (dictionary.DataType, int) {
	dataType := attrDef.DataType
	var fixedLength int

	// Handle fixed-length types - check both format string and explicit Length field
	if strings.Contains(string(dataType), "[") && strings.Contains(string(dataType), "]") {
		parts := strings.Split(string(dataType), "[")
		if len(parts) == 2 {
			lengthStr := strings.TrimSuffix(parts[1], "]")
			if length, err := strconv.Atoi(lengthStr); err == nil {
				fixedLength = length
			}
		}
		dataType = dictionary.DataType(parts[0])
	} else if attrDef.Length > 0 {
		// Use explicit Length field from attribute definition
		fixedLength = attrDef.Length
	}

	return dataType, fixedLength
}

// encodeStringValue encodes a string value with optional fixed length
func (dp *DictionaryParser) encodeStringValue(value interface{}, fixedLength int) ([]byte, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("expected string value for string attribute")
	}
	data := []byte(str)
	if fixedLength > 0 {
		if len(data) > fixedLength {
			return nil, fmt.Errorf("string value too long: %d > %d", len(data), fixedLength)
		}
		// Pad with zeros if needed
		if len(data) < fixedLength {
			padded := make([]byte, fixedLength)
			copy(padded, data)
			data = padded
		}
	}
	return data, nil
}

// encodeOctetsValue encodes an octets value with optional fixed length
func (dp *DictionaryParser) encodeOctetsValue(value interface{}, fixedLength int) ([]byte, error) {
	data, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected []byte value for octets attribute")
	}
	if fixedLength > 0 {
		if len(data) > fixedLength {
			return nil, fmt.Errorf("octets value too long: %d > %d", len(data), fixedLength)
		}
		// Pad with zeros if needed
		if len(data) < fixedLength {
			padded := make([]byte, fixedLength)
			copy(padded, data)
			data = padded
		}
	}
	return data, nil
}

// encodeIntegerValue encodes an integer value with named value support
func (dp *DictionaryParser) encodeIntegerValue(value interface{}, namedValues map[string]uint32) ([]byte, error) {
	var val uint32

	// Handle named values
	if str, ok := value.(string); ok && namedValues != nil {
		if namedVal, exists := namedValues[str]; exists {
			val = namedVal
		} else {
			return nil, fmt.Errorf("unknown named value: %s", str)
		}
	} else {
		switch v := value.(type) {
		case uint32:
			val = v
		case int:
			if v < 0 {
				return nil, fmt.Errorf("negative value not allowed for uint32: %d", v)
			}
			val = uint32(v)
		case int32:
			if v < 0 {
				return nil, fmt.Errorf("negative value not allowed for uint32: %d", v)
			}
			val = uint32(v)
		default:
			return nil, fmt.Errorf("unsupported value type for integer attribute: %T", value)
		}
	}

	return []byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}, nil
}

// encodeUint64Value encodes a uint64 value
func (dp *DictionaryParser) encodeUint64Value(value interface{}) ([]byte, error) {
	var val uint64
	switch v := value.(type) {
	case uint64:
		val = v
	case int:
		if v < 0 {
			return nil, fmt.Errorf("negative value not allowed for uint64: %d", v)
		}
		val = uint64(v)
	case int64:
		if v < 0 {
			return nil, fmt.Errorf("negative value not allowed for uint64: %d", v)
		}
		val = uint64(v)
	default:
		return nil, fmt.Errorf("unsupported value type for uint64 attribute: %T", value)
	}

	return []byte{
		byte(val >> 56), byte(val >> 48), byte(val >> 40), byte(val >> 32),
		byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val),
	}, nil
}

// encodeDateValue encodes a date value
func (dp *DictionaryParser) encodeDateValue(value interface{}) ([]byte, error) {
	var timestamp int64
	switch v := value.(type) {
	case time.Time:
		timestamp = v.Unix()
	case int64:
		timestamp = v
	case int:
		timestamp = int64(v)
	default:
		return nil, fmt.Errorf("unsupported value type for date attribute: %T", value)
	}

	val := uint32(timestamp)
	return []byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}, nil
}

// encodeIPAddrValue encodes an IPv4 address value
func (dp *DictionaryParser) encodeIPAddrValue(value interface{}) ([]byte, error) {
	var ip net.IP
	switch v := value.(type) {
	case net.IP:
		ip = v
	case string:
		ip = net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", v)
		}
	default:
		return nil, fmt.Errorf("unsupported value type for ipaddr attribute: %T", value)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("IP address must be IPv4")
	}
	return []byte(ip4), nil
}

// encodeIPv6AddrValue encodes an IPv6 address value
func (dp *DictionaryParser) encodeIPv6AddrValue(value interface{}) ([]byte, error) {
	var ip net.IP
	switch v := value.(type) {
	case net.IP:
		ip = v
	case string:
		ip = net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", v)
		}
	default:
		return nil, fmt.Errorf("unsupported value type for ipv6addr attribute: %T", value)
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return nil, fmt.Errorf("invalid IPv6 address")
	}
	return []byte(ip6), nil
}

// encodeRawValue encodes a raw value as fallback
func (dp *DictionaryParser) encodeRawValue(value interface{}, dataType dictionary.DataType) ([]byte, error) {
	if data, ok := value.([]byte); ok {
		return data, nil
	}
	return nil, fmt.Errorf("unsupported data type: %s", dataType)
}

// parseVSAHeader parses VSA header and returns vendor ID and vendor type
func (dp *DictionaryParser) parseVSAHeader(value []byte) (vendorID uint32, vendorType uint8, err error) {
	if len(value) < 6 {
		return 0, 0, fmt.Errorf("VSA value too short: %d bytes", len(value))
	}

	vendorID = uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	vendorType = value[4]
	vendorLength := value[5]

	if int(vendorLength) != len(value)-4 {
		return 0, 0, fmt.Errorf("VSA length mismatch: header says %d, actual %d", vendorLength, len(value)-4)
	}

	return vendorID, vendorType, nil
}

// buildVSAHeader builds VSA header
func (dp *DictionaryParser) buildVSAHeader(vendorID uint32, vendorType uint8, value []byte) []byte {
	vendorLength := uint8(len(value) + 2) // +2 for vendor-type and vendor-length
	header := make([]byte, 6+len(value))

	// Vendor ID (4 bytes)
	header[0] = byte(vendorID >> 24)
	header[1] = byte(vendorID >> 16)
	header[2] = byte(vendorID >> 8)
	header[3] = byte(vendorID)

	// Vendor Type (1 byte)
	header[4] = vendorType

	// Vendor Length (1 byte)
	header[5] = vendorLength

	// Value
	copy(header[6:], value)

	return header
}
