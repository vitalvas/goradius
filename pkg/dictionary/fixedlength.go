package dictionary

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FixedLengthType represents a data type with optional fixed length constraint
type FixedLengthType struct {
	BaseType DataType
	Length   int
}

// String returns the string representation of the fixed-length type
func (flt FixedLengthType) String() string {
	if flt.Length > 0 {
		return fmt.Sprintf("%s[%d]", flt.BaseType, flt.Length)
	}
	return string(flt.BaseType)
}

// fixedLengthTypeRegex matches types like "string[10]", "octets[16]", etc.
var fixedLengthTypeRegex = regexp.MustCompile(`^([a-zA-Z0-9_]+)(?:\[(\d+)\])?$`)

// ParseFixedLengthType parses a string representation of a data type with optional fixed length
func ParseFixedLengthType(typeStr string) (FixedLengthType, error) {
	matches := fixedLengthTypeRegex.FindStringSubmatch(strings.TrimSpace(typeStr))
	if len(matches) < 2 {
		return FixedLengthType{}, fmt.Errorf("invalid type format: %s", typeStr)
	}

	baseType := DataType(matches[1])
	var length int

	// Parse fixed length if specified
	if len(matches) > 2 && matches[2] != "" {
		var err error
		length, err = strconv.Atoi(matches[2])
		if err != nil {
			return FixedLengthType{}, fmt.Errorf("invalid length specification: %s", matches[2])
		}

		if length <= 0 {
			return FixedLengthType{}, fmt.Errorf("length must be positive: %d", length)
		}
	}

	// Validate base type
	if !isValidDataType(baseType) {
		return FixedLengthType{}, fmt.Errorf("unsupported data type: %s", baseType)
	}

	result := FixedLengthType{
		BaseType: baseType,
		Length:   length,
	}

	// Validate length constraints for specific types
	if err := validateFixedLengthConstraints(result); err != nil {
		return FixedLengthType{}, err
	}

	return result, nil
}

// isValidDataType checks if a data type is supported
func isValidDataType(dataType DataType) bool {
	switch dataType {
	case DataTypeString, DataTypeOctets, DataTypeInteger, DataTypeUint32, DataTypeUint64,
		DataTypeDate, DataTypeIPAddr, DataTypeIPv6Addr:
		return true
	default:
		return false
	}
}

// validateFixedLengthConstraints validates length constraints for specific data types
func validateFixedLengthConstraints(flt FixedLengthType) error {
	switch flt.BaseType {
	case DataTypeString, DataTypeOctets:
		if flt.Length > 253 {
			return fmt.Errorf("%s attribute length cannot exceed 253 bytes", flt.BaseType)
		}

	case DataTypeInteger, DataTypeUint32, DataTypeDate:
		if flt.Length > 0 && flt.Length != 4 {
			return fmt.Errorf("%s attributes must be exactly 4 bytes", flt.BaseType)
		}

	case DataTypeUint64:
		if flt.Length > 0 && flt.Length != 8 {
			return fmt.Errorf("uint64 attributes must be exactly 8 bytes")
		}

	case DataTypeIPAddr:
		if flt.Length > 0 && flt.Length != 4 {
			return fmt.Errorf("ipaddr attributes must be exactly 4 bytes")
		}

	case DataTypeIPv6Addr:
		if flt.Length > 0 && flt.Length != 16 {
			return fmt.Errorf("ipv6addr attributes must be exactly 16 bytes")
		}
	}

	return nil
}

// GetNaturalLength returns the natural length for fixed-size types
func (flt FixedLengthType) GetNaturalLength() int {
	switch flt.BaseType {
	case DataTypeInteger, DataTypeUint32, DataTypeDate, DataTypeIPAddr:
		return 4
	case DataTypeUint64:
		return 8
	case DataTypeIPv6Addr:
		return 16
	default:
		return 0 // Variable length
	}
}

// IsVariableLength returns true if the type has variable length
func (flt FixedLengthType) IsVariableLength() bool {
	return flt.Length == 0 && flt.GetNaturalLength() == 0
}

// GetEffectiveLength returns the effective length (specified or natural)
func (flt FixedLengthType) GetEffectiveLength() int {
	if flt.Length > 0 {
		return flt.Length
	}
	return flt.GetNaturalLength()
}

// ValidateValueLength validates that a value has the correct length
func (flt FixedLengthType) ValidateValueLength(value []byte) error {
	expectedLength := flt.GetEffectiveLength()
	if expectedLength > 0 && len(value) != expectedLength {
		return fmt.Errorf("value length %d does not match expected length %d for type %s",
			len(value), expectedLength, flt.String())
	}
	return nil
}

// PadValue pads a value to the required length for string and octets types
func (flt FixedLengthType) PadValue(value []byte) []byte {
	if flt.Length == 0 {
		return value
	}

	switch flt.BaseType {
	case DataTypeString:
		// Pad strings with null bytes
		if len(value) < flt.Length {
			padded := make([]byte, flt.Length)
			copy(padded, value)
			return padded
		}

	case DataTypeOctets:
		// Pad octets with zero bytes
		if len(value) < flt.Length {
			padded := make([]byte, flt.Length)
			copy(padded, value)
			return padded
		}
	}

	return value
}

// TrimValue trims padding from a value for string and octets types
func (flt FixedLengthType) TrimValue(value []byte) []byte {
	if flt.Length == 0 {
		return value
	}

	switch flt.BaseType {
	case DataTypeString:
		// Trim null bytes from the end
		for i := len(value) - 1; i >= 0; i-- {
			if value[i] != 0 {
				return value[:i+1]
			}
		}
		return []byte{}

	case DataTypeOctets:
		// Don't trim octets as they may contain meaningful zeros
		return value
	}

	return value
}

// Enhanced attribute definition methods

// GetFixedLengthType returns the parsed fixed-length type for the attribute
func (attr *AttributeDefinition) GetFixedLengthType() FixedLengthType {
	return FixedLengthType{
		BaseType: attr.DataType,
		Length:   attr.Length,
	}
}

// ValidateFixedLengthValue validates a value against fixed-length constraints
func (attr *AttributeDefinition) ValidateFixedLengthValue(value []byte) error {
	flt := attr.GetFixedLengthType()

	// First validate the basic value
	if err := attr.ValidateValue(value); err != nil {
		return err
	}

	// Then validate length constraints
	return flt.ValidateValueLength(value)
}

// PadAttributeValue pads a value to the required length if needed
func (attr *AttributeDefinition) PadAttributeValue(value []byte) []byte {
	flt := attr.GetFixedLengthType()
	return flt.PadValue(value)
}

// TrimAttributeValue trims padding from a value if needed
func (attr *AttributeDefinition) TrimAttributeValue(value []byte) []byte {
	flt := attr.GetFixedLengthType()
	return flt.TrimValue(value)
}

// GetMinimumLength returns the minimum length for the attribute
func (attr *AttributeDefinition) GetMinimumLength() int {
	switch attr.DataType {
	case DataTypeString, DataTypeOctets:
		if attr.Length > 0 {
			return attr.Length
		}
		return 0
	case DataTypeInteger, DataTypeUint32, DataTypeDate, DataTypeIPAddr:
		return 4
	case DataTypeUint64:
		return 8
	case DataTypeIPv6Addr:
		return 16
	default:
		return 0
	}
}

// GetMaximumLength returns the maximum length for the attribute
func (attr *AttributeDefinition) GetMaximumLength() int {
	switch attr.DataType {
	case DataTypeString, DataTypeOctets:
		if attr.Length > 0 {
			return attr.Length
		}
		return 253 // Maximum RADIUS attribute value length
	case DataTypeInteger, DataTypeUint32, DataTypeDate, DataTypeIPAddr:
		return 4
	case DataTypeUint64:
		return 8
	case DataTypeIPv6Addr:
		return 16
	default:
		return 253
	}
}

// IsExactLength returns true if the attribute must have an exact length
func (attr *AttributeDefinition) IsExactLength() bool {
	return attr.Length > 0 || attr.GetFixedLengthType().GetNaturalLength() > 0
}

// FormatValue formats a value for display, handling fixed-length types appropriately
func (attr *AttributeDefinition) FormatValue(value []byte) string {
	flt := attr.GetFixedLengthType()

	// Trim value if it's a fixed-length type
	if flt.Length > 0 {
		value = flt.TrimValue(value)
	}

	switch attr.DataType {
	case DataTypeString:
		return string(value)
	case DataTypeOctets:
		return fmt.Sprintf("0x%x", value)
	case DataTypeInteger, DataTypeUint32:
		if len(value) == 4 {
			val := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
			return fmt.Sprintf("%d", val)
		}
		return fmt.Sprintf("0x%x", value)
	case DataTypeUint64:
		if len(value) == 8 {
			val := uint64(value[0])<<56 | uint64(value[1])<<48 | uint64(value[2])<<40 | uint64(value[3])<<32 |
				uint64(value[4])<<24 | uint64(value[5])<<16 | uint64(value[6])<<8 | uint64(value[7])
			return fmt.Sprintf("%d", val)
		}
		return fmt.Sprintf("0x%x", value)
	case DataTypeIPAddr:
		if len(value) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", value[0], value[1], value[2], value[3])
		}
		return fmt.Sprintf("0x%x", value)
	case DataTypeIPv6Addr:
		if len(value) == 16 {
			return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				uint16(value[0])<<8|uint16(value[1]),
				uint16(value[2])<<8|uint16(value[3]),
				uint16(value[4])<<8|uint16(value[5]),
				uint16(value[6])<<8|uint16(value[7]),
				uint16(value[8])<<8|uint16(value[9]),
				uint16(value[10])<<8|uint16(value[11]),
				uint16(value[12])<<8|uint16(value[13]),
				uint16(value[14])<<8|uint16(value[15]))
		}
		return fmt.Sprintf("0x%x", value)
	default:
		return fmt.Sprintf("0x%x", value)
	}
}
