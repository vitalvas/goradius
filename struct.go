package goradius

import (
	"fmt"
)

// fixedWidthFor returns the fixed encoded width in bytes for a scalar data type,
// or (0, false) if the type is variable-width. Struct members use these widths to
// lay out fields sequentially without per-field length headers.
func fixedWidthFor(dataType DataType) (int, bool) {
	switch dataType {
	case DataTypeByte:
		return 1, true
	case DataTypeShort:
		return 2, true
	case DataTypeInteger, DataTypeIPAddr, DataTypeDate, DataTypeSigned, DataTypeTimeDelta:
		return 4, true
	case DataTypeInteger64:
		return 8, true
	case DataTypeIPv6Addr:
		return 16, true
	case DataTypeIfID:
		return 8, true
	default:
		return 0, false
	}
}

// structMemberWidth returns the encoded width for a struct member. Fixed-width scalar
// types use their natural width; variable-width types (string, octets) require an
// explicit Size hint on the child definition.
func structMemberWidth(child *AttributeDefinition) (int, error) {
	if w, ok := fixedWidthFor(child.DataType); ok {
		return w, nil
	}
	if child.Size > 0 {
		return child.Size, nil
	}
	return 0, fmt.Errorf("struct member %q of type %q requires a Size hint", child.Name, child.DataType)
}

// isTrailingVariableMember reports whether a struct member is a variable-width
// type (string or octets) with no fixed Size. Such a member is only valid as
// the final member of a struct, where it consumes the remaining bytes. This
// matches layouts such as RFC 5580 Location-Information, whose trailing Method
// field is an open-ended string.
func isTrailingVariableMember(child *AttributeDefinition) bool {
	if _, fixed := fixedWidthFor(child.DataType); fixed {
		return false
	}
	if child.Size > 0 {
		return false
	}
	return child.DataType == DataTypeString || child.DataType == DataTypeOctets
}

// EncodeStruct encodes a map of child values into a fixed-layout struct byte stream.
// Members are written sequentially in the order their definitions appear in parent.Children,
// with no per-field type/length header. Every member must be supplied; fixed-width scalar
// types determine their own width, while sized variable-width members (string, octets) are
// zero-padded to their declared Size. A value longer than its declared Size is an error.
// A final string/octets member with no Size is a trailing member: it is written at its
// natural length and consumes the remainder of the struct.
func EncodeStruct(parent *AttributeDefinition, values map[string]any) ([]byte, error) {
	if parent == nil {
		return nil, fmt.Errorf("nil parent attribute")
	}

	out := make([]byte, 0, 16)
	for i, child := range parent.Children {
		raw, ok := values[child.Name]
		if !ok {
			return nil, fmt.Errorf("struct %q missing member %q", parent.Name, child.Name)
		}

		encoded, err := EncodeValue(processEnumeratedValueFor(raw, child), child.DataType)
		if err != nil {
			return nil, fmt.Errorf("failed to encode struct member %q: %w", child.Name, err)
		}

		if isTrailingVariableMember(child) {
			if i != len(parent.Children)-1 {
				return nil, fmt.Errorf("struct member %q of type %q without a Size must be the final member", child.Name, child.DataType)
			}
			out = append(out, encoded...)
			break
		}

		width, err := structMemberWidth(child)
		if err != nil {
			return nil, err
		}
		if _, fixed := fixedWidthFor(child.DataType); fixed {
			if len(encoded) != width {
				return nil, fmt.Errorf("struct member %q encoded to %d bytes, expected %d", child.Name, len(encoded), width)
			}
		} else if len(encoded) > width {
			// Variable-width member: zero-padded, but silent truncation loses data
			return nil, fmt.Errorf("struct member %q encoded to %d bytes, exceeds declared size %d", child.Name, len(encoded), width)
		}
		field := make([]byte, width)
		copy(field, encoded)
		out = append(out, field...)
	}

	return out, nil
}

// DecodeStruct decodes a fixed-layout struct byte stream into a map keyed by member name.
// Each member is read using its fixed width or declared Size, in definition order.
// Trailing bytes beyond the declared layout, or a stream too short for the layout, are errors.
func DecodeStruct(parent *AttributeDefinition, data []byte) (map[string]any, error) {
	if parent == nil {
		return nil, fmt.Errorf("nil parent attribute")
	}

	result := make(map[string]any)
	offset := 0
	for i, child := range parent.Children {
		// A final string/octets member with no Size consumes the remaining bytes.
		if isTrailingVariableMember(child) {
			if i != len(parent.Children)-1 {
				return nil, fmt.Errorf("struct member %q of type %q without a Size must be the final member", child.Name, child.DataType)
			}
			decoded, err := DecodeValue(data[offset:], child.DataType)
			if err != nil {
				return nil, fmt.Errorf("failed to decode struct member %q: %w", child.Name, err)
			}
			result[child.Name] = decoded
			offset = len(data)
			break
		}

		width, err := structMemberWidth(child)
		if err != nil {
			return nil, err
		}

		if offset+width > len(data) {
			return nil, fmt.Errorf("struct %q truncated: member %q needs %d bytes at offset %d, have %d", parent.Name, child.Name, width, offset, len(data)-offset)
		}

		field := data[offset : offset+width]
		decoded, err := DecodeValue(field, child.DataType)
		if err != nil {
			return nil, fmt.Errorf("failed to decode struct member %q: %w", child.Name, err)
		}
		result[child.Name] = decoded
		offset += width
	}

	if offset != len(data) {
		return nil, fmt.Errorf("struct %q has %d trailing bytes after layout", parent.Name, len(data)-offset)
	}

	return result, nil
}
