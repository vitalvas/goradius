package goradius

import (
	"fmt"
)

// fixedWidthFor returns the fixed encoded width in bytes for a scalar data type,
// or (0, false) if the type is variable-width. Struct members use these widths to
// lay out fields sequentially without per-field length headers.
func fixedWidthFor(dataType DataType) (int, bool) {
	switch dataType {
	case DataTypeInteger, DataTypeIPAddr, DataTypeDate:
		return 4, true
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

// EncodeStruct encodes a map of child values into a fixed-layout struct byte stream.
// Members are written sequentially in the order their definitions appear in parent.Children,
// with no per-field type/length header. Every member must be supplied; fixed-width scalar
// types determine their own width, while variable-width members (string, octets) are padded
// or truncated to their declared Size.
func EncodeStruct(parent *AttributeDefinition, values map[string]any) ([]byte, error) {
	if parent == nil {
		return nil, fmt.Errorf("nil parent attribute")
	}

	var out []byte
	for _, child := range parent.Children {
		raw, ok := values[child.Name]
		if !ok {
			return nil, fmt.Errorf("struct %q missing member %q", parent.Name, child.Name)
		}

		width, err := structMemberWidth(child)
		if err != nil {
			return nil, err
		}

		encoded, err := EncodeValue(processEnumeratedValueFor(raw, child), child.DataType)
		if err != nil {
			return nil, fmt.Errorf("failed to encode struct member %q: %w", child.Name, err)
		}

		field := make([]byte, width)
		if _, fixed := fixedWidthFor(child.DataType); fixed {
			if len(encoded) != width {
				return nil, fmt.Errorf("struct member %q encoded to %d bytes, expected %d", child.Name, len(encoded), width)
			}
			copy(field, encoded)
		} else {
			// Variable-width member: copy up to Size bytes, zero-padded.
			copy(field, encoded)
		}

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
	for _, child := range parent.Children {
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
