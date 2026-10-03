package goradius

import (
	"fmt"
)

// RFC 6929 extended attribute wire-format constants.
const (
	// ExtendedHeaderLength is the on-wire header of a short extended attribute:
	// Type(1) + Length(1) + Extended-Type(1).
	ExtendedHeaderLength = 3
	// LongExtendedHeaderLength is the on-wire header of a long extended attribute:
	// Type(1) + Length(1) + Extended-Type(1) + Flags(1).
	LongExtendedHeaderLength = 4
	// MaxShortExtendedValueLength is the maximum value carried by a single short
	// extended attribute: 255 - Type - Length - Extended-Type.
	MaxShortExtendedValueLength = 252
	// MaxLongExtendedValueLength is the maximum value carried by a single long
	// extended attribute fragment: 255 - Type - Length - Extended-Type - Flags.
	MaxLongExtendedValueLength = 251
	// LongExtendedMoreBit is the More (M) flag in the Flags byte of a long extended
	// attribute, set on every fragment except the last.
	LongExtendedMoreBit = 0x80
)

// NewExtendedAttribute builds a short extended attribute (RFC 6929 Section 2.1) for
// base types 241-244. The resulting *Attribute carries the extended-type byte as the
// first byte of its value, so the standard packet encoder emits the correct wire format:
// Type(1) + Length(1) + Extended-Type(1) + Value.
func NewExtendedAttribute(baseType, extType uint8, value []byte) (*Attribute, error) {
	if !IsExtendedBaseType(baseType) || IsLongExtendedBaseType(baseType) {
		return nil, fmt.Errorf("invalid short extended base type %d (must be 241-244)", baseType)
	}
	if len(value) > MaxShortExtendedValueLength {
		return nil, fmt.Errorf("short extended value length %d exceeds maximum %d bytes", len(value), MaxShortExtendedValueLength)
	}

	data := make([]byte, 1+len(value))
	data[0] = extType
	copy(data[1:], value)

	return &Attribute{
		Type:   baseType,
		Length: uint8(len(data) + AttributeHeaderLength),
		Value:  data,
	}, nil
}

// ParseExtendedAttribute extracts the extended type and value from a short extended
// attribute. The attribute's Type must be a short extended base type (241-244).
func ParseExtendedAttribute(attr *Attribute) (extType uint8, value []byte, err error) {
	if !IsExtendedBaseType(attr.Type) || IsLongExtendedBaseType(attr.Type) {
		return 0, nil, fmt.Errorf("attribute type %d is not a short extended type (241-244)", attr.Type)
	}
	if len(attr.Value) < 1 {
		return 0, nil, fmt.Errorf("short extended attribute too short: %d bytes", len(attr.Value))
	}
	return attr.Value[0], attr.Value[1:], nil
}

// NewLongExtendedAttributes builds one or more long extended attributes (RFC 6929
// Section 2.2) for base types 245-246, fragmenting the value across multiple attribute
// instances when it exceeds MaxLongExtendedValueLength. Every fragment but the last has
// the More bit set in its Flags byte. Wire format per fragment:
// Type(1) + Length(1) + Extended-Type(1) + Flags(1) + Value.
func NewLongExtendedAttributes(baseType, extType uint8, value []byte) ([]*Attribute, error) {
	if !IsLongExtendedBaseType(baseType) {
		return nil, fmt.Errorf("invalid long extended base type %d (must be 245-246)", baseType)
	}

	fragments := max((len(value)+MaxLongExtendedValueLength-1)/MaxLongExtendedValueLength, 1)
	attrs := make([]*Attribute, 0, fragments)
	remaining := value
	for {
		chunk := remaining
		more := false
		if len(chunk) > MaxLongExtendedValueLength {
			chunk = remaining[:MaxLongExtendedValueLength]
			remaining = remaining[MaxLongExtendedValueLength:]
			more = true
		} else {
			remaining = nil
		}

		data := make([]byte, 2+len(chunk))
		data[0] = extType
		if more {
			data[1] = LongExtendedMoreBit
		}
		copy(data[2:], chunk)

		attrs = append(attrs, &Attribute{
			Type:   baseType,
			Length: uint8(len(data) + AttributeHeaderLength),
			Value:  data,
		})

		if !more {
			break
		}
	}

	return attrs, nil
}

// parseLongExtendedFragment extracts the extended type, More bit, and value fragment
// from a single long extended attribute.
func parseLongExtendedFragment(attr *Attribute) (extType uint8, more bool, value []byte, err error) {
	if !IsLongExtendedBaseType(attr.Type) {
		return 0, false, nil, fmt.Errorf("attribute type %d is not a long extended type (245-246)", attr.Type)
	}
	if len(attr.Value) < 2 {
		return 0, false, nil, fmt.Errorf("long extended attribute too short: %d bytes", len(attr.Value))
	}
	extType = attr.Value[0]
	more = attr.Value[1]&LongExtendedMoreBit != 0
	value = attr.Value[2:]
	return extType, more, value, nil
}
