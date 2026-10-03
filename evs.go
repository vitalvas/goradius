package goradius

import (
	"fmt"
)

// Extended-Vendor-Specific (EVS) wire-format constants per RFC 6929 Section 2.5.
const (
	// EVSExtendedType is the reserved extended type (26) that marks an
	// Extended-Vendor-Specific attribute.
	EVSExtendedType = 26
	// EVSVendorHeaderLength is the EVS vendor header after the extended-type byte:
	// Vendor-Id(4) + Vendor-Type(1).
	EVSVendorHeaderLength = 5
)

// NewEVSAttribute builds a short Extended-Vendor-Specific attribute (RFC 6929
// Section 2.5) for base types 241-244. The extended type is fixed at 26 (EVS) and the
// value is prefixed with the 4-byte Vendor-Id and 1-byte Vendor-Type. Wire format:
// Type(1) + Length(1) + Extended-Type(1=26) + Vendor-Id(4) + Vendor-Type(1) + Value.
func NewEVSAttribute(baseType uint8, vendorID uint32, vendorType uint8, value []byte) (*Attribute, error) {
	if !IsExtendedBaseType(baseType) || IsLongExtendedBaseType(baseType) {
		return nil, fmt.Errorf("invalid EVS base type %d (must be 241-244)", baseType)
	}

	payload := make([]byte, EVSVendorHeaderLength+len(value))
	payload[0] = byte(vendorID >> 24)
	payload[1] = byte(vendorID >> 16)
	payload[2] = byte(vendorID >> 8)
	payload[3] = byte(vendorID)
	payload[4] = vendorType
	copy(payload[EVSVendorHeaderLength:], value)

	return NewExtendedAttribute(baseType, EVSExtendedType, payload)
}

// ParseEVS extracts the Vendor-Id, Vendor-Type, and value from a short EVS attribute.
func ParseEVS(attr *Attribute) (vendorID uint32, vendorType uint8, value []byte, err error) {
	extType, payload, err := ParseExtendedAttribute(attr)
	if err != nil {
		return 0, 0, nil, err
	}
	if extType != EVSExtendedType {
		return 0, 0, nil, fmt.Errorf("attribute extended type %d is not EVS (%d)", extType, EVSExtendedType)
	}
	if len(payload) < EVSVendorHeaderLength {
		return 0, 0, nil, fmt.Errorf("EVS payload too short: %d bytes", len(payload))
	}

	vendorID = uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	vendorType = payload[4]
	value = payload[EVSVendorHeaderLength:]
	return vendorID, vendorType, value, nil
}
