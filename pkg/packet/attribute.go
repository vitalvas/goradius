package packet

import (
	"fmt"
	"strconv"
	"strings"
)

// Attribute represents a RADIUS attribute per RFC 2865 Section 5
// Format: Type (1) + Length (1) + Value (variable)
type Attribute struct {
	Type   uint8
	Length uint8
	Value  []byte
	Tag    uint8 // For tagged attributes per RFC 2868 (0 = no tag)
}

// VendorAttribute represents a vendor-specific attribute (VSA) per RFC 2865 Section 5.26
// Format: Vendor-Id (4) + Vendor-Type (1) + Vendor-Length (1) + Value (variable)
type VendorAttribute struct {
	VendorID   uint32
	VendorType uint8
	Value      []byte
	Tag        uint8 // For tagged vendor attributes per RFC 2868 (0 = no tag)
}

// NewAttribute creates a new RADIUS attribute per RFC 2865 Section 5
// Note: value length must not exceed MaxAttributeValueLength (253 bytes)
func NewAttribute(attrType uint8, value []byte) *Attribute {
	return &Attribute{
		Type:   attrType,
		Length: uint8(len(value) + AttributeHeaderLength),
		Value:  value,
	}
}

// NewTaggedAttribute creates a new tagged RADIUS attribute per RFC 2868
// Note: value length must not exceed MaxAttributeValueLength-1 (252 bytes, accounting for tag byte)
func NewTaggedAttribute(attrType uint8, tag uint8, value []byte) *Attribute {
	// Per RFC 2868, the tag is the first byte of the value
	taggedValue := make([]byte, len(value)+1)
	taggedValue[0] = tag
	copy(taggedValue[1:], value)

	return &Attribute{
		Type:   attrType,
		Length: uint8(len(taggedValue) + AttributeHeaderLength),
		Value:  taggedValue,
		Tag:    tag,
	}
}

// NewVendorAttribute creates a new vendor-specific attribute per RFC 2865 Section 5.26
// Note: value length must not exceed MaxVSAValueLength (247 bytes)
func NewVendorAttribute(vendorID uint32, vendorType uint8, value []byte) *VendorAttribute {
	return &VendorAttribute{
		VendorID:   vendorID,
		VendorType: vendorType,
		Value:      value,
	}
}

// NewTaggedVendorAttribute creates a new tagged vendor-specific attribute per RFC 2868
// Note: value length must not exceed MaxVSAValueLength-1 (246 bytes, accounting for tag byte)
func NewTaggedVendorAttribute(vendorID uint32, vendorType uint8, tag uint8, value []byte) *VendorAttribute {
	// Per RFC 2868, the tag is the first byte of the value
	taggedValue := make([]byte, len(value)+1)
	taggedValue[0] = tag
	copy(taggedValue[1:], value)

	return &VendorAttribute{
		VendorID:   vendorID,
		VendorType: vendorType,
		Value:      taggedValue,
		Tag:        tag,
	}
}

// GetValue returns the attribute value (excluding tag for tagged attributes)
func (a *Attribute) GetValue() []byte {
	if a.Tag != 0 && len(a.Value) > 0 {
		// Skip the tag byte for tagged attributes
		return a.Value[1:]
	}
	return a.Value
}

// GetValue returns the vendor attribute value (excluding tag for tagged attributes)
func (va *VendorAttribute) GetValue() []byte {
	if va.Tag != 0 && len(va.Value) > 0 {
		// Skip the tag byte for tagged vendor attributes
		return va.Value[1:]
	}
	return va.Value
}

// hexTable is the hexadecimal encoding table for fast encoding
const hexTable = "0123456789abcdef"

// String returns a string representation of the attribute
func (a *Attribute) String() string {
	var value []byte
	if a.Tag != 0 {
		value = a.GetValue()
	} else {
		value = a.Value
	}

	// Calculate exact size needed
	size := 5 + 10 + 9 + 10 + 7 + len(value)*2 // "Type=" + max_uint8 + ", Length=" + max_uint8 + ", Value=" + hex
	if a.Tag != 0 {
		size += 6 + 10 // ", Tag=" + max_uint8
	}

	var b strings.Builder
	b.Grow(size)

	b.WriteString("Type=")
	b.WriteString(strconv.FormatUint(uint64(a.Type), 10))

	if a.Tag != 0 {
		b.WriteString(", Tag=")
		b.WriteString(strconv.FormatUint(uint64(a.Tag), 10))
	}

	b.WriteString(", Length=")
	b.WriteString(strconv.FormatUint(uint64(a.Length), 10))
	b.WriteString(", Value=")

	// Write hex directly to builder without allocating intermediate string
	for _, v := range value {
		b.WriteByte(hexTable[v>>4])
		b.WriteByte(hexTable[v&0x0f])
	}

	return b.String()
}

// String returns a string representation of the vendor attribute
func (va *VendorAttribute) String() string {
	var value []byte
	if va.Tag != 0 {
		value = va.GetValue()
	} else {
		value = va.Value
	}

	// Calculate exact size needed
	size := 9 + 10 + 7 + 3 + 8 + len(value)*2 // "VendorID=" + max_uint32 + ", Type=" + max_uint8 + ", Value=" + hex
	if va.Tag != 0 {
		size += 6 + 3 // ", Tag=" + max_uint8
	}

	var b strings.Builder
	b.Grow(size)

	b.WriteString("VendorID=")
	b.WriteString(strconv.FormatUint(uint64(va.VendorID), 10))
	b.WriteString(", Type=")
	b.WriteString(strconv.FormatUint(uint64(va.VendorType), 10))

	if va.Tag != 0 {
		b.WriteString(", Tag=")
		b.WriteString(strconv.FormatUint(uint64(va.Tag), 10))
	}

	b.WriteString(", Value=")

	// Write hex directly to builder without allocating intermediate string
	for _, v := range value {
		b.WriteByte(hexTable[v>>4])
		b.WriteByte(hexTable[v&0x0f])
	}

	return b.String()
}

// ToVSA converts a VendorAttribute to a standard Attribute (Type 26 - Vendor-Specific) per RFC 2865 Section 5.26
// Note: vendor value length must not exceed MaxVSAValueLength (247 bytes)
func (va *VendorAttribute) ToVSA() *Attribute {
	// Per RFC 2865 Section 5.26: Type(1) + Length(1) + Vendor-ID(4) + Vendor-Type(1) + Vendor-Length(1) + Vendor-Data
	vendorLength := uint8(len(va.Value) + 2)  // +2 for Vendor-Type and Vendor-Length
	vsaValue := make([]byte, 6+len(va.Value)) // 4 bytes Vendor-ID + 2 bytes header + data

	// Vendor-ID (4 bytes, big-endian)
	vsaValue[0] = uint8(va.VendorID >> 24)
	vsaValue[1] = uint8(va.VendorID >> 16)
	vsaValue[2] = uint8(va.VendorID >> 8)
	vsaValue[3] = uint8(va.VendorID)

	// Vendor-Type (1 byte)
	vsaValue[4] = va.VendorType

	// Vendor-Length (1 byte)
	vsaValue[5] = vendorLength

	// Vendor-Data
	copy(vsaValue[6:], va.Value)

	return &Attribute{
		Type:   26, // Vendor-Specific attribute type
		Length: uint8(len(vsaValue) + AttributeHeaderLength),
		Value:  vsaValue,
	}
}

// ParseVSA parses a Vendor-Specific Attribute (Type 26) into VendorAttribute per RFC 2865 Section 5.26
func ParseVSA(attr *Attribute) (*VendorAttribute, error) {
	if attr.Type != 26 {
		return nil, fmt.Errorf("not a vendor-specific attribute (type %d)", attr.Type)
	}

	if len(attr.Value) < 6 {
		return nil, fmt.Errorf("invalid VSA length: %d", len(attr.Value))
	}

	// Extract Vendor-ID (4 bytes, big-endian)
	vendorID := uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 | uint32(attr.Value[2])<<8 | uint32(attr.Value[3])

	// Extract Vendor-Type (1 byte)
	vendorType := attr.Value[4]

	// Extract Vendor-Length (1 byte)
	vendorLength := attr.Value[5]

	// Validate vendor length
	if int(vendorLength) != len(attr.Value)-4 {
		return nil, fmt.Errorf("invalid vendor length: %d, expected %d", vendorLength, len(attr.Value)-4)
	}

	// Extract vendor data
	vendorData := attr.Value[6:]

	va := &VendorAttribute{
		VendorID:   vendorID,
		VendorType: vendorType,
		Value:      vendorData,
	}

	// Check if this is a tagged vendor attribute
	if len(vendorData) > 0 && vendorData[0] <= 31 && vendorData[0] != 0 {
		// Potential tag (tags are 1-31, 0 means no tag)
		va.Tag = vendorData[0]
	}

	return va, nil
}
