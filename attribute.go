package goradius

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

	// encryption and encryptOffset defer value encryption until the packet
	// authenticator is final. When encryption is non-empty, the bytes of Value
	// from encryptOffset onward are plaintext and are encrypted in place by
	// Packet.finalizeEncryption just before the packet is serialized. The
	// offset skips any leading tag octet and, for a VSA, the vendor header.
	// A zero encryption means the value is already final.
	//
	// vsaLengthPos and vsaLengthWidth locate the VSA Vendor-Length field within
	// Value (0 width means this is not a VSA), so the length can be rewritten
	// after encryption changes the inner data size.
	encryption     EncryptionType
	encryptOffset  int
	vsaLengthPos   int
	vsaLengthWidth int
}

// VendorAttribute represents a vendor-specific attribute (VSA) per RFC 2865 Section 5.26
// Format: Vendor-Id (4) + Vendor-Type (1) + Vendor-Length (1) + Value (variable).
// VendorType is widened to uint32 to carry vendors that use a 2-octet type
// field (FreeRADIUS "format=2,1", e.g. Alcatel-ESAM).
type VendorAttribute struct {
	VendorID   uint32
	VendorType uint32
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
func NewVendorAttribute(vendorID uint32, vendorType uint32, value []byte) *VendorAttribute {
	return &VendorAttribute{
		VendorID:   vendorID,
		VendorType: vendorType,
		Value:      value,
	}
}

// NewTaggedVendorAttribute creates a new tagged vendor-specific attribute per RFC 2868
// Note: value length must not exceed MaxVSAValueLength-1 (246 bytes, accounting for tag byte)
func NewTaggedVendorAttribute(vendorID uint32, vendorType uint32, tag uint8, value []byte) *VendorAttribute {
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

// ToVSA converts a VendorAttribute to a standard Attribute (Type 26 - Vendor-Specific)
// using the RFC 2865 Section 5.26 format (1-octet type, 1-octet length).
// Note: vendor value length must not exceed MaxVSAValueLength (247 bytes)
func (va *VendorAttribute) ToVSA() *Attribute {
	return va.ToVSAFormat(1, 1)
}

// ToVSAFormat converts a VendorAttribute to a standard Attribute (Type 26) using
// a vendor-specific header format: typeOctets wide Vendor-Type field and
// lengthOctets wide Vendor-Length field (0 means the vendor carries no length
// field). The fields are big-endian. This supports vendors whose VSA layout
// differs from RFC 2865, matching the FreeRADIUS "format=t,l" flag.
func (va *VendorAttribute) ToVSAFormat(typeOctets, lengthOctets int) *Attribute {
	header := typeOctets + lengthOctets
	vsaValue := make([]byte, 4+header+len(va.Value))

	// Vendor-ID (4 bytes, big-endian)
	vsaValue[0] = uint8(va.VendorID >> 24)
	vsaValue[1] = uint8(va.VendorID >> 16)
	vsaValue[2] = uint8(va.VendorID >> 8)
	vsaValue[3] = uint8(va.VendorID)

	// Vendor-Type (typeOctets bytes, big-endian)
	for i := 0; i < typeOctets; i++ {
		shift := uint(8 * (typeOctets - 1 - i))
		vsaValue[4+i] = uint8(va.VendorType >> shift)
	}

	// Vendor-Length (lengthOctets bytes, big-endian) counts the type, length,
	// and data octets, per the RFC 2865 convention.
	vendorLength := header + len(va.Value)
	for i := 0; i < lengthOctets; i++ {
		shift := uint(8 * (lengthOctets - 1 - i))
		vsaValue[4+typeOctets+i] = uint8(uint(vendorLength) >> shift)
	}

	// Vendor-Data
	copy(vsaValue[4+header:], va.Value)

	return &Attribute{
		Type:   26, // Vendor-Specific attribute type
		Length: uint8(len(vsaValue) + AttributeHeaderLength),
		Value:  vsaValue,
	}
}

// ParseVSA parses a Vendor-Specific Attribute (Type 26) into VendorAttribute
// using the RFC 2865 Section 5.26 format (1-octet type, 1-octet length).
func ParseVSA(attr *Attribute) (*VendorAttribute, error) {
	return ParseVSAFormat(attr, 1, 1)
}

// ParseVSAFormat parses a Vendor-Specific Attribute (Type 26) using a
// vendor-specific header format: typeOctets wide Vendor-Type and lengthOctets
// wide Vendor-Length (0 means no length field). The fields are big-endian.
func ParseVSAFormat(attr *Attribute, typeOctets, lengthOctets int) (*VendorAttribute, error) {
	if attr.Type != 26 {
		return nil, fmt.Errorf("not a vendor-specific attribute (type %d)", attr.Type)
	}

	header := typeOctets + lengthOctets
	if len(attr.Value) < 4+header {
		return nil, fmt.Errorf("invalid VSA length: %d", len(attr.Value))
	}

	// Extract Vendor-ID (4 bytes, big-endian)
	vendorID := uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 | uint32(attr.Value[2])<<8 | uint32(attr.Value[3])

	// Extract Vendor-Type (typeOctets bytes, big-endian)
	var vendorType uint32
	for i := 0; i < typeOctets; i++ {
		vendorType = vendorType<<8 | uint32(attr.Value[4+i])
	}

	// Extract and validate Vendor-Length when present
	if lengthOctets > 0 {
		var vendorLength int
		for i := 0; i < lengthOctets; i++ {
			vendorLength = vendorLength<<8 | int(attr.Value[4+typeOctets+i])
		}
		if vendorLength != len(attr.Value)-4 {
			return nil, fmt.Errorf("invalid vendor length: %d, expected %d", vendorLength, len(attr.Value)-4)
		}
	}

	// Extract vendor data
	vendorData := attr.Value[4+header:]

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
