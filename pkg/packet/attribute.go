package packet

import (
	"fmt"
)

// Attribute represents a RADIUS attribute
type Attribute struct {
	Type   uint8
	Length uint8
	Value  []byte
	Tag    uint8 // For tagged attributes (0 = no tag)
}

// VendorAttribute represents a vendor-specific attribute (VSA)
type VendorAttribute struct {
	VendorID   uint32
	VendorType uint8
	Value      []byte
	Tag        uint8 // For tagged vendor attributes (0 = no tag)
}

// NewAttribute creates a new RADIUS attribute
func NewAttribute(attrType uint8, value []byte) *Attribute {
	return &Attribute{
		Type:   attrType,
		Length: uint8(len(value) + AttributeHeaderLength),
		Value:  value,
	}
}

// NewTaggedAttribute creates a new tagged RADIUS attribute
func NewTaggedAttribute(attrType uint8, tag uint8, value []byte) *Attribute {
	// For tagged attributes, the tag is the first byte of the value
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

// NewVendorAttribute creates a new vendor-specific attribute
func NewVendorAttribute(vendorID uint32, vendorType uint8, value []byte) *VendorAttribute {
	return &VendorAttribute{
		VendorID:   vendorID,
		VendorType: vendorType,
		Value:      value,
	}
}

// NewTaggedVendorAttribute creates a new tagged vendor-specific attribute
func NewTaggedVendorAttribute(vendorID uint32, vendorType uint8, tag uint8, value []byte) *VendorAttribute {
	// For tagged vendor attributes, the tag is the first byte of the value
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

// String returns a string representation of the attribute
func (a *Attribute) String() string {
	if a.Tag != 0 {
		return fmt.Sprintf("Type=%d, Tag=%d, Length=%d, Value=%x", a.Type, a.Tag, a.Length, a.GetValue())
	}
	return fmt.Sprintf("Type=%d, Length=%d, Value=%x", a.Type, a.Length, a.Value)
}

// String returns a string representation of the vendor attribute
func (va *VendorAttribute) String() string {
	if va.Tag != 0 {
		return fmt.Sprintf("VendorID=%d, Type=%d, Tag=%d, Value=%x", va.VendorID, va.VendorType, va.Tag, va.GetValue())
	}
	return fmt.Sprintf("VendorID=%d, Type=%d, Value=%x", va.VendorID, va.VendorType, va.Value)
}

// ToVSA converts a VendorAttribute to a standard Attribute (Type 26 - Vendor-Specific)
func (va *VendorAttribute) ToVSA() *Attribute {
	// VSA format: Type(1) + Length(1) + Vendor-ID(4) + Vendor-Type(1) + Vendor-Length(1) + Vendor-Data
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

// ParseVSA parses a Vendor-Specific Attribute (Type 26) into VendorAttribute
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
