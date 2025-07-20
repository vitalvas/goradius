package packet

import (
	"errors"
	"fmt"
)

// Standard RADIUS attribute types are now provided via dictionary-based lookups
// Use the AttrXxx() functions from attributes.go instead of constants

// Attribute represents a RADIUS attribute as defined in RFC 2865
type Attribute struct {
	Type   uint8
	Length uint8
	Value  []byte
}

// NewAttribute creates a new attribute with the specified type and value
func NewAttribute(attrType uint8, value []byte) Attribute {
	return Attribute{
		Type:   attrType,
		Length: uint8(2 + len(value)), // Type(1) + Length(1) + Value(len)
		Value:  value,
	}
}

// NewStringAttribute creates a new attribute with a string value
func NewStringAttribute(attrType uint8, value string) Attribute {
	return NewAttribute(attrType, []byte(value))
}

// NewIntegerAttribute creates a new attribute with a 32-bit integer value
func NewIntegerAttribute(attrType uint8, value uint32) Attribute {
	data := make([]byte, 4)
	data[0] = byte(value >> 24)
	data[1] = byte(value >> 16)
	data[2] = byte(value >> 8)
	data[3] = byte(value)
	return NewAttribute(attrType, data)
}

// NewIPAddressAttribute creates a new attribute with an IPv4 address value
func NewIPAddressAttribute(attrType uint8, ip [4]byte) Attribute {
	return NewAttribute(attrType, ip[:])
}

// GetString returns the attribute value as a string
func (a *Attribute) GetString() string {
	return string(a.Value)
}

// GetInteger returns the attribute value as a 32-bit integer
func (a *Attribute) GetInteger() (uint32, error) {
	if len(a.Value) != 4 {
		return 0, fmt.Errorf("invalid integer attribute length: %d", len(a.Value))
	}
	return uint32(a.Value[0])<<24 | uint32(a.Value[1])<<16 | uint32(a.Value[2])<<8 | uint32(a.Value[3]), nil
}

// GetIPAddress returns the attribute value as an IPv4 address
func (a *Attribute) GetIPAddress() ([4]byte, error) {
	var ip [4]byte
	if len(a.Value) != 4 {
		return ip, fmt.Errorf("invalid IP address attribute length: %d", len(a.Value))
	}
	copy(ip[:], a.Value)
	return ip, nil
}

// GetBytes returns the attribute value as a byte slice
func (a *Attribute) GetBytes() []byte {
	return a.Value
}

// Validate performs basic attribute validation
func (a *Attribute) Validate() error {
	if a.Length < 2 {
		return errors.New("attribute length must be at least 2")
	}

	// Length field is uint8, so it can't exceed 255 - this check is redundant
	// Keeping the bounds check for clarity but removing the impossible condition

	expectedLength := 2 + len(a.Value)
	if int(a.Length) != expectedLength {
		return fmt.Errorf("attribute length %d does not match calculated length %d", a.Length, expectedLength)
	}

	// Validate specific attribute constraints
	switch a.Type {
	case AttrUserPassword:
		if len(a.Value) < 16 || len(a.Value) > 128 || len(a.Value)%16 != 0 {
			return errors.New("User-Password must be 16-128 octets and multiple of 16")
		}
	case AttrNASIPAddress, AttrFramedIPAddress, AttrFramedIPNetmask, AttrLoginIPHost:
		if len(a.Value) != 4 {
			return errors.New("IP address attributes must be 4 octets")
		}
	case AttrMessageAuthenticator:
		if len(a.Value) != 16 {
			return errors.New("Message-Authenticator must be 16 octets")
		}
	}

	return nil
}

// String returns a string representation of the attribute
func (a *Attribute) String() string {
	return fmt.Sprintf("Attr{Type=%d, Length=%d, Value=%d bytes}", a.Type, a.Length, len(a.Value))
}

// Copy creates a deep copy of the attribute
func (a *Attribute) Copy() Attribute {
	value := make([]byte, len(a.Value))
	copy(value, a.Value)
	return Attribute{
		Type:   a.Type,
		Length: a.Length,
		Value:  value,
	}
}

// IsVendorSpecific returns true if this is a Vendor-Specific attribute
func (a *Attribute) IsVendorSpecific() bool {
	return a.Type == AttrVendorSpecific
}

// GetVendorID returns the vendor ID for Vendor-Specific attributes
func (a *Attribute) GetVendorID() (uint32, error) {
	if !a.IsVendorSpecific() {
		return 0, errors.New("not a vendor-specific attribute")
	}

	if len(a.Value) < 4 {
		return 0, errors.New("vendor-specific attribute too short")
	}

	vendorID := uint32(a.Value[0])<<24 | uint32(a.Value[1])<<16 | uint32(a.Value[2])<<8 | uint32(a.Value[3])
	return vendorID, nil
}

// GetVendorData returns the vendor data for Vendor-Specific attributes
func (a *Attribute) GetVendorData() ([]byte, error) {
	if !a.IsVendorSpecific() {
		return nil, errors.New("not a vendor-specific attribute")
	}

	if len(a.Value) < 4 {
		return nil, errors.New("vendor-specific attribute too short")
	}

	return a.Value[4:], nil
}

// TaggedValue represents a tagged attribute value (RFC 2868)
type TaggedValue struct {
	Tag   uint8  // Tag field (0x01-0x1F)
	Value []byte // Actual attribute value
}

// NewTaggedAttribute creates a new tagged attribute
func NewTaggedAttribute(attrType uint8, tag uint8, value []byte) (Attribute, error) {
	if tag == 0 || tag > 0x1F {
		return Attribute{}, fmt.Errorf("invalid tag value: 0x%02X (must be 0x01-0x1F)", tag)
	}

	taggedValue := make([]byte, 1+len(value))
	taggedValue[0] = tag
	copy(taggedValue[1:], value)

	return NewAttribute(attrType, taggedValue), nil
}

// NewTaggedStringAttribute creates a new tagged attribute with string value
func NewTaggedStringAttribute(attrType uint8, tag uint8, value string) (Attribute, error) {
	return NewTaggedAttribute(attrType, tag, []byte(value))
}

// NewTaggedIntegerAttribute creates a new tagged attribute with integer value
func NewTaggedIntegerAttribute(attrType uint8, tag uint8, value uint32) (Attribute, error) {
	data := make([]byte, 4)
	data[0] = byte(value >> 24)
	data[1] = byte(value >> 16)
	data[2] = byte(value >> 8)
	data[3] = byte(value)
	return NewTaggedAttribute(attrType, tag, data)
}

// GetTaggedValue parses a tagged attribute value
func (a *Attribute) GetTaggedValue() (*TaggedValue, error) {
	if len(a.Value) == 0 {
		return nil, errors.New("tagged attribute cannot be empty")
	}

	tag := a.Value[0]
	if tag == 0 || tag > 0x1F {
		return nil, fmt.Errorf("invalid tag value: 0x%02X (must be 0x01-0x1F)", tag)
	}

	return &TaggedValue{
		Tag:   tag,
		Value: a.Value[1:],
	}, nil
}

// GetTaggedString returns the tagged value as a string
func (a *Attribute) GetTaggedString() (uint8, string, error) {
	tagged, err := a.GetTaggedValue()
	if err != nil {
		return 0, "", err
	}
	return tagged.Tag, string(tagged.Value), nil
}

// GetTaggedInteger returns the tagged value as an integer
func (a *Attribute) GetTaggedInteger() (uint8, uint32, error) {
	tagged, err := a.GetTaggedValue()
	if err != nil {
		return 0, 0, err
	}

	if len(tagged.Value) != 4 {
		return 0, 0, fmt.Errorf("invalid integer attribute length: %d", len(tagged.Value))
	}

	value := uint32(tagged.Value[0])<<24 | uint32(tagged.Value[1])<<16 |
		uint32(tagged.Value[2])<<8 | uint32(tagged.Value[3])

	return tagged.Tag, value, nil
}
