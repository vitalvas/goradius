package packet

import (
	"errors"
	"fmt"
)

const (
	// PacketHeaderLength is the length of the RADIUS packet header in bytes
	PacketHeaderLength = 20
	// MaxPacketLength is the maximum allowed RADIUS packet length
	MaxPacketLength = 4096
	// MinPacketLength is the minimum allowed RADIUS packet length
	MinPacketLength = PacketHeaderLength
	// AuthenticatorLength is the length of the authenticator field
	AuthenticatorLength = 16
)

// Packet represents a RADIUS packet as defined in RFC 2865
type Packet struct {
	Code          Code
	Identifier    uint8
	Length        uint16
	Authenticator [AuthenticatorLength]byte
	Attributes    []Attribute
}

// New creates a new RADIUS packet with the specified code and identifier
func New(code Code, identifier uint8) *Packet {
	return &Packet{
		Code:       code,
		Identifier: identifier,
		Length:     PacketHeaderLength,
		Attributes: make([]Attribute, 0),
	}
}

// AddAttribute adds an attribute to the packet
func (p *Packet) AddAttribute(attr Attribute) {
	p.Attributes = append(p.Attributes, attr)
	p.Length += uint16(attr.Length)
}

// GetAttribute returns the first attribute with the specified type
func (p *Packet) GetAttribute(attrType uint8) (Attribute, bool) {
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			return attr, true
		}
	}
	return Attribute{}, false
}

// GetAttributes returns all attributes with the specified type
func (p *Packet) GetAttributes(attrType uint8) []Attribute {
	var attrs []Attribute
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			attrs = append(attrs, attr)
		}
	}
	return attrs
}

// RemoveAttribute removes the first attribute with the specified type
func (p *Packet) RemoveAttribute(attrType uint8) bool {
	for i, attr := range p.Attributes {
		if attr.Type == attrType {
			p.Length -= uint16(attr.Length)
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
			return true
		}
	}
	return false
}

// RemoveAllAttributes removes all attributes with the specified type
func (p *Packet) RemoveAllAttributes(attrType uint8) int {
	var removed int
	for i := len(p.Attributes) - 1; i >= 0; i-- {
		if p.Attributes[i].Type == attrType {
			p.Length -= uint16(p.Attributes[i].Length)
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
			removed++
		}
	}
	return removed
}

// GetTaggedAttribute returns the first tagged attribute with the specified type and tag
func (p *Packet) GetTaggedAttribute(attrType uint8, tag uint8) (Attribute, bool) {
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			if taggedValue, err := attr.GetTaggedValue(); err == nil && taggedValue.Tag == tag {
				return attr, true
			}
		}
	}
	return Attribute{}, false
}

// GetTaggedAttributes returns all tagged attributes with the specified type and tag
func (p *Packet) GetTaggedAttributes(attrType uint8, tag uint8) []Attribute {
	var attrs []Attribute
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			if taggedValue, err := attr.GetTaggedValue(); err == nil && taggedValue.Tag == tag {
				attrs = append(attrs, attr)
			}
		}
	}
	return attrs
}

// GetAllTaggedAttributes returns all tagged attributes with the specified type, grouped by tag
func (p *Packet) GetAllTaggedAttributes(attrType uint8) map[uint8][]Attribute {
	result := make(map[uint8][]Attribute)
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			if taggedValue, err := attr.GetTaggedValue(); err == nil {
				result[taggedValue.Tag] = append(result[taggedValue.Tag], attr)
			}
		}
	}
	return result
}

// RemoveTaggedAttribute removes the first tagged attribute with the specified type and tag
func (p *Packet) RemoveTaggedAttribute(attrType uint8, tag uint8) bool {
	for i, attr := range p.Attributes {
		if attr.Type == attrType {
			if taggedValue, err := attr.GetTaggedValue(); err == nil && taggedValue.Tag == tag {
				p.Length -= uint16(attr.Length)
				p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
				return true
			}
		}
	}
	return false
}

// Validate performs basic packet validation
func (p *Packet) Validate() error {
	if p.Length < MinPacketLength {
		return fmt.Errorf("packet length %d is less than minimum %d", p.Length, MinPacketLength)
	}

	if p.Length > MaxPacketLength {
		return fmt.Errorf("packet length %d exceeds maximum %d", p.Length, MaxPacketLength)
	}

	// Calculate expected length from attributes
	expectedLength := PacketHeaderLength
	for _, attr := range p.Attributes {
		if err := attr.Validate(); err != nil {
			return fmt.Errorf("invalid attribute: %w", err)
		}
		expectedLength += int(attr.Length)
	}

	if p.Length != uint16(expectedLength) {
		return fmt.Errorf("packet length %d does not match calculated length %d", p.Length, expectedLength)
	}

	return nil
}

// Copy creates a deep copy of the packet
func (p *Packet) Copy() *Packet {
	newPacket := &Packet{
		Code:          p.Code,
		Identifier:    p.Identifier,
		Length:        p.Length,
		Authenticator: p.Authenticator,
		Attributes:    make([]Attribute, len(p.Attributes)),
	}

	for i, attr := range p.Attributes {
		newPacket.Attributes[i] = attr.Copy()
	}
	return newPacket
}

// String returns a string representation of the packet
func (p *Packet) String() string {
	return fmt.Sprintf("RADIUS Packet: Code=%s, ID=%d, Length=%d, Attributes=%d",
		p.Code.String(), p.Identifier, p.Length, len(p.Attributes))
}

var (
	// ErrInvalidPacketLength indicates the packet length is invalid
	ErrInvalidPacketLength = errors.New("invalid packet length")
	// ErrInvalidCode indicates the packet code is invalid
	ErrInvalidCode = errors.New("invalid packet code")
	// ErrPacketTooShort indicates the packet is too short
	ErrPacketTooShort = errors.New("packet too short")
	// ErrPacketTooLong indicates the packet is too long
	ErrPacketTooLong = errors.New("packet too long")
)
