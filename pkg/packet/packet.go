package packet

import (
	"crypto/md5"
	"fmt"

	"github.com/vitalvas/goradius/pkg/dictionary"
)

// Packet represents a RADIUS packet as defined in RFC 2865
type Packet struct {
	Code          Code
	Identifier    uint8
	Length        uint16
	Authenticator [AuthenticatorLength]byte
	Attributes    []*Attribute
	Dict          *dictionary.Dictionary // Optional dictionary for attribute lookups
}

// New creates a new RADIUS packet with the specified code and identifier
func New(code Code, identifier uint8) *Packet {
	return &Packet{
		Code:       code,
		Identifier: identifier,
		Length:     PacketHeaderLength,
		Attributes: make([]*Attribute, 0),
	}
}

// NewWithDictionary creates a new RADIUS packet with dictionary support
func NewWithDictionary(code Code, identifier uint8, dict *dictionary.Dictionary) *Packet {
	p := New(code, identifier)
	p.Dict = dict
	return p
}

// AddAttribute adds an attribute to the packet
func (p *Packet) AddAttribute(attr *Attribute) {
	p.Attributes = append(p.Attributes, attr)
	p.Length += uint16(attr.Length)
}

// AddVendorAttribute adds a vendor-specific attribute to the packet
func (p *Packet) AddVendorAttribute(va *VendorAttribute) {
	attr := va.ToVSA()
	p.AddAttribute(attr)
}

// GetAttribute returns the first attribute with the specified type
func (p *Packet) GetAttribute(attrType uint8) (*Attribute, bool) {
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			return attr, true
		}
	}
	return nil, false
}

// GetAttributes returns all attributes with the specified type
func (p *Packet) GetAttributes(attrType uint8) []*Attribute {
	var attrs []*Attribute
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			attrs = append(attrs, attr)
		}
	}
	return attrs
}

// GetVendorAttribute returns the first vendor attribute with the specified vendor ID and type
func (p *Packet) GetVendorAttribute(vendorID uint32, vendorType uint8) (*VendorAttribute, bool) {
	for _, attr := range p.Attributes {
		if attr.Type == 26 { // Vendor-Specific
			if va, err := ParseVSA(attr); err == nil {
				if va.VendorID == vendorID && va.VendorType == vendorType {
					return va, true
				}
			}
		}
	}
	return nil, false
}

// GetVendorAttributes returns all vendor attributes with the specified vendor ID and type
func (p *Packet) GetVendorAttributes(vendorID uint32, vendorType uint8) []*VendorAttribute {
	var attrs []*VendorAttribute
	for _, attr := range p.Attributes {
		if attr.Type == 26 { // Vendor-Specific
			if va, err := ParseVSA(attr); err == nil {
				if va.VendorID == vendorID && va.VendorType == vendorType {
					attrs = append(attrs, va)
				}
			}
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

// RemoveAttributes removes all attributes with the specified type
func (p *Packet) RemoveAttributes(attrType uint8) int {
	removed := 0
	for i := len(p.Attributes) - 1; i >= 0; i-- {
		if p.Attributes[i].Type == attrType {
			p.Length -= uint16(p.Attributes[i].Length)
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
			removed++
		}
	}
	return removed
}

// SetAuthenticator sets the packet authenticator
func (p *Packet) SetAuthenticator(auth [AuthenticatorLength]byte) {
	p.Authenticator = auth
}

// CalculateResponseAuthenticator calculates the Response Authenticator for Access-Accept, Access-Reject, and Access-Challenge packets
func (p *Packet) CalculateResponseAuthenticator(secret []byte, requestAuthenticator [AuthenticatorLength]byte) [AuthenticatorLength]byte {
	// Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Response Attributes + Secret)
	
	// Build the packet bytes for hashing
	packetBytes := make([]byte, int(p.Length))
	
	// Header: Code + ID + Length + Request Authenticator
	packetBytes[0] = byte(p.Code)
	packetBytes[1] = p.Identifier
	packetBytes[2] = byte(p.Length >> 8)
	packetBytes[3] = byte(p.Length)
	copy(packetBytes[4:20], requestAuthenticator[:])
	
	// Attributes
	offset := PacketHeaderLength
	for _, attr := range p.Attributes {
		packetBytes[offset] = attr.Type
		packetBytes[offset+1] = attr.Length
		copy(packetBytes[offset+2:offset+int(attr.Length)], attr.Value)
		offset += int(attr.Length)
	}
	
	// Append secret
	data := append(packetBytes, secret...)
	
	// Calculate MD5 hash
	hash := md5.Sum(data)
	return hash
}

// CalculateRequestAuthenticator calculates the Request Authenticator for Access-Request packets
func (p *Packet) CalculateRequestAuthenticator(secret []byte) [AuthenticatorLength]byte {
	// Request Authenticator = MD5(Code + ID + Length + Null Authenticator + Attributes + Secret)
	
	// Build the packet bytes for hashing
	packetBytes := make([]byte, int(p.Length))
	
	// Header: Code + ID + Length + Null Authenticator (16 zero bytes)
	packetBytes[0] = byte(p.Code)
	packetBytes[1] = p.Identifier
	packetBytes[2] = byte(p.Length >> 8)
	packetBytes[3] = byte(p.Length)
	// Authenticator field is already zero-initialized
	
	// Attributes
	offset := PacketHeaderLength
	for _, attr := range p.Attributes {
		packetBytes[offset] = attr.Type
		packetBytes[offset+1] = attr.Length
		copy(packetBytes[offset+2:offset+int(attr.Length)], attr.Value)
		offset += int(attr.Length)
	}
	
	// Append secret
	data := append(packetBytes, secret...)
	
	// Calculate MD5 hash
	hash := md5.Sum(data)
	return hash
}

// IsValid performs basic validation of the packet
func (p *Packet) IsValid() error {
	if !p.Code.IsValid() {
		return fmt.Errorf("invalid packet code: %d", p.Code)
	}
	
	if p.Length < MinPacketLength {
		return fmt.Errorf("packet too short: %d bytes", p.Length)
	}
	
	if p.Length > MaxPacketLength {
		return fmt.Errorf("packet too long: %d bytes", p.Length)
	}
	
	// Calculate expected length from attributes
	expectedLength := uint16(PacketHeaderLength)
	for _, attr := range p.Attributes {
		expectedLength += uint16(attr.Length)
	}
	
	if p.Length != expectedLength {
		return fmt.Errorf("packet length mismatch: header says %d, calculated %d", p.Length, expectedLength)
	}
	
	return nil
}

// String returns a string representation of the packet
func (p *Packet) String() string {
	return fmt.Sprintf("Code=%s(%d), ID=%d, Length=%d, Attributes=%d", 
		p.Code.String(), p.Code, p.Identifier, p.Length, len(p.Attributes))
}