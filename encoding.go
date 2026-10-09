package goradius

import (
	"fmt"
)

// Encode converts a Packet into its binary representation per RFC 2865 Section 3.
// Attribute encryption is transparent: any attribute whose dictionary
// definition declares an Encryption type is encrypted here (or by an earlier
// authenticator calculation) using the packet Secret and the packet-type-
// appropriate authenticator. A packet whose encryption cannot be finalized
// (no Secret set, or a response with no request authenticator bound) is
// refused rather than emitting the plaintext on the wire.
func (p *Packet) Encode() ([]byte, error) {
	p.finalizeDeferredEncryption()

	if err := p.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid packet: %w", err)
	}

	for _, attr := range p.Attributes {
		if attr.encryption == EncryptionNone {
			continue
		}
		if len(p.Secret) == 0 {
			return nil, fmt.Errorf("attribute type %d requires encryption but no shared secret is set on the packet", attr.Type)
		}
		return nil, fmt.Errorf("attribute type %d requires encryption but the keying authenticator is not available: set the packet authenticator first, or build responses with NewResponse", attr.Type)
	}

	data := make([]byte, p.Length)

	// Header
	data[0] = byte(p.Code)
	data[1] = p.Identifier
	data[2] = byte(p.Length >> 8)
	data[3] = byte(p.Length)
	copy(data[4:20], p.Authenticator[:])

	// Attributes
	offset := PacketHeaderLength
	for _, attr := range p.Attributes {
		data[offset] = attr.Type
		data[offset+1] = attr.Length
		copy(data[offset+2:offset+int(attr.Length)], attr.Value)
		offset += int(attr.Length)
	}

	return data, nil
}

// Decode parses binary data into a Packet per RFC 2865 Section 3
func Decode(data []byte) (*Packet, error) {
	if len(data) < MinPacketLength {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	// Parse header
	code := Code(data[0])
	identifier := data[1]
	length := uint16(data[2])<<8 | uint16(data[3])

	// RFC 2865 Section 3: the Length field bounds the packet at 20-4096
	// octets; input beyond the Length field is padding and ignored, even
	// when the datagram itself exceeds the maximum packet length
	if length < MinPacketLength || length > MaxPacketLength {
		return nil, fmt.Errorf("invalid packet length in header: %d", length)
	}

	// RFC 2865 Section 3: a packet shorter than the Length field is silently
	// discarded
	if int(length) > len(data) {
		return nil, fmt.Errorf("packet shorter than length field: header says %d, got %d", length, len(data))
	}

	var authenticator [AuthenticatorLength]byte
	copy(authenticator[:], data[4:20])

	// First pass: validate attribute framing and count attributes
	attrCount := 0
	offset := PacketHeaderLength
	for offset < int(length) {
		if offset+AttributeHeaderLength > int(length) {
			return nil, fmt.Errorf("incomplete attribute header at offset %d", offset)
		}

		attrLength := data[offset+1]

		if attrLength < AttributeHeaderLength {
			return nil, fmt.Errorf("invalid attribute length: %d", attrLength)
		}

		if offset+int(attrLength) > int(length) {
			return nil, fmt.Errorf("attribute extends beyond packet: offset %d, length %d, packet length %d",
				offset, attrLength, length)
		}

		attrCount++
		offset += int(attrLength)
	}

	packet := &Packet{
		Code:          code,
		Identifier:    identifier,
		Length:        length,
		Authenticator: authenticator,
		Attributes:    make([]*Attribute, attrCount),
	}

	// Second pass: one backing buffer for all values and one slab for all
	// attributes instead of two allocations per attribute
	valueBuf := make([]byte, int(length)-PacketHeaderLength)
	copy(valueBuf, data[PacketHeaderLength:length])
	slab := make([]Attribute, attrCount)

	offset = 0
	for i := range slab {
		attrType := valueBuf[offset]
		attrLength := int(valueBuf[offset+1])
		end := offset + attrLength

		// The full slice expression caps capacity so a caller appending to one
		// attribute's value cannot overwrite the neighboring attribute's bytes
		attrValue := valueBuf[offset+AttributeHeaderLength : end : end]

		slab[i] = Attribute{
			Type:   attrType,
			Length: uint8(attrLength),
			Value:  attrValue,
		}

		// Check if this is a tagged attribute (for known tagged attribute types)
		// First byte might be a tag (1-31, 0 means no tag)
		if isTaggedAttributeType(attrType) && len(attrValue) > 0 && attrValue[0] >= 1 && attrValue[0] <= 31 {
			slab[i].Tag = attrValue[0]
		}

		packet.Attributes[i] = &slab[i]
		offset = end
	}

	return packet, nil
}

// isTaggedAttributeType returns true if the attribute type supports tagging
func isTaggedAttributeType(attrType uint8) bool {
	// Standard tagged attributes from RFC 2868 (Tunnel attributes)
	switch attrType {
	case 64, 65, 66, 67, 69, 81, 82, 83, 90, 91: // Tunnel-* attributes
		return true
	default:
		return false
	}
}
