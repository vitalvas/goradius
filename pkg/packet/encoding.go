package packet

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Encode encodes the packet into binary format according to RFC 2865
func (p *Packet) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("packet validation failed: %w", err)
	}

	buf := make([]byte, p.Length)

	// Encode header
	buf[0] = byte(p.Code)
	buf[1] = p.Identifier
	binary.BigEndian.PutUint16(buf[2:4], p.Length)
	copy(buf[4:20], p.Authenticator[:])

	// Encode attributes
	offset := PacketHeaderLength
	for _, attr := range p.Attributes {
		attrData, err := attr.Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode attribute: %w", err)
		}
		copy(buf[offset:], attrData)
		offset += len(attrData)
	}

	return buf, nil
}

// Decode decodes a packet from binary format according to RFC 2865
func Decode(data []byte) (*Packet, error) {
	if len(data) < PacketHeaderLength {
		return nil, ErrPacketTooShort
	}

	// Decode header
	code := Code(data[0])
	if !code.IsValid() {
		return nil, fmt.Errorf("%w: %d", ErrInvalidCode, code)
	}

	identifier := data[1]
	length := binary.BigEndian.Uint16(data[2:4])

	if length < MinPacketLength {
		return nil, fmt.Errorf("%w: %d < %d", ErrInvalidPacketLength, length, MinPacketLength)
	}

	if length > MaxPacketLength {
		return nil, fmt.Errorf("%w: %d > %d", ErrInvalidPacketLength, length, MaxPacketLength)
	}

	if len(data) < int(length) {
		return nil, fmt.Errorf("data length %d is less than packet length %d", len(data), length)
	}

	var authenticator [AuthenticatorLength]byte
	copy(authenticator[:], data[4:20])

	packet := &Packet{
		Code:          code,
		Identifier:    identifier,
		Length:        length,
		Authenticator: authenticator,
		Attributes:    make([]Attribute, 0),
	}

	// Decode attributes
	offset := PacketHeaderLength
	for offset < int(length) {
		if offset+2 > int(length) {
			return nil, fmt.Errorf("incomplete attribute header at offset %d", offset)
		}

		attr, bytesRead, err := DecodeAttribute(data[offset:int(length)])
		if err != nil {
			return nil, fmt.Errorf("failed to decode attribute at offset %d: %w", offset, err)
		}

		packet.Attributes = append(packet.Attributes, attr)
		offset += bytesRead
	}

	return packet, nil
}

// DecodeFromReader decodes a packet from an io.Reader
func DecodeFromReader(r io.Reader) (*Packet, error) {
	// Read header first
	header := make([]byte, PacketHeaderLength)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("failed to read packet header: %w", err)
	}

	// Extract length from header
	length := binary.BigEndian.Uint16(header[2:4])
	if length < PacketHeaderLength {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPacketLength, length)
	}

	if length > MaxPacketLength {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPacketLength, length)
	}

	// Read the rest of the packet
	data := make([]byte, length)
	copy(data[:PacketHeaderLength], header)

	if length > PacketHeaderLength {
		remaining := data[PacketHeaderLength:]
		if _, err := io.ReadFull(r, remaining); err != nil {
			return nil, fmt.Errorf("failed to read packet body: %w", err)
		}
	}

	return Decode(data)
}

// Encode encodes the attribute into binary format
func (a *Attribute) Encode() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}

	buf := make([]byte, a.Length)
	buf[0] = a.Type
	buf[1] = a.Length
	copy(buf[2:], a.Value)

	return buf, nil
}

// DecodeAttribute decodes an attribute from binary data
func DecodeAttribute(data []byte) (Attribute, int, error) {
	if len(data) < 2 {
		return Attribute{}, 0, fmt.Errorf("attribute data too short: %d bytes", len(data))
	}

	attrType := data[0]
	length := data[1]

	if length < 2 {
		return Attribute{}, 0, fmt.Errorf("invalid attribute length: %d", length)
	}

	if len(data) < int(length) {
		return Attribute{}, 0, fmt.Errorf("attribute data too short for length %d", length)
	}

	valueLength := int(length) - 2
	value := make([]byte, valueLength)
	copy(value, data[2:2+valueLength])

	attr := Attribute{
		Type:   attrType,
		Length: length,
		Value:  value,
	}

	if err := attr.Validate(); err != nil {
		return Attribute{}, 0, fmt.Errorf("attribute validation failed: %w", err)
	}

	return attr, int(length), nil
}

// WriteTo writes the encoded packet to an io.Writer
func (p *Packet) WriteTo(w io.Writer) (int64, error) {
	data, err := p.Encode()
	if err != nil {
		return 0, err
	}

	n, err := w.Write(data)
	return int64(n), err
}
