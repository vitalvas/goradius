package goradius

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// ContinuationMarker is the suffix used to indicate attribute continuation
	ContinuationMarker = "<contd>"
)

// Packet represents a RADIUS packet as defined in RFC 2865 Section 3
// Format: Code (1) + Identifier (1) + Length (2) + Authenticator (16) + Attributes (variable)
type Packet struct {
	Code          Code
	Identifier    uint8
	Length        uint16
	Authenticator [AuthenticatorLength]byte
	Attributes    []*Attribute
	Dict          *Dictionary // Optional dictionary for attribute lookups

	// Secret is the shared secret used to encrypt and decrypt attributes
	// whose dictionary definition declares an Encryption type (User-Password,
	// Tunnel-Password, Ascend-Secret). The server and client set it when they
	// build the packet, so callers never pass a secret to SetAttributes.
	// Encryption and decryption are transparent: attributes are encrypted
	// automatically when the packet is serialized and decrypted automatically
	// when read through GetAttribute, using the packet-type-appropriate
	// authenticator.
	Secret []byte

	// requestAuth carries the Request Authenticator of the packet being
	// answered, which keys attribute encryption in responses (RFC 2865
	// Section 5.2, RFC 2868 Section 3.5). It is bound automatically by
	// NewResponse, the server pipeline, the Client when it receives a
	// response, and whenever a response/message authenticator is computed.
	requestAuth    [AuthenticatorLength]byte
	hasRequestAuth bool

	// usedTunnelSalts records every Tunnel-Password salt emitted by this
	// packet, so repeated salt-encrypted attributes never share a salt
	// (RFC 2868 Section 3.5).
	usedTunnelSalts map[uint16]struct{}

	vsaCache map[int][]*VendorAttribute
}

// bindRequestAuthenticator records the Request Authenticator of the packet
// this one answers, enabling transparent encryption and decryption of
// response attributes.
func (p *Packet) bindRequestAuthenticator(auth [AuthenticatorLength]byte) {
	p.requestAuth = auth
	p.hasRequestAuth = true
}

// encryptionAuthenticator returns the authenticator that keys attribute
// encryption for this packet: the packet's own (random) authenticator for
// Access-Request and Status-Server, sixteen zero octets for requests whose
// authenticator is computed over the attributes (Accounting/CoA/Disconnect,
// RFC 2868 Section 3.5 / RFC 5176), and the bound Request Authenticator for
// responses. ok is false when a response has no request authenticator bound.
func (p *Packet) encryptionAuthenticator() (auth [AuthenticatorLength]byte, ok bool) {
	switch p.Code {
	case CodeAccessRequest, CodeStatusServer:
		return p.Authenticator, true
	case CodeAccountingRequest, CodeCoARequest, CodeDisconnectRequest:
		return [AuthenticatorLength]byte{}, true
	default:
		return p.requestAuth, p.hasRequestAuth
	}
}

// finalizeDeferredEncryption transparently encrypts any pending attributes
// using the packet-type-appropriate authenticator. It runs before every
// serialization (Encode and the authenticator/integrity calculations), so
// callers never invoke encryption explicitly.
func (p *Packet) finalizeDeferredEncryption() {
	if auth, ok := p.encryptionAuthenticator(); ok {
		p.finalizeEncryption(auth)
	}
}

// AttributeValue contains a single attribute value with type information
type AttributeValue struct {
	Name       string   // Attribute name from dictionary
	Type       uint8    // Attribute type ID (26 for VSA)
	DataType   DataType // Data type (string, integer, ipaddr, etc.)
	Value      []byte   // Raw value bytes
	Tag        uint8    // Tag value for tagged attributes (0 = no tag)
	IsVSA      bool     // True if this is a vendor-specific attribute
	VendorID   uint32   // Vendor ID (only for VSA)
	VendorType uint32   // Vendor attribute type (only for VSA)
	Multiline  bool     // True if attribute supports multiline continuation

	def *AttributeDefinition // Attribute definition (for decoding container types)

	// decoded carries an already-decoded native value for container children
	// (set by containerChildValues), covering types such as bits and union
	// members that have no standalone byte decoder.
	decoded any
}

// Decoded returns the attribute value decoded into its native Go type (string,
// uint32, net.IP, uint64, time.Duration, ...) per the attribute's DataType.
// Container types and values with no scalar decoder return the raw bytes.
func (av AttributeValue) Decoded() any {
	if av.decoded != nil {
		return av.decoded
	}
	v, err := DecodeValue(av.Value, av.DataType)
	if err != nil {
		return av.Value
	}
	return v
}

// Children decodes a container attribute value (tlv or struct) into a map keyed by
// child attribute name. Returns an error if the attribute is not a container type or
// the raw bytes cannot be parsed.
func (av AttributeValue) Children() (map[string]any, error) {
	if av.def == nil {
		return nil, fmt.Errorf("attribute %q has no definition to decode children", av.Name)
	}
	switch av.DataType {
	case DataTypeTLV:
		return DecodeTLV(av.def, av.Value)
	case DataTypeStruct:
		return DecodeStruct(av.def, av.Value)
	case DataTypeEVS:
		// For EVS, av.Value already has the vendor header stripped; its inner payload
		// is a TLV stream when the definition declares children.
		if len(av.def.Children) == 0 {
			return nil, fmt.Errorf("EVS attribute %q has no children to decode", av.Name)
		}
		return DecodeTLV(av.def, av.Value)
	default:
		return nil, fmt.Errorf("attribute %q is not a container type (%s)", av.Name, av.DataType)
	}
}

// String returns the attribute value as a string, decoded based on DataType
func (av AttributeValue) String() string {
	switch av.DataType {
	case DataTypeString:
		return DecodeString(av.Value)

	case DataTypeInteger:
		val, err := DecodeInteger(av.Value)
		if err != nil {
			return formatHex(av.Value)
		}
		return strconv.FormatUint(uint64(val), 10)

	case DataTypeIPAddr:
		ip, err := DecodeIPAddr(av.Value)
		if err != nil {
			return formatHex(av.Value)
		}
		return ip.String()

	case DataTypeIPv6Addr:
		ip, err := DecodeIPv6Addr(av.Value)
		if err != nil {
			return formatHex(av.Value)
		}
		return ip.String()

	case DataTypeIPv6Prefix:
		prefix, err := DecodeIPv6Prefix(av.Value)
		if err != nil {
			return formatHex(av.Value)
		}
		return prefix.String()

	case DataTypeIfID:
		ifid, err := DecodeIfID(av.Value)
		if err != nil {
			return formatHex(av.Value)
		}
		return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			ifid[0], ifid[1], ifid[2], ifid[3], ifid[4], ifid[5], ifid[6], ifid[7])

	case DataTypeDate:
		t, err := DecodeDate(av.Value)
		if err != nil {
			return formatHex(av.Value)
		}
		return t.Format(time.RFC3339)

	case DataTypeOctets:
		return formatHex(av.Value)

	default:
		// For unknown types, return hex representation
		return formatHex(av.Value)
	}
}

// formatHex formats bytes as "0x" followed by hex digits
func formatHex(data []byte) string {
	if len(data) == 0 {
		return "0x"
	}
	result := make([]byte, 2+len(data)*2)
	result[0] = '0'
	result[1] = 'x'
	for i, b := range data {
		result[2+i*2] = hexTable[b>>4]
		result[2+i*2+1] = hexTable[b&0x0f]
	}
	return string(result)
}

// NewPacket creates a new RADIUS packet with the specified code and identifier
func NewPacket(code Code, identifier uint8) *Packet {
	return &Packet{
		Code:       code,
		Identifier: identifier,
		Length:     PacketHeaderLength,
		Attributes: nil, // nil slice works with append and avoids allocation
	}
}

// NewPacketWithDictionary creates a new RADIUS packet with dictionary support
func NewPacketWithDictionary(code Code, identifier uint8, dict *Dictionary) *Packet {
	p := NewPacket(code, identifier)
	p.Dict = dict
	return p
}

// AddAttribute adds an attribute to the packet
func (p *Packet) AddAttribute(attr *Attribute) {
	p.Attributes = append(p.Attributes, attr)
	p.Length += uint16(attr.Length)
}

// AddVendorAttribute adds a vendor-specific attribute to the packet, encoding
// it with the vendor's VSA header format when the dictionary defines one, and
// returns the resulting wire attribute.
func (p *Packet) AddVendorAttribute(va *VendorAttribute) *Attribute {
	typeOctets, lengthOctets := p.vsaFormat(va.VendorID)
	attr := va.ToVSAFormat(typeOctets, lengthOctets)
	p.AddAttribute(attr)
	return attr
}

// vsaDataOffset returns the offset within an encoded VSA Attribute.Value at
// which the vendor data (the part subject to encryption) begins: the 4-octet
// Vendor-Id plus the type and length fields, plus a tag octet when tagged.
func (p *Packet) vsaDataOffset(vendorID uint32, tagged bool) int {
	typeOctets, lengthOctets := p.vsaFormat(vendorID)
	offset := 4 + typeOctets + lengthOctets
	if tagged {
		offset++
	}
	return offset
}

// vsaFormat returns the VSA header widths for a vendor, defaulting to the
// RFC 2865 standard (1,1) when the vendor is unknown or uses the default.
func (p *Packet) vsaFormat(vendorID uint32) (typeOctets, lengthOctets int) {
	if p.Dict != nil {
		if vendor, ok := p.Dict.LookupVendorByID(vendorID); ok {
			return vendor.vsaTypeOctets(), vendor.vsaLengthOctets()
		}
	}
	return 1, 1
}

// getAttributesByType returns all raw attributes with the specified type.
// Internal helper; external callers use GetAttribute(name) or GetAttributes().
func (p *Packet) getAttributesByType(attrType uint8) []*Attribute {
	var attrs []*Attribute
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			attrs = append(attrs, attr)
		}
	}
	return attrs
}

// getParsedVSAs returns the cached parsed vendor sub-attributes of a VSA, or
// parses and caches them. One Vendor-Specific attribute may carry several
// sub-attributes (RFC 2865 Section 5.26).
func (p *Packet) getParsedVSAs(index int, attr *Attribute) ([]*VendorAttribute, error) {
	if p.vsaCache == nil {
		p.vsaCache = make(map[int][]*VendorAttribute)
	}

	if vas, exists := p.vsaCache[index]; exists {
		return vas, nil
	}

	// The Vendor-ID is always the first 4 octets regardless of format; read it
	// to resolve the vendor's VSA header widths, then parse with those.
	typeOctets, lengthOctets := 1, 1
	if len(attr.Value) >= 4 {
		vendorID := uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 | uint32(attr.Value[2])<<8 | uint32(attr.Value[3])
		typeOctets, lengthOctets = p.vsaFormat(vendorID)
	}

	vas, err := parseVSAList(attr, typeOctets, lengthOctets)
	if err != nil {
		return nil, err
	}

	// Tag detection needs the dictionary: only attributes defined as tagged
	// carry a tag octet, and only a first octet of 1-31 is a tag (RFC 2868)
	for _, va := range vas {
		if p.Dict == nil {
			break
		}
		if def, ok := p.Dict.LookupVendorAttributeByID(va.VendorID, va.VendorType); ok && def.HasTag {
			if len(va.Value) > 0 && va.Value[0] >= 1 && va.Value[0] <= MaxAttributeTag {
				va.Tag = va.Value[0]
			}
		}
	}

	p.vsaCache[index] = vas
	return vas, nil
}

// GetVendorAttribute returns the first vendor attribute with the specified vendor ID and type
func (p *Packet) GetVendorAttribute(vendorID uint32, vendorType uint32) (*VendorAttribute, bool) {
	for i, attr := range p.Attributes {
		if attr.Type == AttributeTypeVendorSpecific {
			vas, err := p.getParsedVSAs(i, attr)
			if err != nil {
				continue
			}
			for _, va := range vas {
				if va.VendorID == vendorID && va.VendorType == vendorType {
					return va, true
				}
			}
		}
	}
	return nil, false
}

// GetVendorAttributes returns all vendor attributes with the specified vendor ID and type
func (p *Packet) GetVendorAttributes(vendorID uint32, vendorType uint32) []*VendorAttribute {
	var attrs []*VendorAttribute
	for i, attr := range p.Attributes {
		if attr.Type == AttributeTypeVendorSpecific {
			vas, err := p.getParsedVSAs(i, attr)
			if err != nil {
				continue
			}
			for _, va := range vas {
				if va.VendorID == vendorID && va.VendorType == vendorType {
					attrs = append(attrs, va)
				}
			}
		}
	}
	return attrs
}

// RemoveAttribute removes the first attribute with the specified type
// INTERNAL: This method is for internal library use only and may be removed in future versions.
func (p *Packet) RemoveAttribute(attrType uint8) bool {
	for i, attr := range p.Attributes {
		if attr.Type == attrType {
			p.Length -= uint16(attr.Length)
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
			p.vsaCache = nil // Invalidate cache as indices have shifted
			return true
		}
	}
	return false
}

// RemoveAttributes removes all attributes with the specified type
// INTERNAL: This method is for internal library use only and may be removed in future versions.
func (p *Packet) RemoveAttributes(attrType uint8) int {
	removed := 0
	for i := len(p.Attributes) - 1; i >= 0; i-- {
		if p.Attributes[i].Type == attrType {
			p.Length -= uint16(p.Attributes[i].Length)
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
			removed++
		}
	}
	if removed > 0 {
		p.vsaCache = nil // Invalidate cache as indices have shifted
	}
	return removed
}

// RemoveAttributeByName removes all attributes with the specified name using dictionary lookup
func (p *Packet) RemoveAttributeByName(name string) int {
	if p.Dict == nil {
		return 0
	}

	removed := 0

	// Try standard attribute first
	if attrDef, exists := p.Dict.LookupStandardByName(name); exists {
		// Remove all standard attributes of this type
		for i := len(p.Attributes) - 1; i >= 0; i-- {
			if p.Attributes[i].Type == uint8(attrDef.ID) {
				p.Length -= uint16(p.Attributes[i].Length)
				p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
				removed++
			}
		}
		// Invalidate VSA cache: removals shift the indices of subsequent VSAs
		if removed > 0 {
			p.vsaCache = nil
		}
		return removed
	}

	// Try vendor attribute using unified lookup
	attrDef, exists := p.Dict.LookupByAttributeName(name)
	if !exists {
		return 0
	}

	// Find the vendor ID for this attribute using O(1) lookup
	vendorID, exists := p.Dict.LookupVendorIDByAttributeName(name)
	if !exists {
		return 0
	}

	// Remove all VSAs carrying this vendor and attribute ID. A multi-sub-attribute
	// VSA is removed as a whole when any of its sub-attributes matches.
	for i := len(p.Attributes) - 1; i >= 0; i-- {
		if p.Attributes[i].Type == AttributeTypeVendorSpecific {
			vas, err := p.getParsedVSAs(i, p.Attributes[i])
			if err != nil {
				continue
			}
			for _, va := range vas {
				if va.VendorID == vendorID && va.VendorType == attrDef.ID {
					p.Length -= uint16(p.Attributes[i].Length)
					p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
					removed++
					break
				}
			}
		}
	}

	// Invalidate VSA cache after removals (rebuild on next access)
	if removed > 0 {
		p.vsaCache = nil
	}

	return removed
}

// SetAuthenticator sets the packet authenticator.
func (p *Packet) SetAuthenticator(auth [AuthenticatorLength]byte) {
	p.Authenticator = auth
}

// EncryptAttributes finalizes any deferred attribute encryption using the
// supplied authenticator. Calling it is OPTIONAL: encryption is transparent
// and runs automatically with the packet-type-appropriate authenticator when
// the packet is serialized (Encode, Message-Authenticator, and response or
// request authenticator calculations). This method remains as a low-level
// escape hatch for callers that need to key encryption with an authenticator
// the packet cannot derive itself.
//
// Per RFC the authenticator depends on the packet type:
//
//   - Access-Request: the random Request Authenticator (RFC 2865 Section 3).
//   - Accounting-Request, CoA-Request, Disconnect-Request: 16 zero octets,
//     because the Request Authenticator is computed over the attributes and is
//     not yet known when they are encrypted (RFC 2868 Section 3.5, RFC 5176).
//   - Access-Accept/Reject/Challenge and CoA/Disconnect responses: the
//     Request Authenticator of the packet being answered (RFC 2865/2868).
//
// It is idempotent: once an attribute is encrypted its marker is cleared, so a
// later Encode does not re-encrypt.
func (p *Packet) EncryptAttributes(auth [AuthenticatorLength]byte) {
	p.finalizeEncryption(auth)
}

// finalizeEncryption encrypts any attribute whose value was deferred for
// encryption, in place, using the packet Secret and the supplied authenticator.
// It is idempotent: once an attribute is encrypted its marker is cleared.
// Without a Secret the markers are left in place, so Encode refuses to emit
// the plaintext instead of sending it on the wire.
func (p *Packet) finalizeEncryption(auth [AuthenticatorLength]byte) {
	if len(p.Secret) == 0 {
		return
	}
	for _, attr := range p.Attributes {
		if attr.encryption == EncryptionNone {
			continue
		}
		off := attr.encryptOffset
		if off > len(attr.Value) {
			continue
		}
		plaintext := attr.Value[off:]

		// RFC 2868 Section 3.5: each Salt in a packet MUST be unique, so
		// Tunnel-Password attributes draw their salt from the packet-level
		// uniqueness tracker.
		var ciphertext []byte
		if attr.encryption == EncryptionTunnelPassword {
			ciphertext = encryptTunnelPasswordSalted(plaintext, p.Secret, auth, p.uniqueTunnelSalt())
		} else {
			ciphertext = EncryptAttributeValue(plaintext, attr.encryption, p.Secret, auth)
		}

		newValue := make([]byte, off+len(ciphertext))
		copy(newValue, attr.Value[:off])
		copy(newValue[off:], ciphertext)

		// For a VSA the Vendor-Length field is inside the value and must be
		// rewritten to cover the new (encrypted) data length: it counts every
		// octet after the 4-octet Vendor-Id.
		if attr.vsaLengthWidth > 0 {
			vendorLen := len(newValue) - 4
			for i := 0; i < attr.vsaLengthWidth; i++ {
				shift := uint(8 * (attr.vsaLengthWidth - 1 - i))
				newValue[attr.vsaLengthPos+i] = byte(vendorLen >> shift)
			}
		}

		// Encryption can change the value length (User-Password pads to a
		// 16-octet multiple; Tunnel-Password adds salt and a length octet), so
		// adjust the attribute and packet lengths accordingly.
		delta := len(newValue) - len(attr.Value)
		attr.Value = newValue
		attr.Length = uint8(len(newValue) + AttributeHeaderLength)
		p.Length += uint16(delta)

		attr.encryption = EncryptionNone
		attr.encryptOffset = 0
	}
}

// packetByteLength returns the total packet length computed from the
// attributes in int space, so oversized packets cannot wrap the uint16
// Length field and under-allocate serialization buffers.
func (p *Packet) packetByteLength() int {
	length := PacketHeaderLength
	for _, attr := range p.Attributes {
		length += int(attr.Length)
	}
	return length
}

// buildPacketBytes builds packet bytes for authentication/integrity calculations
func (p *Packet) buildPacketBytes(authenticator [AuthenticatorLength]byte, zeroMessageAuth bool) []byte {
	// Integrity values must cover the encrypted attribute bytes, so pending
	// encryption is finalized before the packet is rendered.
	p.finalizeDeferredEncryption()

	length := p.packetByteLength()
	packetBytes := make([]byte, length)

	packetBytes[0] = byte(p.Code)
	packetBytes[1] = p.Identifier
	packetBytes[2] = byte(length >> 8)
	packetBytes[3] = byte(length)
	copy(packetBytes[4:20], authenticator[:])

	offset := PacketHeaderLength
	for _, attr := range p.Attributes {
		packetBytes[offset] = attr.Type
		packetBytes[offset+1] = attr.Length

		if zeroMessageAuth && attr.Type == AttributeTypeMessageAuthenticator {
			offset += int(attr.Length)
		} else {
			copy(packetBytes[offset+2:offset+int(attr.Length)], attr.Value)
			offset += int(attr.Length)
		}
	}

	return packetBytes
}

// calculateAuthenticator calculates RADIUS authenticator using MD5(packet + secret) per RFC 2865 Section 3
func (p *Packet) calculateAuthenticator(secret []byte, requestAuthenticator [AuthenticatorLength]byte) [AuthenticatorLength]byte {
	// The authenticator must cover the encrypted attribute bytes, so pending
	// encryption is finalized before the packet is rendered.
	p.finalizeDeferredEncryption()

	// Pre-allocate with capacity for secret to avoid reallocation
	length := p.packetByteLength()
	packetBytes := make([]byte, length, length+len(secret))

	packetBytes[0] = byte(p.Code)
	packetBytes[1] = p.Identifier
	packetBytes[2] = byte(length >> 8)
	packetBytes[3] = byte(length)
	copy(packetBytes[4:20], requestAuthenticator[:])

	offset := PacketHeaderLength
	for _, attr := range p.Attributes {
		packetBytes[offset] = attr.Type
		packetBytes[offset+1] = attr.Length
		copy(packetBytes[offset+2:offset+int(attr.Length)], attr.Value)
		offset += int(attr.Length)
	}

	packetBytes = append(packetBytes, secret...)
	return md5.Sum(packetBytes)
}

// CalculateResponseAuthenticator calculates the Response Authenticator per RFC 2865 Section 3
// ResponseAuth = MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
// The supplied request authenticator is bound to the packet so encrypted
// response attributes finalize and decrypt transparently.
func (p *Packet) CalculateResponseAuthenticator(secret []byte, requestAuthenticator [AuthenticatorLength]byte) [AuthenticatorLength]byte {
	p.bindRequestAuthenticator(requestAuthenticator)
	return p.calculateAuthenticator(secret, requestAuthenticator)
}

// CalculateRequestAuthenticator calculates the Request Authenticator for Accounting-Request (RFC 2866 Section 4.1),
// CoA-Request and Disconnect-Request (RFC 5176 Section 3.3)
// RequestAuth = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
// Per RFC 5176 Section 3.4 the Message-Authenticator, when present, is calculated and
// inserted before this call, so its real value is covered by the hash.
func (p *Packet) CalculateRequestAuthenticator(secret []byte) [AuthenticatorLength]byte {
	var nullAuth [AuthenticatorLength]byte
	return p.calculateAuthenticator(secret, nullAuth)
}

// calculateMessageAuthenticator calculates the Message-Authenticator attribute value per RFC 2869 Section 5.14
// MessageAuth = HMAC-MD5(packet with Message-Authenticator zeroed, secret)
func (p *Packet) calculateMessageAuthenticator(secret []byte, requestAuthenticator [AuthenticatorLength]byte) [16]byte {
	var auth [AuthenticatorLength]byte
	switch p.Code {
	case CodeAccessRequest, CodeStatusServer:
		// RFC 2869 Section 5.14 / RFC 5997: computed with the random Request
		// Authenticator in place
		auth = p.Authenticator
	case CodeAccountingRequest, CodeCoARequest, CodeDisconnectRequest:
		// RFC 5176 Section 3.4: the Request Authenticator field is considered to be
		// sixteen octets of zero while computing the Message-Authenticator
	default:
		// Responses use the Request Authenticator of the corresponding request;
		// bind it so encrypted response attributes finalize and decrypt
		// transparently.
		auth = requestAuthenticator
		if p.Code.IsReply() {
			p.bindRequestAuthenticator(requestAuthenticator)
		}
	}

	packetBytes := p.buildPacketBytes(auth, true)

	mac := hmac.New(md5.New, secret)
	mac.Write(packetBytes)
	var result [16]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// hasMessageAuthenticator reports whether the packet carries a
// Message-Authenticator attribute.
func (p *Packet) hasMessageAuthenticator() bool {
	for _, attr := range p.Attributes {
		if attr.Type == AttributeTypeMessageAuthenticator {
			return true
		}
	}
	return false
}

// VerifyMessageAuthenticator verifies the Message-Authenticator attribute per RFC 2869 Section 5.14
func (p *Packet) VerifyMessageAuthenticator(secret []byte, requestAuthenticator [AuthenticatorLength]byte) bool {
	var messageAuth []byte
	for _, attr := range p.Attributes {
		if attr.Type == AttributeTypeMessageAuthenticator {
			messageAuth = attr.Value
			break
		}
	}

	if messageAuth == nil {
		return false
	}

	if len(messageAuth) != 16 {
		return false
	}

	expected := p.calculateMessageAuthenticator(secret, requestAuthenticator)

	return hmac.Equal(messageAuth, expected[:])
}

// AddMessageAuthenticator adds a Message-Authenticator attribute to the packet
func (p *Packet) AddMessageAuthenticator(secret []byte, requestAuthenticator [AuthenticatorLength]byte) {
	// The zeroed placeholder must be present during the HMAC computation so the
	// attribute's type and length bytes are covered; the result is copied into it.
	attr := NewAttribute(AttributeTypeMessageAuthenticator, make([]byte, 16))
	p.AddAttribute(attr)

	mac := p.calculateMessageAuthenticator(secret, requestAuthenticator)
	copy(attr.Value, mac[:])
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

	// Calculate expected length from attributes in int space, so an oversized
	// packet cannot wrap the uint16 arithmetic back into the valid range
	expectedLength := PacketHeaderLength
	for _, attr := range p.Attributes {
		// Catches uint8 overflow from constructors given oversized values
		if int(attr.Length) != len(attr.Value)+AttributeHeaderLength {
			return fmt.Errorf("attribute type %d length %d does not match value length %d", attr.Type, attr.Length, len(attr.Value))
		}
		expectedLength += int(attr.Length)
	}

	if expectedLength > MaxPacketLength {
		return fmt.Errorf("packet too long: attributes total %d bytes", expectedLength)
	}

	if int(p.Length) != expectedLength {
		return fmt.Errorf("packet length mismatch: header says %d, calculated %d", p.Length, expectedLength)
	}

	return nil
}

// AddAttributeByName adds an attribute to the packet using dictionary lookup
// with full feature support. Attributes whose dictionary definition declares
// an Encryption type are encrypted transparently with the packet's Secret
// when the packet is serialized; the caller never supplies a secret or calls
// an encryption step.
func (p *Packet) AddAttributeByName(name string, value any) error {
	if p.Dict == nil {
		return fmt.Errorf("no dictionary loaded")
	}

	// Try standard attribute first
	if attrDef, exists := p.Dict.LookupStandardByName(name); exists {
		// Filter out attributes that don't match the packet type
		if !p.isAttributeAllowed(attrDef) {
			return nil
		}
		return p.addStandardAttribute(name, value, attrDef)
	}

	// Tagged standard attribute using "name:tag" syntax (RFC 2868 tunnel attributes)
	if base, _, found := strings.Cut(name, ":"); found {
		if attrDef, exists := p.Dict.LookupStandardByName(base); exists {
			if !p.isAttributeAllowed(attrDef) {
				return nil
			}
			return p.addStandardAttribute(name, value, attrDef)
		}
	}

	// Handle vendor attributes
	return p.addVendorAttributeByName(name, value)
}

// SetAttributesFromStrings populates the packet from a flat map of string
// values, the form a policy server (for example a PCRF) typically returns.
// Keys are the same as SetAttributes (attribute name, optionally "name:tag",
// container children by their own name); each string is converted to the
// attribute's native type per the dictionary before encoding:
//
//   - enumerated values accept the value name (for example "start") or its
//     decimal number;
//   - integer, byte, short, integer64, signed, and time_delta accept a decimal
//     string;
//   - octets accept a hex string (with or without a "0x" prefix);
//   - string, ipaddr, ipv6addr, and ipv6prefix pass through unchanged (their
//     encoders already parse text).
//
// It then delegates to SetAttributes, so encryption and container grouping work
// exactly as for typed input.
func (p *Packet) SetAttributesFromStrings(attrs map[string][]string) error {
	if p.Dict == nil {
		return fmt.Errorf("no dictionary loaded")
	}

	typed := make(map[string][]any, len(attrs))
	for key, values := range attrs {
		def, ok := p.resolveAttributeDef(key)
		if !ok {
			return fmt.Errorf("attribute %q not found in dictionary", key)
		}
		converted := make([]any, len(values))
		for i, s := range values {
			v, err := convertStringValue(s, def)
			if err != nil {
				return fmt.Errorf("attribute %q value %q: %w", key, s, err)
			}
			converted[i] = v
		}
		typed[key] = converted
	}

	return p.SetAttributes(typed)
}

// resolveAttributeDef resolves a flat key (name or "name:tag", top-level or a
// container child) to its attribute definition.
func (p *Packet) resolveAttributeDef(key string) (*AttributeDefinition, bool) {
	base, _ := splitAttributeTag(key)
	if def, ok := p.Dict.LookupByAttributeName(base); ok {
		return def, true
	}
	if parent, ok := p.Dict.childParent(base); ok {
		for _, child := range parent.Children {
			if child.Name == base {
				return child, true
			}
		}
	}
	return nil, false
}

// convertStringValue converts a single PCRF-style string into the Go value
// expected by the attribute's data type.
func convertStringValue(s string, def *AttributeDefinition) (any, error) {
	// Enumerated value name takes precedence (for example "start" -> 1).
	if len(def.Values) > 0 {
		if v, ok := def.Values[s]; ok {
			return v, nil
		}
	}

	switch def.DataType {
	case DataTypeInteger, DataTypeByte, DataTypeShort, DataTypeTimeDelta:
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", def.DataType, err)
		}
		switch def.DataType {
		case DataTypeByte:
			return uint8(n), nil
		case DataTypeShort:
			return uint16(n), nil
		default:
			return uint32(n), nil
		}
	case DataTypeInteger64:
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid integer64: %w", err)
		}
		return n, nil
	case DataTypeSigned:
		n, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid signed: %w", err)
		}
		return int32(n), nil
	case DataTypeOctets, DataTypeABinary:
		raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid hex octets: %w", err)
		}
		return raw, nil
	default:
		// string, ipaddr, ipv6addr, ipv6prefix, ifid, combo-ip: the encoders
		// already accept a text value.
		return s, nil
	}
}

// SetAttributes populates the packet from a flat attribute map, the canonical
// request/response representation. Keys are attribute names, optionally with a
// ":tag" suffix for RFC 2868 tagged attributes (for example
// "erx-service-activate:1"). Values are always slices; each element becomes one
// on-wire attribute instance, so repeated attributes are expressed naturally.
//
// There is no nesting. Container members (struct/tlv/evs children) are addressed
// by their own flat child name as top-level keys; children that resolve to the
// same parent are grouped and encoded into a single container attribute. A given
// child name may therefore appear once per call (one container instance).
func (p *Packet) SetAttributes(attrs map[string][]any) error {
	if p.Dict == nil {
		return fmt.Errorf("no dictionary loaded")
	}

	// Collect container children grouped by (parent name + tag), so a set of
	// flat child keys becomes one encoded container instance.
	type containerGroup struct {
		parent *AttributeDefinition
		tag    string
		values map[string]any
	}
	groups := make(map[string]*containerGroup)
	groupOrder := make([]string, 0)

	for key, values := range attrs {
		base, tag := splitAttributeTag(key)

		// Is this key a flat container child?
		if parent, ok := p.Dict.childParent(base); ok {
			if len(values) != 1 {
				return fmt.Errorf("container child %q requires exactly one value, got %d", key, len(values))
			}
			groupKey := fmt.Sprintf("%s\x00%s", parent.Name, tag)
			g := groups[groupKey]
			if g == nil {
				g = &containerGroup{parent: parent, tag: tag, values: make(map[string]any)}
				groups[groupKey] = g
				groupOrder = append(groupOrder, groupKey)
			}
			g.values[base] = values[0]
			continue
		}

		// Plain (possibly tagged, possibly repeated) attribute: one instance per element.
		for _, v := range values {
			if err := p.AddAttributeByName(key, v); err != nil {
				return err
			}
		}
	}

	// Encode each grouped container once, keyed by the parent name plus tag.
	for _, gk := range groupOrder {
		g := groups[gk]
		name := g.parent.Name
		if g.tag != "" {
			name = fmt.Sprintf("%s:%s", g.parent.Name, g.tag)
		}
		if err := p.AddAttributeByName(name, g.values); err != nil {
			return err
		}
	}

	return nil
}

// splitAttributeTag separates a "name:tag" key into its base name and tag
// string. If there is no ":", the tag is empty.
func splitAttributeTag(key string) (base, tag string) {
	if b, t, found := strings.Cut(key, ":"); found {
		return b, t
	}
	return key, ""
}

// parseAttributeTag parses the tag portion of a "name:tag" key. RFC 2868
// Section 3: valid tag values are 0x01-0x1F, with 0x00 meaning the tag field
// is unused; greater values would be read as attribute data by receivers.
func parseAttributeTag(tagValue string) (uint8, error) {
	parsedTag, err := strconv.ParseUint(tagValue, 10, 8)
	if err != nil || parsedTag > MaxAttributeTag {
		return 0, fmt.Errorf("invalid tag %q: tag must be 0-31 (RFC 2868)", tagValue)
	}
	return uint8(parsedTag), nil
}

// addStandardAttribute handles standard attribute addition with full feature support
func (p *Packet) addStandardAttribute(name string, value any, attrDef *AttributeDefinition) error {
	if attrDef == nil {
		return nil
	}

	var tag uint8

	if strings.Contains(name, ":") && attrDef.HasTag {
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 && parts[1] != "" {
			parsedTag, err := parseAttributeTag(parts[1])
			if err != nil {
				return fmt.Errorf("attribute %q: %w", attrDef.Name, err)
			}
			tag = parsedTag
		}
	}

	// Handle enumerated values - convert string names to integers
	processedValue := p.processEnumeratedValue(value, attrDef)

	// Handle RFC 6929 extended attributes (types 241-246)
	if attrDef.Extended {
		return p.addExtendedAttribute(attrDef, processedValue)
	}

	// Handle array attributes - check if value is a slice
	// This handles both attributes marked as Array=true and user-provided slices
	return p.addArrayAttribute(attrDef, processedValue, tag)
}

// addExtendedAttribute encodes and adds an RFC 6929 extended attribute (short form for
// base types 241-244, long form with fragmentation for 245-246, or Extended-Vendor-Specific).
func (p *Packet) addExtendedAttribute(attrDef *AttributeDefinition, value any) error {
	baseType := attrDef.ExtendedBaseType()
	extType := attrDef.ExtendedType()

	// Extended-Vendor-Specific (EVS): encode the inner value, then wrap with the
	// vendor header under extended type 26.
	if attrDef.DataType == DataTypeEVS {
		return p.addEVSAttribute(attrDef, baseType, value)
	}

	encoded, err := p.encodeAttributeValue(value, attrDef)
	if err != nil {
		return fmt.Errorf("failed to encode extended attribute %q: %w", attrDef.Name, err)
	}

	if IsLongExtendedBaseType(baseType) {
		attrs, err := NewLongExtendedAttributes(baseType, extType, encoded)
		if err != nil {
			return err
		}
		for _, attr := range attrs {
			p.AddAttribute(attr)
		}
		return nil
	}

	attr, err := NewExtendedAttribute(baseType, extType, encoded)
	if err != nil {
		return err
	}
	p.AddAttribute(attr)
	return nil
}

// addEVSAttribute encodes the inner value of an Extended-Vendor-Specific attribute and
// wraps it with the vendor header. When the definition has children, the inner value is
// a TLV map; otherwise it is treated as raw octets.
func (p *Packet) addEVSAttribute(attrDef *AttributeDefinition, baseType uint8, value any) error {
	var inner []byte

	if len(attrDef.Children) > 0 {
		children, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("EVS attribute %q with children requires a map[string]any value", attrDef.Name)
		}
		encoded, err := EncodeTLV(attrDef, children)
		if err != nil {
			return fmt.Errorf("failed to encode EVS TLV %q: %w", attrDef.Name, err)
		}
		inner = encoded
	} else {
		raw, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("EVS attribute %q requires a []byte value", attrDef.Name)
		}
		inner = raw
	}

	attr, err := NewEVSAttribute(baseType, attrDef.VendorID, attrDef.VendorType, inner)
	if err != nil {
		return err
	}
	p.AddAttribute(attr)
	return nil
}

// addVendorAttributeByName handles vendor-specific attribute addition with full feature support
// Supports formats:
//   - "AttributeName" - vendor attribute without tag
//   - "AttributeName:tag" - vendor attribute with tag (tag is a number)
func (p *Packet) addVendorAttributeByName(name string, value any) error {
	parts := strings.SplitN(name, ":", 2)
	attrName := parts[0]

	attrDef, exists := p.Dict.LookupByAttributeName(attrName)
	if !exists {
		return fmt.Errorf("attribute %q not found in dictionary", attrName)
	}

	var tag uint8
	if len(parts) == 2 && parts[1] != "" && attrDef.HasTag {
		parsedTag, err := parseAttributeTag(parts[1])
		if err != nil {
			return fmt.Errorf("attribute %q: %w", attrDef.Name, err)
		}
		tag = parsedTag
	}

	if !p.isAttributeAllowed(attrDef) {
		return nil
	}

	vendorID, exists := p.Dict.LookupVendorIDByAttributeName(attrName)
	if !exists {
		return fmt.Errorf("vendor not found for attribute %q", attrName)
	}

	vendor, exists := p.Dict.LookupVendorByID(vendorID)
	if !exists {
		return fmt.Errorf("vendor ID %d not found for attribute %q", vendorID, attrName)
	}

	processedValue := p.processEnumeratedValue(value, attrDef)
	return p.addVendorArrayAttribute(vendorAttrParams{
		vendor:  vendor,
		attrDef: attrDef,
		value:   processedValue,
		tag:     tag,
	})
}

// isAttributeAllowed checks if an attribute can be used in the current packet type
// according to the per-packet-type Usage bitmask
func (p *Packet) isAttributeAllowed(attrDef *AttributeDefinition) bool {
	return attrDef.AllowedIn(p.Code)
}

// processEnumeratedValue converts string enumerated values to integers
func (p *Packet) processEnumeratedValue(value any, attrDef *AttributeDefinition) any {
	return processEnumeratedValueFor(value, attrDef)
}

// encodeAttributeValue encodes a value based on the attribute data type.
// Container types (tlv, struct) are encoded from a map[string]any of child values;
// scalar types fall through to EncodeValue.
func (p *Packet) encodeAttributeValue(value any, attrDef *AttributeDefinition) ([]byte, error) {
	switch attrDef.DataType {
	case DataTypeTLV:
		children, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("attribute %q is a TLV and requires a map[string]any value", attrDef.Name)
		}
		return EncodeTLV(attrDef, children)

	case DataTypeStruct:
		children, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("attribute %q is a struct and requires a map[string]any value", attrDef.Name)
		}
		return EncodeStruct(attrDef, children)

	default:
		return EncodeValue(value, attrDef.DataType)
	}
}

// EncryptAttributeValue applies encryption to attribute values using the shared secret
func EncryptAttributeValue(value []byte, encryption EncryptionType, secret []byte, authenticator [16]byte) []byte {
	switch encryption {
	case EncryptionUserPassword:
		return encryptUserPassword(value, secret, authenticator)
	case EncryptionTunnelPassword:
		return encryptTunnelPassword(value, secret, authenticator)
	case EncryptionAscendSecret:
		return encryptAscendSecret(value, secret, authenticator)
	default:
		return value
	}
}

// DecryptAttributeValue reverses EncryptAttributeValue, recovering the
// plaintext of an encrypted attribute value. The authenticator is the one
// that keyed the encryption: the Request Authenticator for attributes in an
// Access-Request or in any response, and sixteen zero octets for attributes
// in Accounting-Request, CoA-Request, and Disconnect-Request packets.
//
// Calling it is normally unnecessary: GetAttribute decrypts transparently
// when the packet Secret is set — for requests using the packet's own
// authenticator, and for responses (for example MPPE keys received by the
// Client) using the bound Request Authenticator. This function remains as a
// low-level escape hatch for raw values obtained outside the packet API.
func DecryptAttributeValue(value []byte, encryption EncryptionType, secret []byte, authenticator [16]byte) ([]byte, error) {
	switch encryption {
	case EncryptionUserPassword:
		return decryptUserPassword(value, secret, authenticator)
	case EncryptionTunnelPassword:
		return decryptTunnelPassword(value, secret, authenticator)
	case EncryptionAscendSecret:
		return decryptAscendSecret(value, secret, authenticator)
	default:
		return value, nil
	}
}

// encryptUserPassword implements User-Password encryption (RFC 2865, Section 5.2)
func encryptUserPassword(password []byte, secret []byte, authenticator [16]byte) []byte {
	// User-Password encryption:
	// 1. Pad password to multiple of 16 bytes with null bytes
	// 2. XOR with MD5(secret + authenticator) for first 16 bytes
	// 3. XOR with MD5(secret + previous encrypted block) for subsequent blocks

	// Pad password to multiple of 16 bytes (minimum 16 bytes per RFC 2865)
	paddedLen := ((len(password) + 15) / 16) * 16
	if paddedLen == 0 {
		paddedLen = 16
	}
	padded := make([]byte, paddedLen)
	copy(padded, password)

	encrypted := make([]byte, len(padded))

	// Create a buffer for MD5 input to avoid mutating secret slice
	hashInput := make([]byte, len(secret)+16)
	copy(hashInput, secret)

	// First block: XOR with MD5(secret + authenticator)
	copy(hashInput[len(secret):], authenticator[:])
	hash1 := md5.Sum(hashInput)
	for i := range 16 {
		encrypted[i] = padded[i] ^ hash1[i]
	}

	// Subsequent blocks: XOR with MD5(secret + previous encrypted block)
	for block := 1; block < len(padded)/16; block++ {
		offset := block * 16
		prevBlock := encrypted[offset-16 : offset]
		copy(hashInput[len(secret):], prevBlock)
		hash := md5.Sum(hashInput)

		for i := range 16 {
			encrypted[offset+i] = padded[offset+i] ^ hash[i]
		}
	}

	return encrypted
}

// encryptTunnelPassword implements Tunnel-Password encryption (RFC 2868, Section 3.5)
// with a freshly drawn random salt. In-packet encryption goes through
// finalizeEncryption, which draws salts from the packet-level uniqueness
// tracker instead.
func encryptTunnelPassword(password []byte, secret []byte, authenticator [16]byte) []byte {
	return encryptTunnelPasswordSalted(password, secret, authenticator, newTunnelSalt())
}

// newTunnelSalt returns a random 2-octet salt with the high bit of the first
// octet set, as required by RFC 2868 Section 3.5.
func newTunnelSalt() [2]byte {
	var salt [2]byte
	// crypto/rand.Read never returns an error (Go 1.24+)
	_, _ = rand.Read(salt[:])
	salt[0] |= 0x80
	return salt
}

// uniqueTunnelSalt returns a salt not yet used by this packet, satisfying the
// RFC 2868 Section 3.5 requirement that each Salt field in a packet be unique.
func (p *Packet) uniqueTunnelSalt() [2]byte {
	if p.usedTunnelSalts == nil {
		p.usedTunnelSalts = make(map[uint16]struct{})
	}
	for {
		salt := newTunnelSalt()
		key := uint16(salt[0])<<8 | uint16(salt[1])
		if _, used := p.usedTunnelSalts[key]; !used {
			p.usedTunnelSalts[key] = struct{}{}
			return salt
		}
	}
}

// encryptTunnelPasswordSalted implements the Tunnel-Password cipher with the
// supplied salt.
func encryptTunnelPasswordSalted(password []byte, secret []byte, authenticator [16]byte, salt [2]byte) []byte {
	// Tunnel-Password encryption (RFC 2868):
	// Format: Salt (2 bytes, unencrypted) + encrypted(1-byte length + password + padding)
	// Encryption: XOR with MD5(secret + authenticator + salt) for first block,
	//             XOR with MD5(secret + previous encrypted block) for subsequent blocks

	// Build plaintext: 1-byte length + password, padded to 16-byte boundary
	plainLen := 1 + len(password)
	paddedLen := ((plainLen + 15) / 16) * 16
	if paddedLen == 0 {
		paddedLen = 16
	}
	plaintext := make([]byte, paddedLen)
	plaintext[0] = byte(len(password))
	copy(plaintext[1:], password)

	encrypted := make([]byte, paddedLen)

	// Create hash input buffer: secret + authenticator + salt for first block
	hashInput := make([]byte, len(secret)+16+2)
	copy(hashInput, secret)
	copy(hashInput[len(secret):], authenticator[:])
	copy(hashInput[len(secret)+16:], salt[:])

	// First block: XOR with MD5(secret + authenticator + salt)
	hash := md5.Sum(hashInput)
	for i := range 16 {
		encrypted[i] = plaintext[i] ^ hash[i]
	}

	// Subsequent blocks: XOR with MD5(secret + previous encrypted block),
	// reusing the prefix of the first-block hash input buffer
	hashInputSubseq := hashInput[:len(secret)+16]
	for block := 1; block < paddedLen/16; block++ {
		offset := block * 16
		prevBlock := encrypted[offset-16 : offset]
		copy(hashInputSubseq[len(secret):], prevBlock)
		hash = md5.Sum(hashInputSubseq)

		for i := range 16 {
			encrypted[offset+i] = plaintext[offset+i] ^ hash[i]
		}
	}

	// Result: salt (unencrypted) + encrypted data
	result := make([]byte, 2+len(encrypted))
	copy(result, salt[:])
	copy(result[2:], encrypted)

	return result
}

// encryptAscendSecret implements the Ascend-Send-Secret/Ascend-Receive-Secret cipher
// as implemented by FreeRADIUS make_secret: digest = MD5(authenticator + secret), the
// first min(len(value), 16) octets of the digest are XORed with the value, and the
// result is always sixteen octets (a single block, no chaining).
func encryptAscendSecret(value []byte, secret []byte, authenticator [16]byte) []byte {
	hashInput := make([]byte, AuthenticatorLength+len(secret))
	copy(hashInput, authenticator[:])
	copy(hashInput[AuthenticatorLength:], secret)
	digest := md5.Sum(hashInput)

	n := min(len(value), AuthenticatorLength)
	for i := range n {
		digest[i] ^= value[i]
	}
	return digest[:]
}

// decryptUserPassword reverses encryptUserPassword (RFC 2865 Section 5.2).
// Each block is XORed with MD5(secret + previous ciphertext block), with the
// authenticator seeding the first block; trailing NUL padding is stripped.
func decryptUserPassword(encrypted []byte, secret []byte, authenticator [16]byte) ([]byte, error) {
	if len(encrypted) == 0 || len(encrypted)%16 != 0 {
		return nil, fmt.Errorf("encrypted User-Password length %d is not a positive multiple of 16", len(encrypted))
	}

	decrypted := make([]byte, len(encrypted))

	hashInput := make([]byte, len(secret)+16)
	copy(hashInput, secret)
	copy(hashInput[len(secret):], authenticator[:])

	for block := 0; block < len(encrypted)/16; block++ {
		offset := block * 16
		hash := md5.Sum(hashInput)
		for i := range 16 {
			decrypted[offset+i] = encrypted[offset+i] ^ hash[i]
		}
		// The next block is chained on this block's ciphertext
		copy(hashInput[len(secret):], encrypted[offset:offset+16])
	}

	return bytes.TrimRight(decrypted, "\x00"), nil
}

// decryptTunnelPassword reverses encryptTunnelPassword (RFC 2868 Section 3.5):
// the 2-octet salt seeds the first block hash together with the authenticator,
// and the first plaintext octet carries the password length.
func decryptTunnelPassword(encrypted []byte, secret []byte, authenticator [16]byte) ([]byte, error) {
	if len(encrypted) < 2+16 || (len(encrypted)-2)%16 != 0 {
		return nil, fmt.Errorf("encrypted Tunnel-Password length %d is not a salt plus a positive multiple of 16", len(encrypted))
	}

	salt := encrypted[:2]
	data := encrypted[2:]
	decrypted := make([]byte, len(data))

	hashInput := make([]byte, len(secret)+16+2)
	copy(hashInput, secret)
	copy(hashInput[len(secret):], authenticator[:])
	copy(hashInput[len(secret)+16:], salt)

	// First block: XOR with MD5(secret + authenticator + salt)
	hash := md5.Sum(hashInput)
	for i := range 16 {
		decrypted[i] = data[i] ^ hash[i]
	}

	// Subsequent blocks: XOR with MD5(secret + previous ciphertext block)
	hashInputSubseq := hashInput[:len(secret)+16]
	for block := 1; block < len(data)/16; block++ {
		offset := block * 16
		copy(hashInputSubseq[len(secret):], data[offset-16:offset])
		hash = md5.Sum(hashInputSubseq)
		for i := range 16 {
			decrypted[offset+i] = data[offset+i] ^ hash[i]
		}
	}

	passwordLen := int(decrypted[0])
	if passwordLen > len(decrypted)-1 {
		return nil, fmt.Errorf("Tunnel-Password length octet %d exceeds decrypted data %d", passwordLen, len(decrypted)-1)
	}

	return decrypted[1 : 1+passwordLen], nil
}

// decryptAscendSecret reverses encryptAscendSecret: the single 16-octet block
// is XORed with MD5(authenticator + secret) and trailing NUL padding stripped.
func decryptAscendSecret(encrypted []byte, secret []byte, authenticator [16]byte) ([]byte, error) {
	if len(encrypted) != AuthenticatorLength {
		return nil, fmt.Errorf("encrypted Ascend secret length %d is not %d", len(encrypted), AuthenticatorLength)
	}

	hashInput := make([]byte, AuthenticatorLength+len(secret))
	copy(hashInput, authenticator[:])
	copy(hashInput[AuthenticatorLength:], secret)
	digest := md5.Sum(hashInput)

	decrypted := make([]byte, AuthenticatorLength)
	for i := range decrypted {
		decrypted[i] = encrypted[i] ^ digest[i]
	}

	return bytes.TrimRight(decrypted, "\x00"), nil
}

// squeezeTaggedInteger converts a 4-octet encoded integer into the 3-octet form used
// by tagged integer attributes (RFC 2868 Sections 3.1-3.3). Values that do not fit in
// three octets are an error. Non-integer values pass through unchanged.
func squeezeTaggedInteger(attrDef *AttributeDefinition, attrValue []byte) ([]byte, error) {
	if attrDef.DataType != DataTypeInteger || len(attrValue) != 4 {
		return attrValue, nil
	}
	if attrValue[0] != 0 {
		return nil, fmt.Errorf("attribute %q value exceeds three-octet tagged integer range", attrDef.Name)
	}
	return attrValue[1:], nil
}

// padTaggedInteger restores the 4-octet integer form from the 3-octet value carried by
// tagged integer attributes (RFC 2868 Sections 3.1-3.3) so DecodeInteger can parse it.
func padTaggedInteger(attrDef *AttributeDefinition, value []byte) []byte {
	if attrDef.DataType != DataTypeInteger || len(value) != 3 {
		return value
	}
	padded := make([]byte, 4)
	copy(padded[1:], value)
	return padded
}

// multilineSplittable reports whether an encoded value must be fragmented across
// multiple attribute instances with the continuation marker. Only plain string
// attributes participate: tags and encryption do not compose with fragmentation.
func multilineSplittable(attrDef *AttributeDefinition, attrValue []byte, maxLen int) bool {
	return attrDef.Multiline &&
		attrDef.DataType == DataTypeString &&
		!attrDef.HasTag &&
		attrDef.Encryption == EncryptionNone &&
		len(attrValue) > maxLen
}

// addArrayAttribute handles array attributes (multiple values for same attribute)
// If value is a slice, it adds each element as a separate attribute instance
func (p *Packet) addArrayAttribute(attrDef *AttributeDefinition, value any, tag uint8) error {
	if attrDef == nil {
		return nil
	}

	values := []any{value}

	// Try to convert to slice for array handling
	switch v := value.(type) {
	case []any:
		values = v
	case []string:
		values = make([]any, len(v))
		for i, s := range v {
			values[i] = s
		}
	case []int:
		values = make([]any, len(v))
		for i, n := range v {
			values[i] = n
		}
	case []uint32:
		values = make([]any, len(v))
		for i, n := range v {
			values[i] = n
		}
	case [][]byte:
		values = make([]any, len(v))
		for i, b := range v {
			values[i] = b
		}
	}

	// Add each value as a separate attribute
	for _, val := range values {
		attrValue, err := p.encodeAttributeValue(val, attrDef)
		if err != nil {
			return fmt.Errorf("failed to encode attribute %q: %w", attrDef.Name, err)
		}

		// Multiline attributes carry long values as multiple instances, each but
		// the last ending with the continuation marker (observed Junos behavior)
		if multilineSplittable(attrDef, attrValue, MaxAttributeValueLength) {
			for _, chunk := range SplitMultilineAttribute(string(attrValue), MaxAttributeValueLength) {
				p.AddAttribute(NewAttribute(uint8(attrDef.ID), []byte(chunk)))
			}
			continue
		}

		// RFC 2865 Section 5.2: passwords are limited to 128 octets
		if attrDef.Encryption == EncryptionUserPassword && len(attrValue) > MaxUserPasswordLength {
			return fmt.Errorf("attribute %q password length %d exceeds maximum %d octets", attrDef.Name, len(attrValue), MaxUserPasswordLength)
		}

		// Encryption is deferred to encode time (when the authenticator is
		// final); the plaintext is stored and the value region recorded.
		if attrDef.HasTag {
			attrValue, err = squeezeTaggedInteger(attrDef, attrValue)
			if err != nil {
				return err
			}
			// RFC 2868: tagged attributes always carry the tag octet; 0 means untagged
			// Validate the length the value will have on the wire, including
			// the tag octet and any growth from deferred encryption
			if finalLen := encryptedValueLength(len(attrValue), attrDef.Encryption) + 1; finalLen > MaxAttributeValueLength {
				return fmt.Errorf("attribute %q value length %d exceeds maximum %d bytes", attrDef.Name, finalLen, MaxAttributeValueLength)
			}
			taggedValue := make([]byte, len(attrValue)+1)
			taggedValue[0] = tag
			copy(taggedValue[1:], attrValue)
			attr := NewAttribute(uint8(attrDef.ID), taggedValue)
			if attrDef.Encryption != "" {
				attr.encryption = attrDef.Encryption
				attr.encryptOffset = 1 // skip the leading tag octet
			}
			p.AddAttribute(attr)
		} else {
			// Validate the on-wire length, including growth from deferred encryption
			if finalLen := encryptedValueLength(len(attrValue), attrDef.Encryption); finalLen > MaxAttributeValueLength {
				return fmt.Errorf("attribute %q value length %d exceeds maximum %d bytes", attrDef.Name, finalLen, MaxAttributeValueLength)
			}
			attr := NewAttribute(uint8(attrDef.ID), attrValue)
			if attrDef.Encryption != "" {
				attr.encryption = attrDef.Encryption
			}
			p.AddAttribute(attr)
		}
	}
	return nil
}

// encryptedValueLength returns the on-wire size of an attribute value after
// deferred encryption expands it. User-Password pads to a 16-octet multiple
// (RFC 2865 Section 5.2); Tunnel-Password adds a 2-octet salt plus a length
// octet before padding (RFC 2868 Section 3.5); Ascend-Secret is a single
// 16-octet block. Unencrypted values keep their length.
func encryptedValueLength(plainLen int, encryption EncryptionType) int {
	switch encryption {
	case EncryptionUserPassword:
		return max(((plainLen+15)/16)*16, 16)
	case EncryptionTunnelPassword:
		return 2 + ((1+plainLen+15)/16)*16
	case EncryptionAscendSecret:
		return 16
	default:
		return plainLen
	}
}

type vendorAttrParams struct {
	vendor  *VendorDefinition
	attrDef *AttributeDefinition
	value   any
	tag     uint8
}

// addVendorArrayAttribute handles vendor array attributes
// If value is a slice, it adds each element as a separate vendor attribute instance
func (p *Packet) addVendorArrayAttribute(params vendorAttrParams) error {
	vendor, attrDef, value, tag := params.vendor, params.attrDef, params.value, params.tag
	if vendor == nil || attrDef == nil {
		return nil
	}

	// The vendor data cap depends on the vendor's VSA header widths: the
	// outer attribute value (max 253 octets) carries the 4-octet Vendor-Id
	// plus the vendor type and length fields.
	typeOctets, lengthOctets := p.vsaFormat(vendor.ID)
	maxVendorData := MaxAttributeValueLength - 4 - typeOctets - lengthOctets

	values := []any{value}

	// Try to convert to slice for array handling
	switch v := value.(type) {
	case []any:
		values = v
	case []string:
		values = make([]any, len(v))
		for i, s := range v {
			values[i] = s
		}
	case []int:
		values = make([]any, len(v))
		for i, n := range v {
			values[i] = n
		}
	case []uint32:
		values = make([]any, len(v))
		for i, n := range v {
			values[i] = n
		}
	case [][]byte:
		values = make([]any, len(v))
		for i, b := range v {
			values[i] = b
		}
	}

	// Add each value as a separate vendor attribute
	for _, val := range values {
		attrValue, err := p.encodeAttributeValue(val, attrDef)
		if err != nil {
			return fmt.Errorf("failed to encode vendor attribute %q: %w", attrDef.Name, err)
		}

		// Multiline attributes carry long values as multiple instances, each but
		// the last ending with the continuation marker (observed Junos behavior)
		if multilineSplittable(attrDef, attrValue, maxVendorData) {
			for _, chunk := range SplitMultilineAttribute(string(attrValue), maxVendorData) {
				p.AddVendorAttribute(NewVendorAttribute(vendor.ID, attrDef.ID, []byte(chunk)))
			}
			continue
		}

		// RFC 2865 Section 5.2: passwords are limited to 128 octets
		if attrDef.Encryption == EncryptionUserPassword && len(attrValue) > MaxUserPasswordLength {
			return fmt.Errorf("attribute %q password length %d exceeds maximum %d octets", attrDef.Name, len(attrValue), MaxUserPasswordLength)
		}

		// Encryption is deferred to encode time; the plaintext vendor data is
		// stored and encrypted in place once the authenticator is final.
		var vsa *VendorAttribute
		if attrDef.HasTag {
			attrValue, err = squeezeTaggedInteger(attrDef, attrValue)
			if err != nil {
				return err
			}
			// RFC 2868: tagged attributes always carry the tag octet; 0 means untagged
			// Validate the on-wire vendor data length, including the tag octet
			// and any growth from deferred encryption
			if finalLen := encryptedValueLength(len(attrValue), attrDef.Encryption) + 1; finalLen > maxVendorData {
				return fmt.Errorf("vendor attribute %q value length %d exceeds maximum %d bytes", attrDef.Name, finalLen, maxVendorData)
			}
			vsa = NewTaggedVendorAttribute(vendor.ID, attrDef.ID, tag, attrValue)
		} else {
			// Validate the on-wire vendor data length, including growth from
			// deferred encryption
			if finalLen := encryptedValueLength(len(attrValue), attrDef.Encryption); finalLen > maxVendorData {
				return fmt.Errorf("vendor attribute %q value length %d exceeds maximum %d bytes", attrDef.Name, finalLen, maxVendorData)
			}
			vsa = NewVendorAttribute(vendor.ID, attrDef.ID, attrValue)
		}
		attr := p.AddVendorAttribute(vsa)
		if attrDef.Encryption != "" {
			attr.encryption = attrDef.Encryption
			attr.encryptOffset = p.vsaDataOffset(vendor.ID, attrDef.HasTag)
			attr.vsaLengthPos = 4 + typeOctets
			attr.vsaLengthWidth = lengthOctets
		}
	}
	return nil
}

// ListAttributes returns a list of unique attribute names found in the
// Requires a dictionary to be set on the  Returns empty slice if dictionary is nil.
// Attributes not found in dictionary are skipped.
// VSA attributes return their attribute name (e.g., "erx-dhcp-mac-addr").
func (p *Packet) ListAttributes() []string {
	if p.Dict == nil {
		return []string{}
	}

	seen := make(map[string]struct{}, len(p.Attributes))
	result := make([]string, 0, len(p.Attributes))

	addName := func(name string) {
		if _, exists := seen[name]; !exists {
			seen[name] = struct{}{}
			result = append(result, name)
		}
	}

	for i, attr := range p.Attributes {
		if attr.Type == AttributeTypeVendorSpecific {
			vas, err := p.getParsedVSAs(i, attr)
			if err != nil {
				continue
			}
			for _, va := range vas {
				if attrDef, found := p.Dict.LookupVendorAttributeByID(va.VendorID, va.VendorType); found {
					addName(attrDef.Name)
				}
			}
			continue
		}

		// Standard attribute
		if attrDef, exists := p.Dict.LookupStandardByID(uint32(attr.Type)); exists {
			addName(attrDef.Name)
		}
	}

	return result
}

// GetAttribute returns all values for the given attribute name.
// Works for both standard and VSA attributes.
// Returns empty slice if dictionary is nil or attribute not found.
func (p *Packet) GetAttribute(name string) []AttributeValue {
	if p.Dict == nil {
		return []AttributeValue{}
	}

	var result []AttributeValue

	// Try to find as standard attribute
	if attrDef, exists := p.Dict.LookupStandardByName(name); exists {
		// RFC 6929 extended attributes match on base type + extended type, not ID.
		if attrDef.Extended {
			return p.getExtendedAttribute(attrDef)
		}
		for _, attr := range p.Attributes {
			if attr.Type == uint8(attrDef.ID) {
				// For tagged attributes (HasTag=true), a first octet of 0x00-0x1F is
				// the tag; RFC 2868 Section 3 treats a greater first octet as part
				// of the attribute data, sent without a tag octet
				tag := uint8(0)
				value := attr.Value
				if attrDef.HasTag && len(attr.Value) > 0 && attr.Value[0] <= MaxAttributeTag {
					tag = attr.Value[0]
					value = padTaggedInteger(attrDef, attr.Value[1:]) // Strip tag byte
				}
				value = p.decryptedAttributeValue(attr, attrDef, value)

				result = append(result, AttributeValue{
					Name:      attrDef.Name,
					Type:      attr.Type,
					DataType:  attrDef.DataType,
					Value:     value,
					Tag:       tag,
					IsVSA:     false,
					Multiline: attrDef.Multiline,
					def:       attrDef,
				})
			}
		}
		return result
	}

	// Try to find as vendor attribute using unified lookup
	if attrDef, exists := p.Dict.LookupByAttributeName(name); exists {
		// Find vendor ID for this attribute using O(1) lookup
		vendorID, exists := p.Dict.LookupVendorIDByAttributeName(name)
		if !exists {
			return []AttributeValue{}
		}

		// Search packet attributes for this vendor attribute
		for i, pktAttr := range p.Attributes {
			if pktAttr.Type != AttributeTypeVendorSpecific {
				continue
			}
			vas, err := p.getParsedVSAs(i, pktAttr)
			if err != nil {
				continue
			}

			for _, va := range vas {
				if va.VendorID != vendorID || va.VendorType != attrDef.ID {
					continue
				}
				// For tagged attributes (HasTag=true), a first octet of 0x00-0x1F is
				// the tag; RFC 2868 Section 3 treats a greater first octet as part
				// of the attribute data, sent without a tag octet
				tag := uint8(0)
				value := va.Value
				if attrDef.HasTag && len(va.Value) > 0 && va.Value[0] <= MaxAttributeTag {
					tag = va.Value[0]
					value = padTaggedInteger(attrDef, va.Value[1:]) // Strip tag byte
				}
				value = p.decryptedAttributeValue(pktAttr, attrDef, value)

				result = append(result, AttributeValue{
					Name:       attrDef.Name,
					Type:       pktAttr.Type,
					DataType:   attrDef.DataType,
					Value:      value,
					Tag:        tag,
					IsVSA:      true,
					VendorID:   va.VendorID,
					VendorType: va.VendorType,
					Multiline:  attrDef.Multiline,
					def:        attrDef,
				})
			}
		}
		return result
	}

	return []AttributeValue{}
}

// decryptedAttributeValue decrypts an encrypted attribute value when the
// dictionary declares an Encryption type and the packet state permits: the
// Secret is set, the attribute is not still awaiting deferred encryption (its
// bytes would be plaintext), and the keying authenticator is known — the
// packet's own for requests, the bound Request Authenticator for responses.
// On a decrypt error the raw value is returned unchanged.
func (p *Packet) decryptedAttributeValue(attr *Attribute, attrDef *AttributeDefinition, value []byte) []byte {
	if attrDef.Encryption == EncryptionNone || len(p.Secret) == 0 || attr.encryption != EncryptionNone {
		return value
	}

	auth, ok := p.encryptionAuthenticator()
	if !ok {
		return value
	}

	decrypted, err := DecryptAttributeValue(value, attrDef.Encryption, p.Secret, auth)
	if err != nil {
		return value
	}
	return decrypted
}

// GetAttributes returns the packet as a flat attribute map: attribute name (with
// a ":tag" suffix when tagged) to the slice of values present. Container
// attributes are expanded so each child appears under its own flat child name.
// Values use the native decoded Go type for scalars; unknown attributes are
// skipped.
func (p *Packet) GetAttributes() map[string][]AttributeValue {
	out := make(map[string][]AttributeValue)
	if p.Dict == nil {
		return out
	}

	for _, name := range p.ListAttributes() {
		for _, av := range p.GetAttribute(name) {
			// Expand container attributes into their flat child keys. Each child
			// is surfaced as its own AttributeValue so metadata is preserved.
			if av.DataType == DataTypeTLV || av.DataType == DataTypeStruct || av.DataType == DataTypeEVS {
				for _, child := range p.containerChildValues(av) {
					key := child.Name
					if av.Tag != 0 {
						key = fmt.Sprintf("%s:%d", child.Name, av.Tag)
					}
					out[key] = append(out[key], child)
				}
				continue
			}

			key := av.Name
			if av.Tag != 0 {
				key = fmt.Sprintf("%s:%d", av.Name, av.Tag)
			}
			out[key] = append(out[key], av)
		}
	}

	return out
}

// containerChildValues decodes a container attribute (struct/tlv/evs) into a
// slice of child AttributeValues, each carrying its own name, data type, and
// raw bytes so the flat map preserves per-child metadata.
func (p *Packet) containerChildValues(av AttributeValue) []AttributeValue {
	if av.def == nil {
		return nil
	}

	raw, err := av.Children()
	if err != nil {
		return nil
	}

	result := make([]AttributeValue, 0, len(raw))
	for _, childDef := range av.def.Children {
		decoded, ok := raw[childDef.Name]
		if !ok {
			continue
		}
		result = append(result, AttributeValue{
			Name:       childDef.Name,
			DataType:   childDef.DataType,
			Value:      encodeContainerChild(childDef, decoded, raw),
			IsVSA:      av.IsVSA,
			VendorID:   av.VendorID,
			VendorType: av.VendorType,
			def:        childDef,
			decoded:    decoded,
		})
	}
	return result
}

// encodeContainerChild re-encodes a decoded container child to raw bytes for
// the AttributeValue view. Bit-field members encode as an 8-octet big-endian
// integer; a union member re-encodes its selected variant (chosen by the key
// sibling in the same decoded map); scalar members use their natural encoding.
// A child with no byte representation yields nil, with the decoded native
// value still available via Decoded().
func encodeContainerChild(childDef *AttributeDefinition, decoded any, siblings map[string]any) []byte {
	switch childDef.DataType {
	case DataTypeBits:
		if v, ok := decoded.(uint64); ok {
			return EncodeInteger64(v)
		}
	case DataTypeUnion:
		sub, ok := decoded.(map[string]any)
		if !ok {
			return nil
		}
		key, err := unionKeyFromResult(siblings, childDef)
		if err != nil {
			return nil
		}
		variant := unionVariant(childDef, key)
		if variant == nil {
			return nil
		}
		if encoded, err := EncodeStruct(variant, sub); err == nil {
			return encoded
		}
	default:
		if encoded, err := EncodeValue(decoded, childDef.DataType); err == nil {
			return encoded
		}
	}
	return nil
}

// getExtendedAttribute collects RFC 6929 extended attribute values for the given
// definition. Short extended attributes (241-244) each yield one value; long extended
// attributes (245-246) are reassembled across consecutive fragments using the More bit.
func (p *Packet) getExtendedAttribute(attrDef *AttributeDefinition) []AttributeValue {
	baseType := attrDef.ExtendedBaseType()
	extType := attrDef.ExtendedType()

	var result []AttributeValue

	// Extended-Vendor-Specific: match on base type, EVS extended type, and the
	// vendor ID/type, surfacing the inner value with the vendor header stripped.
	if attrDef.DataType == DataTypeEVS {
		for _, attr := range p.Attributes {
			if attr.Type != baseType {
				continue
			}
			vendorID, vendorType, value, err := ParseEVS(attr)
			if err != nil || vendorID != attrDef.VendorID || vendorType != attrDef.VendorType {
				continue
			}
			av := p.newExtendedValue(attrDef, baseType, value)
			av.IsVSA = true
			av.VendorID = vendorID
			av.VendorType = uint32(vendorType)
			result = append(result, av)
		}
		return result
	}

	if !IsLongExtendedBaseType(baseType) {
		for _, attr := range p.Attributes {
			if attr.Type != baseType {
				continue
			}
			et, value, err := ParseExtendedAttribute(attr)
			if err != nil || et != extType {
				continue
			}
			result = append(result, p.newExtendedValue(attrDef, baseType, value))
		}
		return result
	}

	// Long extended: reassemble fragments that share the same extended type.
	// RFC 6929 Section 2.2 requires fragments of one value to be consecutive
	// attributes, a fragment with More set to be full-size, and the final
	// fragment to clear More; chains violating any of these are invalid
	// attributes and are discarded (Section 2.8), never surfaced as values.
	var buf []byte
	collecting := false
	prevIdx := 0
	for i, attr := range p.Attributes {
		if attr.Type != baseType {
			continue
		}
		et, more, value, err := parseLongExtendedFragment(attr)
		if err != nil || et != extType {
			continue
		}

		// A continuation that is not the attribute immediately following the
		// previous fragment invalidates the pending chain; this fragment
		// starts a new chain instead.
		if collecting && i != prevIdx+1 {
			buf = nil
		}

		// More set on a fragment that is not full-size is invalid: the More
		// flag MUST be clear when Length is below the maximum.
		if more && len(value) != MaxLongExtendedValueLength {
			buf = nil
			collecting = false
			continue
		}

		prevIdx = i
		buf = append(buf, value...)
		collecting = true
		if !more {
			result = append(result, p.newExtendedValue(attrDef, baseType, buf))
			buf = nil
			collecting = false
		}
	}

	return result
}

// newExtendedValue builds an AttributeValue for a reassembled extended attribute.
func (p *Packet) newExtendedValue(attrDef *AttributeDefinition, baseType uint8, value []byte) AttributeValue {
	return AttributeValue{
		Name:      attrDef.Name,
		Type:      baseType,
		DataType:  attrDef.DataType,
		Value:     value,
		Multiline: attrDef.Multiline,
		def:       attrDef,
	}
}

// GetAttributeString returns the attribute value(s) as a string.
// If the attribute is marked as multiline in the dictionary, it automatically
// joins multiple instances using JoinMultilineAttribute.
// For non-multiline attributes, it returns the first value's String() representation.
func (p *Packet) GetAttributeString(name string) string {
	values := p.GetAttribute(name)
	if len(values) == 0 {
		return ""
	}

	// If multiline is enabled and we have multiple values, join them
	if values[0].Multiline && len(values) > 1 {
		stringValues := make([]string, len(values))
		for i, v := range values {
			stringValues[i] = v.String()
		}
		return JoinMultilineAttribute(stringValues)
	}

	// Return first value as string
	return values[0].String()
}

// String returns a string representation of the packet
func (p *Packet) String() string {
	return fmt.Sprintf("Code=%s(%d), ID=%d, Length=%d, Attributes=%d",
		p.Code.String(), p.Code, p.Identifier, p.Length, len(p.Attributes))
}

// JoinMultilineAttribute combines multiple attribute values into a single string.
// It handles vendor-specific attributes that exceed the 253-byte limit by
// removing continuation markers and joining the values.
//
// RADIUS attributes have a maximum length of 255 bytes (2 bytes for Type and Length,
// leaving 253 bytes for data). Vendor-specific attributes further reduce this to
// approximately 247 bytes after accounting for vendor ID and vendor type fields.
//
// For attributes exceeding this limit, multiple instances can be sent with a
// continuation marker (default: "<contd>") appended to all but the last value.
//
// Example:
//
//	values := []string{"first part<contd>", "second part<contd>", "last part"}
//	result := JoinMultilineAttribute(values) // Returns: "first partsecond partlast part"
func JoinMultilineAttribute(values []string) string {
	if len(values) == 0 {
		return ""
	}

	if len(values) == 1 {
		return strings.TrimSuffix(values[0], ContinuationMarker)
	}

	var b strings.Builder
	for _, row := range values {
		b.WriteString(strings.TrimSuffix(row, ContinuationMarker))
	}

	return b.String()
}

// SplitMultilineAttribute splits a long string into multiple attribute values
// that fit within the RADIUS attribute size limit.
//
// Each chunk will be no longer than maxLength bytes. All chunks except the last
// will have the continuation marker appended.
//
// Parameters:
//   - value: The string to split
//   - maxLength: Maximum length per chunk (should be 247 for VSA, 253 for standard attributes)
//
// Returns a slice of strings, each suitable for a separate RADIUS attribute instance.
//
// Example:
//
//	longString := strings.Repeat("x", 500)
//	chunks := SplitMultilineAttribute(longString, 247)
//	// chunks[0] will end with "<contd>"
//	// chunks[1] will end with "<contd>"
//	// chunks[2] will be the remainder without "<contd>"
func SplitMultilineAttribute(value string, maxLength int) []string {
	if len(value) == 0 {
		return []string{""}
	}

	markerLen := len(ContinuationMarker)
	chunkSize := maxLength - markerLen

	if chunkSize <= 0 {
		chunkSize = maxLength
	}

	if len(value) <= maxLength {
		return []string{value}
	}

	var chunks []string
	remaining := value

	for len(remaining) > 0 {
		if len(remaining) <= maxLength {
			chunks = append(chunks, remaining)
			break
		}

		chunk := remaining[:chunkSize]
		chunks = append(chunks, chunk+ContinuationMarker)
		remaining = remaining[chunkSize:]
	}

	return chunks
}
