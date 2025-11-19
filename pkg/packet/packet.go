package packet

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"time"

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

// AttributeValue contains a single attribute value with type information
type AttributeValue struct {
	Name       string              // Attribute name from dictionary
	Type       uint8               // Attribute type ID (26 for VSA)
	DataType   dictionary.DataType // Data type (string, integer, ipaddr, etc.)
	Value      []byte              // Raw value bytes
	Tag        uint8               // Tag value for tagged attributes (0 = no tag)
	IsVSA      bool                // True if this is a vendor-specific attribute
	VendorID   uint32              // Vendor ID (only for VSA)
	VendorType uint8               // Vendor attribute type (only for VSA)
}

// String returns the attribute value as a string, decoded based on DataType
func (av AttributeValue) String() string {
	switch av.DataType {
	case dictionary.DataTypeString:
		return DecodeString(av.Value)

	case dictionary.DataTypeInteger:
		val, err := DecodeInteger(av.Value)
		if err != nil {
			return fmt.Sprintf("0x%x", av.Value)
		}
		return fmt.Sprintf("%d", val)

	case dictionary.DataTypeIPAddr:
		ip, err := DecodeIPAddr(av.Value)
		if err != nil {
			return fmt.Sprintf("0x%x", av.Value)
		}
		return ip.String()

	case dictionary.DataTypeIPv6Addr:
		ip, err := DecodeIPv6Addr(av.Value)
		if err != nil {
			return fmt.Sprintf("0x%x", av.Value)
		}
		return ip.String()

	case dictionary.DataTypeDate:
		t, err := DecodeDate(av.Value)
		if err != nil {
			return fmt.Sprintf("0x%x", av.Value)
		}
		return t.Format(time.RFC3339)

	case dictionary.DataTypeOctets:
		return fmt.Sprintf("0x%x", av.Value)

	default:
		// For unknown types, return hex representation
		return fmt.Sprintf("0x%x", av.Value)
	}
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

// GetAttributes returns all attributes with the specified type
// INTERNAL: This method is for internal library use only and may be removed in future versions.
// Users should use GetAttribute(name string) instead.
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
// INTERNAL: This method is for internal library use only and may be removed in future versions.
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
		return removed
	}

	// Try vendor attribute
	// Parse vendor:attribute format
	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 {
		return 0
	}

	vendorName := parts[0]
	attrName := parts[1]

	// Lookup vendor
	vendors := p.Dict.GetAllVendors()
	var vendorID uint32
	var vendorAttrID uint8
	found := false

	for _, vendor := range vendors {
		if vendor.Name == vendorName {
			vendorID = vendor.ID
			// Look for the attribute in this vendor
			for _, attr := range vendor.Attributes {
				if attr.Name == attrName {
					vendorAttrID = uint8(attr.ID)
					found = true
					break
				}
			}
			break
		}
	}

	if !found {
		return 0
	}

	// Remove all VSAs matching this vendor and attribute ID
	for i := len(p.Attributes) - 1; i >= 0; i-- {
		if p.Attributes[i].Type == 26 { // VSA
			va, err := ParseVSA(p.Attributes[i])
			if err == nil && va.VendorID == vendorID && va.VendorType == vendorAttrID {
				p.Length -= uint16(p.Attributes[i].Length)
				p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
				removed++
			}
		}
	}

	return removed
}

// SetAuthenticator sets the packet authenticator
// INTERNAL: This method is for internal library use only and may be removed in future versions.
// Authenticators are managed automatically by the server.
func (p *Packet) SetAuthenticator(auth [AuthenticatorLength]byte) {
	p.Authenticator = auth
}

// CalculateResponseAuthenticator calculates the Response Authenticator for Access-Accept, Access-Reject, and Access-Challenge packets
// INTERNAL: This method is for internal library use only and may be removed in future versions.
// Authenticators are managed automatically by the server.
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

	// Append secret and calculate MD5 hash
	packetBytes = append(packetBytes, secret...)
	hash := md5.Sum(packetBytes)
	return hash
}

// CalculateRequestAuthenticator calculates the Request Authenticator for Access-Request packets
// INTERNAL: This method is for internal library use only and may be removed in future versions.
// Authenticators are managed automatically by the server/client.
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

	// Append secret and calculate MD5 hash
	packetBytes = append(packetBytes, secret...)
	hash := md5.Sum(packetBytes)
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

// AddAttributeByName adds an attribute to the packet using dictionary lookup with full feature support
func (p *Packet) AddAttributeByName(name string, value interface{}) error {
	if p.Dict == nil {
		return fmt.Errorf("no dictionary loaded")
	}

	// Try standard attribute first
	if attrDef, exists := p.Dict.LookupStandardByName(name); exists {
		p.addStandardAttribute(name, value, attrDef, nil, [16]byte{})
		return nil
	}

	// Handle vendor attributes
	if err := p.addVendorAttributeByName(name, value, nil, [16]byte{}); err != nil {
		return err
	}

	return nil
}

// AddAttributeByNameWithSecret adds an attribute with encryption support using shared secret
func (p *Packet) AddAttributeByNameWithSecret(name string, value interface{}, secret []byte, authenticator [16]byte) error {
	if p.Dict == nil {
		return fmt.Errorf("no dictionary loaded")
	}

	// Try standard attribute first
	if attrDef, exists := p.Dict.LookupStandardByName(name); exists {
		p.addStandardAttribute(name, value, attrDef, secret, authenticator)
		return nil
	}

	// Handle vendor attributes
	if err := p.addVendorAttributeByName(name, value, secret, authenticator); err != nil {
		return err
	}

	return nil
}

// addStandardAttribute handles standard attribute addition with full feature support
func (p *Packet) addStandardAttribute(name string, value interface{}, attrDef *dictionary.AttributeDefinition, secret []byte, authenticator [16]byte) {
	// Handle tagged attributes by extracting the tag
	var tag uint8

	if strings.Contains(name, ":") && attrDef.HasTag {
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			if tagValue := parts[1]; tagValue != "" {
				if parsedTag, err := strconv.ParseUint(tagValue, 10, 8); err == nil {
					tag = uint8(parsedTag)
				}
			}
		}
	}

	// Handle enumerated values - convert string names to integers
	processedValue := p.processEnumeratedValue(value, attrDef)

	// Handle array attributes - check if value is a slice
	// This handles both attributes marked as Array=true and user-provided slices
	p.addArrayAttribute(attrDef, processedValue, tag, secret, authenticator)
}

// addVendorAttributeByName handles vendor-specific attribute addition with full feature support
// Supports formats:
//   - "AttributeName" - vendor attribute without tag
//   - "AttributeName:tag" - vendor attribute with tag (tag is a number)
func (p *Packet) addVendorAttributeByName(name string, value interface{}, secret []byte, authenticator [16]byte) error {
	var attrName string
	var tag uint8

	// Parse the name format (attribute:tag)
	parts := strings.SplitN(name, ":", 2)
	attrName = parts[0]

	// Check if there's a tag
	if len(parts) == 2 {
		if tagValue := parts[1]; tagValue != "" {
			if parsedTag, err := strconv.ParseUint(tagValue, 10, 8); err == nil {
				tag = uint8(parsedTag)
			}
		}
	}

	// Search all vendors for this attribute name
	vendors := p.Dict.GetAllVendors()
	for _, vendor := range vendors {
		for _, attrDef := range vendor.Attributes {
			if attrDef.Name == attrName {
				// Handle enumerated values
				processedValue := p.processEnumeratedValue(value, attrDef)

				// Handle array attributes - check if value is a slice
				// This handles both attributes marked as Array=true and user-provided slices
				p.addVendorArrayAttribute(vendor, attrDef, processedValue, tag, secret, authenticator)
				return nil
			}
		}
	}

	return fmt.Errorf("attribute %q not found in dictionary", name)
}

// processEnumeratedValue converts string enumerated values to integers
func (p *Packet) processEnumeratedValue(value interface{}, attrDef *dictionary.AttributeDefinition) interface{} {
	if len(attrDef.Values) == 0 {
		return value
	}

	// If value is a string, try to find it in enumerated values
	if strValue, ok := value.(string); ok {
		if enumValue, exists := attrDef.Values[strValue]; exists {
			return enumValue
		}
	}

	return value
}

// encodeAttributeValue encodes a value based on the attribute data type
func (p *Packet) encodeAttributeValue(value interface{}, attrDef *dictionary.AttributeDefinition) ([]byte, error) {
	return EncodeValue(value, attrDef.DataType)
}

// EncryptAttributeValue applies encryption to attribute values using the shared secret
func EncryptAttributeValue(value []byte, encryption dictionary.EncryptionType, secret []byte, authenticator [16]byte) []byte {
	switch encryption {
	case dictionary.EncryptionUserPassword:
		return encryptUserPassword(value, secret, authenticator)
	case dictionary.EncryptionTunnelPassword:
		return encryptTunnelPassword(value, secret, authenticator)
	case dictionary.EncryptionAscendSecret:
		return encryptAscendSecret(value, secret, authenticator)
	default:
		return value
	}
}

// encryptUserPassword implements User-Password encryption (RFC 2865, Section 5.2)
func encryptUserPassword(password []byte, secret []byte, authenticator [16]byte) []byte {
	// User-Password encryption:
	// 1. Pad password to multiple of 16 bytes with null bytes
	// 2. XOR with MD5(secret + authenticator) for first 16 bytes
	// 3. XOR with MD5(secret + previous encrypted block) for subsequent blocks

	// Pad password to multiple of 16 bytes
	padded := make([]byte, ((len(password)+15)/16)*16)
	copy(padded, password)

	encrypted := make([]byte, len(padded))

	// First block: XOR with MD5(secret + authenticator)
	hash1 := md5.Sum(append(secret, authenticator[:]...))
	for i := 0; i < 16; i++ {
		encrypted[i] = padded[i] ^ hash1[i]
	}

	// Subsequent blocks: XOR with MD5(secret + previous encrypted block)
	for block := 1; block < len(padded)/16; block++ {
		offset := block * 16
		prevBlock := encrypted[offset-16 : offset]
		hash := md5.Sum(append(secret, prevBlock...))

		for i := 0; i < 16; i++ {
			encrypted[offset+i] = padded[offset+i] ^ hash[i]
		}
	}

	return encrypted
}

// encryptTunnelPassword implements Tunnel-Password encryption (RFC 2868, Section 3.5)
func encryptTunnelPassword(password []byte, secret []byte, authenticator [16]byte) []byte {
	// Tunnel-Password encryption is similar to User-Password but with a salt
	// 1. Generate 2-byte random salt
	// 2. Prepend salt to password
	// 3. Apply User-Password style encryption

	// Generate random salt
	salt := make([]byte, 2)
	rand.Read(salt)

	// Prepend salt to password
	salt = append(salt, password...)

	// Apply User-Password encryption to the salted password
	encrypted := encryptUserPassword(salt, secret, authenticator)

	return encrypted
}

// encryptAscendSecret implements Ascend-Secret encryption
func encryptAscendSecret(value []byte, secret []byte, authenticator [16]byte) []byte {
	// Ascend-Secret uses a vendor-specific encryption similar to User-Password
	// For simplicity, we'll use the same algorithm as User-Password
	// In a real implementation, this might differ based on Ascend's specification
	return encryptUserPassword(value, secret, authenticator)
}

// addArrayAttribute handles array attributes (multiple values for same attribute)
// If value is a slice, it adds each element as a separate attribute instance
func (p *Packet) addArrayAttribute(attrDef *dictionary.AttributeDefinition, value interface{}, tag uint8, secret []byte, authenticator [16]byte) {
	// Check if value is a slice/array
	values := []interface{}{value}

	// Try to convert to slice for array handling
	switch v := value.(type) {
	case []interface{}:
		values = v
	case []string:
		values = make([]interface{}, len(v))
		for i, s := range v {
			values[i] = s
		}
	case []int:
		values = make([]interface{}, len(v))
		for i, n := range v {
			values[i] = n
		}
	case []uint32:
		values = make([]interface{}, len(v))
		for i, n := range v {
			values[i] = n
		}
	case [][]byte:
		values = make([]interface{}, len(v))
		for i, b := range v {
			values[i] = b
		}
	}

	// Add each value as a separate attribute
	for _, val := range values {
		if attrValue, err := p.encodeAttributeValue(val, attrDef); err == nil {
			if attrDef.Encryption != "" && secret != nil {
				attrValue = EncryptAttributeValue(attrValue, attrDef.Encryption, secret, authenticator)
			}

			if attrDef.HasTag && tag > 0 {
				taggedValue := append([]byte{tag}, attrValue...)
				attr := NewAttribute(uint8(attrDef.ID), taggedValue)
				p.AddAttribute(attr)
			} else {
				attr := NewAttribute(uint8(attrDef.ID), attrValue)
				p.AddAttribute(attr)
			}
		}
	}
}

// addVendorArrayAttribute handles vendor array attributes
// If value is a slice, it adds each element as a separate vendor attribute instance
func (p *Packet) addVendorArrayAttribute(vendor *dictionary.VendorDefinition, attrDef *dictionary.AttributeDefinition, value interface{}, tag uint8, secret []byte, authenticator [16]byte) {
	// Check if value is a slice/array
	values := []interface{}{value}

	// Try to convert to slice for array handling
	switch v := value.(type) {
	case []interface{}:
		values = v
	case []string:
		values = make([]interface{}, len(v))
		for i, s := range v {
			values[i] = s
		}
	case []int:
		values = make([]interface{}, len(v))
		for i, n := range v {
			values[i] = n
		}
	case []uint32:
		values = make([]interface{}, len(v))
		for i, n := range v {
			values[i] = n
		}
	case [][]byte:
		values = make([]interface{}, len(v))
		for i, b := range v {
			values[i] = b
		}
	}

	// Add each value as a separate vendor attribute
	for _, val := range values {
		if attrValue, err := p.encodeAttributeValue(val, attrDef); err == nil {
			if attrDef.Encryption != "" && secret != nil {
				attrValue = EncryptAttributeValue(attrValue, attrDef.Encryption, secret, authenticator)
			}

			var vsa *VendorAttribute
			if attrDef.HasTag && tag > 0 {
				vsa = NewTaggedVendorAttribute(vendor.ID, uint8(attrDef.ID), tag, attrValue)
			} else {
				vsa = NewVendorAttribute(vendor.ID, uint8(attrDef.ID), attrValue)
			}
			p.AddVendorAttribute(vsa)
		}
	}
}

// ListAttributes returns a list of unique attribute names found in the packet.
// Requires a dictionary to be set on the packet. Returns empty slice if dictionary is nil.
// Attributes not found in dictionary are skipped.
// VSA attributes return their attribute name (e.g., "ERX-Dhcp-Mac-Addr").
func (p *Packet) ListAttributes() []string {
	if p.Dict == nil {
		return []string{}
	}

	seen := make(map[string]bool)
	var result []string

	for _, attr := range p.Attributes {
		var name string

		if attr.Type == 26 {
			// VSA - Vendor-Specific Attribute
			va, err := ParseVSA(attr)
			if err != nil {
				continue
			}

			attrDef, found := p.Dict.LookupVendorAttributeByID(va.VendorID, uint32(va.VendorType))
			if !found {
				continue
			}

			name = attrDef.Name
		} else {
			// Standard attribute
			attrDef, exists := p.Dict.LookupStandardByID(uint32(attr.Type))
			if !exists {
				continue
			}

			name = attrDef.Name
		}

		if !seen[name] {
			seen[name] = true
			result = append(result, name)
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
		for _, attr := range p.Attributes {
			if attr.Type == uint8(attrDef.ID) {
				// Only use tag if the attribute definition supports tagging
				tag := uint8(0)
				value := attr.Value
				if attrDef.HasTag && attr.Tag > 0 {
					tag = attr.Tag
					value = attr.GetValue() // Strips tag byte
				}

				result = append(result, AttributeValue{
					Name:     attrDef.Name,
					Type:     attr.Type,
					DataType: attrDef.DataType,
					Value:    value,
					Tag:      tag,
					IsVSA:    false,
				})
			}
		}
		return result
	}

	// Try to find as vendor attribute
	vendors := p.Dict.GetAllVendors()
	for _, vendor := range vendors {
		if attrDef, exists := p.Dict.LookupVendorAttributeByName(vendor.Name, name); exists {
			for _, attr := range p.Attributes {
				if attr.Type == 26 {
					va, err := ParseVSA(attr)
					if err != nil {
						continue
					}

					if va.VendorID == vendor.ID && va.VendorType == uint8(attrDef.ID) {
						// Only use tag if the attribute definition supports tagging
						tag := uint8(0)
						value := va.Value
						if attrDef.HasTag && va.Tag > 0 {
							tag = va.Tag
							value = va.GetValue() // Strips tag byte
						}

						result = append(result, AttributeValue{
							Name:       attrDef.Name,
							Type:       attr.Type,
							DataType:   attrDef.DataType,
							Value:      value,
							Tag:        tag,
							IsVSA:      true,
							VendorID:   va.VendorID,
							VendorType: va.VendorType,
						})
					}
				}
			}
			return result
		}
	}

	return []AttributeValue{}
}

// String returns a string representation of the packet
func (p *Packet) String() string {
	return fmt.Sprintf("Code=%s(%d), ID=%d, Length=%d, Attributes=%d",
		p.Code.String(), p.Code, p.Identifier, p.Length, len(p.Attributes))
}
