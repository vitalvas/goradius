package packet

import (
	"fmt"
	"net"
	"time"

	"github.com/vitalvas/goradius/pkg/dictionary"
)

// EnhancedPacket provides dictionary-aware packet operations
type EnhancedPacket struct {
	*Packet
	parser *DictionaryParser
}

// NewEnhancedPacket creates an enhanced packet with dictionary support
func NewEnhancedPacket(code Code, identifier uint8, dict *dictionary.Dictionary) *EnhancedPacket {
	return &EnhancedPacket{
		Packet: New(code, identifier),
		parser: NewDictionaryParser(dict),
	}
}

// WrapPacket wraps an existing packet with dictionary support
func WrapPacket(pkt *Packet, dict *dictionary.Dictionary) *EnhancedPacket {
	return &EnhancedPacket{
		Packet: pkt,
		parser: NewDictionaryParser(dict),
	}
}

// AddTypedAttribute adds an attribute with automatic type conversion
func (ep *EnhancedPacket) AddTypedAttribute(attrType uint8, value interface{}) error {
	valueBytes, err := ep.parser.BuildAttributeValue(attrType, value)
	if err != nil {
		return fmt.Errorf("failed to build attribute value: %w", err)
	}

	attr := NewAttribute(attrType, valueBytes)

	// Validate the attribute
	if err := ep.parser.ValidateAttribute(attr); err != nil {
		return fmt.Errorf("attribute validation failed: %w", err)
	}

	ep.AddAttribute(attr)
	return nil
}

// AddVSA adds a vendor-specific attribute with automatic type conversion
func (ep *EnhancedPacket) AddVSA(vendorID uint32, vendorType uint8, value interface{}) error {
	vsaBytes, err := ep.parser.BuildVSAValue(vendorID, vendorType, value)
	if err != nil {
		return fmt.Errorf("failed to build VSA value: %w", err)
	}

	attr := NewAttribute(AttrVendorSpecific, vsaBytes)

	// Validate the VSA
	if err := ep.parser.ValidateAttribute(attr); err != nil {
		return fmt.Errorf("VSA validation failed: %w", err)
	}

	ep.AddAttribute(attr)
	return nil
}

// GetTypedAttribute retrieves and parses an attribute value by type
func (ep *EnhancedPacket) GetTypedAttribute(attrType uint8) (interface{}, bool, error) {
	attr, found := ep.GetAttribute(attrType)
	if !found {
		return nil, false, nil
	}

	value, err := ep.parser.ParseAttributeValue(attr)
	if err != nil {
		return nil, true, fmt.Errorf("failed to parse attribute value: %w", err)
	}

	return value, true, nil
}

// GetTypedAttributes retrieves and parses all attributes of a given type (for array attributes)
func (ep *EnhancedPacket) GetTypedAttributes(attrType uint8) ([]interface{}, error) {
	attrs := ep.GetAttributes(attrType)
	if len(attrs) == 0 {
		return nil, nil
	}

	values := make([]interface{}, len(attrs))
	for i, attr := range attrs {
		value, err := ep.parser.ParseAttributeValue(attr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse attribute value at index %d: %w", i, err)
		}
		values[i] = value
	}

	return values, nil
}

// GetVSA retrieves and parses a VSA value
func (ep *EnhancedPacket) GetVSA(vendorID uint32, vendorType uint8) (interface{}, bool, error) {
	// Look through all vendor-specific attributes
	attrs := ep.GetAttributes(AttrVendorSpecific)
	for _, attr := range attrs {
		if len(attr.Value) < 6 {
			continue // Invalid VSA
		}

		// Parse VSA header
		attrVendorID := uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 |
			uint32(attr.Value[2])<<8 | uint32(attr.Value[3])
		attrVendorType := attr.Value[4]

		if attrVendorID == vendorID && attrVendorType == vendorType {
			value, err := ep.parser.ParseAttributeValue(attr)
			if err != nil {
				return nil, true, fmt.Errorf("failed to parse VSA value: %w", err)
			}
			return value, true, nil
		}
	}

	return nil, false, nil
}

// GetVSAs retrieves all VSAs for a given vendor
func (ep *EnhancedPacket) GetVSAs(vendorID uint32) (map[uint8]interface{}, error) {
	result := make(map[uint8]interface{})

	attrs := ep.GetAttributes(AttrVendorSpecific)
	for _, attr := range attrs {
		if len(attr.Value) < 6 {
			continue // Invalid VSA
		}

		// Parse VSA header
		attrVendorID := uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 |
			uint32(attr.Value[2])<<8 | uint32(attr.Value[3])
		attrVendorType := attr.Value[4]

		if attrVendorID == vendorID {
			value, err := ep.parser.ParseAttributeValue(attr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse VSA value for type %d: %w", attrVendorType, err)
			}
			result[attrVendorType] = value
		}
	}

	return result, nil
}

// GetAttributeName returns the human-readable name of an attribute
func (ep *EnhancedPacket) GetAttributeName(attrType uint8) string {
	return ep.parser.GetAttributeName(attrType)
}

// GetVSAName returns the human-readable name of a VSA
func (ep *EnhancedPacket) GetVSAName(vendorID uint32, vendorType uint8) string {
	return ep.parser.GetVSAName(vendorID, vendorType)
}

// ValidatePacket validates all attributes in the packet against the dictionary
func (ep *EnhancedPacket) ValidatePacket() error {
	// First validate the base packet structure
	if err := ep.Validate(); err != nil {
		return fmt.Errorf("basic packet validation failed: %w", err)
	}

	// Then validate each attribute against the dictionary
	for i, attr := range ep.Attributes {
		if err := ep.parser.ValidateAttribute(attr); err != nil {
			return fmt.Errorf("attribute %d validation failed: %w", i, err)
		}
	}

	return nil
}

// String returns a human-readable representation of the packet
func (ep *EnhancedPacket) String() string {
	result := fmt.Sprintf("RADIUS %s (ID: %d, Length: %d)\n", ep.Code, ep.Identifier, ep.Length)

	for i, attr := range ep.Attributes {
		attrName := ep.GetAttributeName(attr.Type)
		value, err := ep.parser.ParseAttributeValue(attr)
		if err != nil {
			result += fmt.Sprintf("  [%d] %s = <parse error: %v>\n", i, attrName, err)
		} else {
			result += fmt.Sprintf("  [%d] %s = %v\n", i, attrName, formatValue(value))
		}
	}

	return result
}

// Helper function to format values for display
func formatValue(value interface{}) string {
	switch v := value.(type) {
	case []byte:
		return fmt.Sprintf("0x%x", v)
	case net.IP:
		return v.String()
	case time.Time:
		return v.Format(time.RFC3339)
	case string:
		return fmt.Sprintf("%q", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ArrayAttribute represents support for array attributes (RFC 7542)
type ArrayAttribute struct {
	Type   uint8
	Values []interface{}
}

// AddArrayAttribute adds multiple values for an array attribute
func (ep *EnhancedPacket) AddArrayAttribute(attrType uint8, values []interface{}) error {
	for i, value := range values {
		if err := ep.AddTypedAttribute(attrType, value); err != nil {
			return fmt.Errorf("failed to add array attribute value at index %d: %w", i, err)
		}
	}
	return nil
}

// GetArrayAttribute retrieves all values for an array attribute
func (ep *EnhancedPacket) GetArrayAttribute(attrType uint8) (*ArrayAttribute, error) {
	values, err := ep.GetTypedAttributes(attrType)
	if err != nil {
		return nil, err
	}

	if len(values) == 0 {
		return nil, nil
	}

	return &ArrayAttribute{
		Type:   attrType,
		Values: values,
	}, nil
}

// IsArrayAttribute checks if an attribute type is defined as an array in the dictionary
func (ep *EnhancedPacket) IsArrayAttribute(attrType uint8) bool {
	if ep.parser.dict == nil {
		return false
	}

	if def, exists := ep.parser.dict.Attributes[attrType]; exists {
		return def.Array
	}

	return false
}

// Convenience methods for common attribute types

// SetUserName sets the User-Name attribute
func (ep *EnhancedPacket) SetUserName(username string) error {
	return ep.AddTypedAttribute(AttrUserName, username)
}

// GetUserName gets the User-Name attribute
func (ep *EnhancedPacket) GetUserName() (string, bool) {
	value, found, err := ep.GetTypedAttribute(AttrUserName)
	if !found || err != nil {
		return "", false
	}
	if str, ok := value.(string); ok {
		return str, true
	}
	return "", false
}

// SetNASIPAddress sets the NAS-IP-Address attribute
func (ep *EnhancedPacket) SetNASIPAddress(ip net.IP) error {
	return ep.AddTypedAttribute(AttrNASIPAddress, ip)
}

// GetNASIPAddress gets the NAS-IP-Address attribute
func (ep *EnhancedPacket) GetNASIPAddress() (net.IP, bool) {
	value, found, err := ep.GetTypedAttribute(AttrNASIPAddress)
	if !found || err != nil {
		return nil, false
	}
	if ip, ok := value.(net.IP); ok {
		return ip, true
	}
	return nil, false
}

// SetServiceType sets the Service-Type attribute with named value support
func (ep *EnhancedPacket) SetServiceType(serviceType interface{}) error {
	return ep.AddTypedAttribute(AttrServiceType, serviceType)
}

// GetServiceType gets the Service-Type attribute
func (ep *EnhancedPacket) GetServiceType() (interface{}, bool) {
	value, found, err := ep.GetTypedAttribute(AttrServiceType)
	if !found || err != nil {
		return nil, false
	}
	return value, true
}

// Tagged attribute methods

// AddTaggedAttribute adds a tagged attribute with automatic type conversion
func (ep *EnhancedPacket) AddTaggedAttribute(attrType uint8, tag uint8, value interface{}) error {
	valueBytes, err := ep.parser.BuildTaggedAttributeValue(attrType, tag, value)
	if err != nil {
		return fmt.Errorf("failed to build tagged attribute value: %w", err)
	}

	attr := NewAttribute(attrType, valueBytes)

	// Validate the attribute
	if err := ep.parser.ValidateAttribute(attr); err != nil {
		return fmt.Errorf("tagged attribute validation failed: %w", err)
	}

	ep.AddAttribute(attr)
	return nil
}

// GetTaggedAttribute retrieves and parses a tagged attribute value by type and tag
func (ep *EnhancedPacket) GetTaggedAttribute(attrType uint8, tag uint8) (interface{}, bool, error) {
	attr, found := ep.Packet.GetTaggedAttribute(attrType, tag)
	if !found {
		return nil, false, nil
	}

	value, err := ep.parser.ParseAttributeValue(attr)
	if err != nil {
		return nil, true, fmt.Errorf("failed to parse tagged attribute value: %w", err)
	}

	// If it's a TaggedValue, return the parsed content
	if taggedValue, ok := value.(*TaggedValue); ok {
		parsedValue, err := ep.parser.parseValueByType(taggedValue.Value, ep.getAttributeDefinition(attrType))
		if err != nil {
			return nil, true, err
		}
		return parsedValue, true, nil
	}

	return value, true, nil
}

// GetAllTaggedAttributesByType returns all tagged attributes of a given type, grouped by tag
func (ep *EnhancedPacket) GetAllTaggedAttributesByType(attrType uint8) (map[uint8]interface{}, error) {
	result := make(map[uint8]interface{})

	attrs := ep.GetAttributes(attrType)
	for _, attr := range attrs {
		value, err := ep.parser.ParseAttributeValue(attr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tagged attribute: %w", err)
		}

		if taggedValue, ok := value.(*TaggedValue); ok {
			parsedValue, err := ep.parser.parseValueByType(taggedValue.Value, ep.getAttributeDefinition(attrType))
			if err != nil {
				return nil, err
			}
			result[taggedValue.Tag] = parsedValue
		}
	}

	return result, nil
}

// IsTaggedAttribute checks if an attribute type is defined as tagged in the dictionary
func (ep *EnhancedPacket) IsTaggedAttribute(attrType uint8) bool {
	if ep.parser.dict == nil {
		return false
	}

	if def, exists := ep.parser.dict.Attributes[attrType]; exists {
		return def.IsTagged()
	}

	return false
}

// Helper method to get attribute definition
func (ep *EnhancedPacket) getAttributeDefinition(attrType uint8) *dictionary.AttributeDefinition {
	if ep.parser.dict == nil {
		return nil
	}

	if def, exists := ep.parser.dict.Attributes[attrType]; exists {
		return def
	}

	return nil
}
