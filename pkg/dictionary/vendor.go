package dictionary

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// VendorSpecificAttribute represents a vendor-specific attribute
type VendorSpecificAttribute struct {
	VendorID     uint32
	VendorType   uint8
	VendorLength uint8
	VendorData   []byte
	Definition   *AttributeDefinition
	ParsedValue  interface{}
}

// VendorAttributeFormat defines the format for vendor-specific attributes
type VendorAttributeFormat struct {
	// TypeOctets specifies the number of octets for the type field (usually 1)
	TypeOctets uint8

	// LengthOctets specifies the number of octets for the length field (usually 1)
	LengthOctets uint8

	// HasContinuation indicates if the vendor supports continuation
	HasContinuation bool

	// WiMAXFormat indicates if this uses WiMAX format (continuation bit in type field)
	WiMAXFormat bool
}

// VendorRegistry manages vendor-specific attributes
type VendorRegistry struct {
	vendors map[uint32]*VendorDefinition
	formats map[uint32]*VendorAttributeFormat
}

// NewVendorRegistry creates a new vendor registry
func NewVendorRegistry() *VendorRegistry {
	return &VendorRegistry{
		vendors: make(map[uint32]*VendorDefinition),
		formats: make(map[uint32]*VendorAttributeFormat),
	}
}

// RegisterVendor registers a vendor with its format
func (vr *VendorRegistry) RegisterVendor(vendor *VendorDefinition, format *VendorAttributeFormat) error {
	if vendor == nil {
		return fmt.Errorf("vendor definition cannot be nil")
	}

	if vendor.ID == 0 {
		return fmt.Errorf("vendor ID cannot be zero")
	}

	if format == nil {
		// Use default format
		format = &VendorAttributeFormat{
			TypeOctets:   1,
			LengthOctets: 1,
		}
	}

	vr.vendors[vendor.ID] = vendor
	vr.formats[vendor.ID] = format

	return nil
}

// GetVendor returns a vendor definition by ID
func (vr *VendorRegistry) GetVendor(vendorID uint32) (*VendorDefinition, bool) {
	vendor, exists := vr.vendors[vendorID]
	return vendor, exists
}

// GetVendorFormat returns a vendor format by ID
func (vr *VendorRegistry) GetVendorFormat(vendorID uint32) (*VendorAttributeFormat, bool) {
	format, exists := vr.formats[vendorID]
	return format, exists
}

// GetAllVendors returns all registered vendors
func (vr *VendorRegistry) GetAllVendors() map[uint32]*VendorDefinition {
	result := make(map[uint32]*VendorDefinition)
	for id, vendor := range vr.vendors {
		result[id] = vendor
	}
	return result
}

// GetVendorIDs returns all vendor IDs
func (vr *VendorRegistry) GetVendorIDs() []uint32 {
	ids := make([]uint32, 0, len(vr.vendors))
	for id := range vr.vendors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	return ids
}

// ParseVendorSpecificAttribute parses a vendor-specific attribute
func (vr *VendorRegistry) ParseVendorSpecificAttribute(vendorID uint32, data []byte) (*VendorSpecificAttribute, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("vendor-specific attribute data too short: %d bytes", len(data))
	}

	format, exists := vr.formats[vendorID]
	if !exists {
		// Use default format for unknown vendors
		format = &VendorAttributeFormat{
			TypeOctets:   1,
			LengthOctets: 1,
		}
	}

	if len(data) < int(format.TypeOctets+format.LengthOctets) {
		return nil, fmt.Errorf("vendor-specific attribute data too short for format: %d bytes", len(data))
	}

	var vendorType uint8
	var vendorLength uint8
	var vendorData []byte

	// Parse type field
	if format.TypeOctets == 1 {
		vendorType = data[0]

		// Handle WiMAX format (continuation bit in type field)
		if format.WiMAXFormat {
			vendorType &= 0x7F // Clear continuation bit
		}
	} else {
		return nil, fmt.Errorf("unsupported type octets: %d", format.TypeOctets)
	}

	// Parse length field
	if format.LengthOctets == 1 {
		vendorLength = data[format.TypeOctets]
	} else {
		return nil, fmt.Errorf("unsupported length octets: %d", format.LengthOctets)
	}

	// Validate length
	headerLength := int(format.TypeOctets + format.LengthOctets)
	if int(vendorLength) < headerLength {
		return nil, fmt.Errorf("invalid vendor length: %d (must be at least %d)", vendorLength, headerLength)
	}

	if int(vendorLength) > len(data) {
		return nil, fmt.Errorf("vendor length %d exceeds data length %d", vendorLength, len(data))
	}

	// Extract vendor data
	dataLength := int(vendorLength) - headerLength
	if dataLength > 0 {
		vendorData = data[headerLength : headerLength+dataLength]
	}

	vsa := &VendorSpecificAttribute{
		VendorID:     vendorID,
		VendorType:   vendorType,
		VendorLength: vendorLength,
		VendorData:   vendorData,
	}

	return vsa, nil
}

// EncodeVendorSpecificAttribute encodes a vendor-specific attribute
func (vr *VendorRegistry) EncodeVendorSpecificAttribute(vsa *VendorSpecificAttribute) ([]byte, error) {
	format, exists := vr.formats[vsa.VendorID]
	if !exists {
		// Use default format for unknown vendors
		format = &VendorAttributeFormat{
			TypeOctets:   1,
			LengthOctets: 1,
		}
	}

	headerLength := int(format.TypeOctets + format.LengthOctets)
	totalLength := headerLength + len(vsa.VendorData)

	if totalLength > 255 {
		return nil, fmt.Errorf("vendor-specific attribute too long: %d bytes", totalLength)
	}

	result := make([]byte, totalLength)

	// Encode type field
	if format.TypeOctets == 1 {
		result[0] = vsa.VendorType
	} else {
		return nil, fmt.Errorf("unsupported type octets: %d", format.TypeOctets)
	}

	// Encode length field
	if format.LengthOctets == 1 {
		result[format.TypeOctets] = uint8(totalLength)
	} else {
		return nil, fmt.Errorf("unsupported length octets: %d", format.LengthOctets)
	}

	// Copy vendor data
	copy(result[headerLength:], vsa.VendorData)

	return result, nil
}

// VendorAttributeCollection manages multiple vendor-specific attributes
type VendorAttributeCollection struct {
	attributes map[uint32]map[uint8]*VendorSpecificAttribute
	registry   *VendorRegistry
}

// NewVendorAttributeCollection creates a new vendor attribute collection
func NewVendorAttributeCollection(registry *VendorRegistry) *VendorAttributeCollection {
	return &VendorAttributeCollection{
		attributes: make(map[uint32]map[uint8]*VendorSpecificAttribute),
		registry:   registry,
	}
}

// AddAttribute adds a vendor-specific attribute
func (vac *VendorAttributeCollection) AddAttribute(vsa *VendorSpecificAttribute) error {
	if vac.attributes[vsa.VendorID] == nil {
		vac.attributes[vsa.VendorID] = make(map[uint8]*VendorSpecificAttribute)
	}

	vac.attributes[vsa.VendorID][vsa.VendorType] = vsa
	return nil
}

// GetAttribute retrieves a vendor-specific attribute
func (vac *VendorAttributeCollection) GetAttribute(vendorID uint32, vendorType uint8) (*VendorSpecificAttribute, bool) {
	if vendorAttrs, exists := vac.attributes[vendorID]; exists {
		if vsa, exists := vendorAttrs[vendorType]; exists {
			return vsa, true
		}
	}
	return nil, false
}

// GetAttributesByVendor retrieves all attributes for a vendor
func (vac *VendorAttributeCollection) GetAttributesByVendor(vendorID uint32) map[uint8]*VendorSpecificAttribute {
	if vendorAttrs, exists := vac.attributes[vendorID]; exists {
		result := make(map[uint8]*VendorSpecificAttribute)
		for vendorType, vsa := range vendorAttrs {
			result[vendorType] = vsa
		}
		return result
	}
	return make(map[uint8]*VendorSpecificAttribute)
}

// GetAllVendorIDs returns all vendor IDs with attributes
func (vac *VendorAttributeCollection) GetAllVendorIDs() []uint32 {
	ids := make([]uint32, 0, len(vac.attributes))
	for id := range vac.attributes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	return ids
}

// RemoveAttribute removes a vendor-specific attribute
func (vac *VendorAttributeCollection) RemoveAttribute(vendorID uint32, vendorType uint8) bool {
	if vendorAttrs, exists := vac.attributes[vendorID]; exists {
		if _, exists := vendorAttrs[vendorType]; exists {
			delete(vendorAttrs, vendorType)

			// Clean up empty vendor map
			if len(vendorAttrs) == 0 {
				delete(vac.attributes, vendorID)
			}

			return true
		}
	}
	return false
}

// Clear removes all attributes
func (vac *VendorAttributeCollection) Clear() {
	vac.attributes = make(map[uint32]map[uint8]*VendorSpecificAttribute)
}

// GetAttributeCount returns the total number of attributes
func (vac *VendorAttributeCollection) GetAttributeCount() int {
	count := 0
	for _, vendorAttrs := range vac.attributes {
		count += len(vendorAttrs)
	}
	return count
}

// Enhanced methods for vendor-specific attribute handling

// ParseVendorSpecificAttributeData parses vendor-specific attribute data with dictionary lookup
func (d *Dictionary) ParseVendorSpecificAttributeData(vendorID uint32, data []byte) (*VendorSpecificAttribute, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("vendor-specific attribute data too short: %d bytes", len(data))
	}

	vendorType := data[0]
	vendorLength := data[1]

	// Validate length
	if int(vendorLength) < 2 {
		return nil, fmt.Errorf("invalid vendor length: %d (must be at least 2)", vendorLength)
	}

	if int(vendorLength) > len(data) {
		return nil, fmt.Errorf("vendor length %d exceeds data length %d", vendorLength, len(data))
	}

	// Extract vendor data
	vendorData := data[2:vendorLength]

	vsa := &VendorSpecificAttribute{
		VendorID:     vendorID,
		VendorType:   vendorType,
		VendorLength: vendorLength,
		VendorData:   vendorData,
	}

	// Look up attribute definition
	if definition, exists := d.GetVSA(vendorID, vendorType); exists {
		vsa.Definition = definition

		// Parse value according to definition
		if err := definition.ValidateValue(vendorData); err == nil {
			vsa.ParsedValue = d.parseValueForType(definition, vendorData)
		}
	}

	return vsa, nil
}

// parseValueForType parses value according to attribute type
func (d *Dictionary) parseValueForType(definition *AttributeDefinition, data []byte) interface{} {
	switch definition.DataType {
	case DataTypeString:
		return string(data)
	case DataTypeInteger, DataTypeUint32:
		if len(data) == 4 {
			return binary.BigEndian.Uint32(data)
		}
		return data
	case DataTypeUint64:
		if len(data) == 8 {
			return binary.BigEndian.Uint64(data)
		}
		return data
	case DataTypeIPAddr:
		if len(data) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
		}
		return data
	case DataTypeIPv6Addr:
		if len(data) == 16 {
			return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				binary.BigEndian.Uint16(data[0:2]),
				binary.BigEndian.Uint16(data[2:4]),
				binary.BigEndian.Uint16(data[4:6]),
				binary.BigEndian.Uint16(data[6:8]),
				binary.BigEndian.Uint16(data[8:10]),
				binary.BigEndian.Uint16(data[10:12]),
				binary.BigEndian.Uint16(data[12:14]),
				binary.BigEndian.Uint16(data[14:16]))
		}
		return data
	default:
		return data
	}
}

// GetVendorName returns the name of a vendor by ID
func (d *Dictionary) GetVendorName(vendorID uint32) string {
	if vendor, exists := d.GetVendor(vendorID); exists {
		return vendor.Name
	}
	return fmt.Sprintf("Unknown-Vendor-%d", vendorID)
}

// GetVSAName returns the name of a vendor-specific attribute
func (d *Dictionary) GetVSAName(vendorID uint32, vendorType uint8) string {
	if attr, exists := d.GetVSA(vendorID, vendorType); exists {
		return attr.Name
	}

	vendorName := d.GetVendorName(vendorID)
	return fmt.Sprintf("%s-Unknown-Attr-%d", vendorName, vendorType)
}

// FormatVSAValue formats a vendor-specific attribute value for display
func (d *Dictionary) FormatVSAValue(vendorID uint32, vendorType uint8, data []byte) string {
	if attr, exists := d.GetVSA(vendorID, vendorType); exists {
		return attr.FormatValue(data)
	}

	// Default formatting for unknown VSAs
	return fmt.Sprintf("0x%x", data)
}

// GetVSAsByVendor returns all VSAs for a specific vendor
func (d *Dictionary) GetVSAsByVendor(vendorID uint32) map[uint8]*AttributeDefinition {
	if vendorAttrs, exists := d.VSAs[vendorID]; exists {
		result := make(map[uint8]*AttributeDefinition)
		for vendorType, attr := range vendorAttrs {
			result[vendorType] = attr
		}
		return result
	}
	return make(map[uint8]*AttributeDefinition)
}

// GetVendorsByName returns vendors matching a name pattern
func (d *Dictionary) GetVendorsByName(pattern string) map[uint32]*VendorDefinition {
	result := make(map[uint32]*VendorDefinition)
	pattern = strings.ToLower(pattern)

	for id, vendor := range d.Vendors {
		if strings.Contains(strings.ToLower(vendor.Name), pattern) {
			result[id] = vendor
		}
	}

	return result
}

// GetVSAsByName returns VSAs matching a name pattern
func (d *Dictionary) GetVSAsByName(pattern string) map[string]*AttributeDefinition {
	result := make(map[string]*AttributeDefinition)
	pattern = strings.ToLower(pattern)

	for _, vendorAttrs := range d.VSAs {
		for _, attr := range vendorAttrs {
			if strings.Contains(strings.ToLower(attr.Name), pattern) {
				key := fmt.Sprintf("%d:%d", attr.VendorID, attr.ID)
				result[key] = attr
			}
		}
	}

	return result
}

// ValidateVSAConstraints validates vendor-specific attribute constraints
func (d *Dictionary) ValidateVSAConstraints(vendorID uint32, vendorType uint8, data []byte) error {
	// Check if vendor exists
	if _, exists := d.GetVendor(vendorID); !exists {
		return fmt.Errorf("unknown vendor ID: %d", vendorID)
	}

	// Check if VSA exists
	if attr, exists := d.GetVSA(vendorID, vendorType); exists {
		return attr.ValidateValue(data)
	}

	// For unknown VSAs, perform basic validation
	if len(data) > 253 {
		return fmt.Errorf("VSA data too long: %d bytes", len(data))
	}

	return nil
}

// GetVSAStatistics returns statistics about VSAs in the dictionary
func (d *Dictionary) GetVSAStatistics() map[string]interface{} {
	totalVSAs := 0
	vendorCounts := make(map[uint32]int)

	for vendorID, vendorAttrs := range d.VSAs {
		count := len(vendorAttrs)
		totalVSAs += count
		vendorCounts[vendorID] = count
	}

	return map[string]interface{}{
		"total_vsas":    totalVSAs,
		"vendor_count":  len(d.Vendors),
		"vendor_counts": vendorCounts,
	}
}

// CloneVSA creates a deep copy of a vendor-specific attribute
func (vsa *VendorSpecificAttribute) Clone() *VendorSpecificAttribute {
	clone := &VendorSpecificAttribute{
		VendorID:     vsa.VendorID,
		VendorType:   vsa.VendorType,
		VendorLength: vsa.VendorLength,
		Definition:   vsa.Definition,
		ParsedValue:  vsa.ParsedValue,
	}

	// Deep copy vendor data
	if vsa.VendorData != nil {
		clone.VendorData = make([]byte, len(vsa.VendorData))
		copy(clone.VendorData, vsa.VendorData)
	}

	return clone
}

// String returns a string representation of the vendor-specific attribute
func (vsa *VendorSpecificAttribute) String() string {
	if vsa.Definition != nil {
		return fmt.Sprintf("%s = %s", vsa.Definition.Name, vsa.Definition.FormatValue(vsa.VendorData))
	}

	return fmt.Sprintf("Vendor-%d-Type-%d = 0x%x", vsa.VendorID, vsa.VendorType, vsa.VendorData)
}

// GetDataAsString returns the vendor data as a string
func (vsa *VendorSpecificAttribute) GetDataAsString() string {
	if vsa.Definition != nil && vsa.Definition.DataType == DataTypeString {
		return string(vsa.VendorData)
	}
	return fmt.Sprintf("0x%x", vsa.VendorData)
}

// GetDataAsUint32 returns the vendor data as a uint32
func (vsa *VendorSpecificAttribute) GetDataAsUint32() (uint32, error) {
	if len(vsa.VendorData) != 4 {
		return 0, fmt.Errorf("data length is not 4 bytes: %d", len(vsa.VendorData))
	}
	return binary.BigEndian.Uint32(vsa.VendorData), nil
}

// GetDataAsUint64 returns the vendor data as a uint64
func (vsa *VendorSpecificAttribute) GetDataAsUint64() (uint64, error) {
	if len(vsa.VendorData) != 8 {
		return 0, fmt.Errorf("data length is not 8 bytes: %d", len(vsa.VendorData))
	}
	return binary.BigEndian.Uint64(vsa.VendorData), nil
}
