package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLVDataType(t *testing.T) {
	// Test TLV data type constant
	assert.Equal(t, DataType("tlv"), DataTypeTLV)
}

func TestTLVSubAttribute(t *testing.T) {
	subAttr := &TLVSubAttribute{
		Name:     "Test-Sub-Attr",
		Type:     1,
		DataType: DataTypeString,
		Length:   0,
		Optional: false,
	}

	assert.Equal(t, "Test-Sub-Attr", subAttr.Name)
	assert.Equal(t, uint8(1), subAttr.Type)
	assert.Equal(t, DataTypeString, subAttr.DataType)
	assert.Equal(t, 0, subAttr.Length)
	assert.False(t, subAttr.Optional)
}

func TestAttributeDefinitionTLV(t *testing.T) {
	dict := NewDictionary()

	// Create a TLV attribute
	tlvAttr := &AttributeDefinition{
		Name:     "Test-TLV",
		ID:       100,
		DataType: DataTypeTLV,
	}

	// Test TLV methods
	assert.True(t, tlvAttr.IsTLV())
	assert.False(t, tlvAttr.HasSubAttributes())

	// Add sub-attribute
	subAttr := &TLVSubAttribute{
		Name:     "Sub-String",
		Type:     1,
		DataType: DataTypeString,
	}

	err := tlvAttr.AddSubAttribute(subAttr)
	assert.NoError(t, err)
	assert.True(t, tlvAttr.HasSubAttributes())

	// Test retrieval by type
	retrieved, exists := tlvAttr.GetSubAttribute(1)
	assert.True(t, exists)
	assert.Equal(t, "Sub-String", retrieved.Name)
	assert.Equal(t, DataTypeString, retrieved.DataType)

	// Test retrieval by name
	retrieved, exists = tlvAttr.GetSubAttributeByName("Sub-String")
	assert.True(t, exists)
	assert.Equal(t, uint8(1), retrieved.Type)

	// Test non-existent sub-attribute
	_, exists = tlvAttr.GetSubAttribute(99)
	assert.False(t, exists)

	_, exists = tlvAttr.GetSubAttributeByName("NonExistent")
	assert.False(t, exists)

	// Add to dictionary
	err = dict.AddAttribute(tlvAttr)
	assert.NoError(t, err)
}

func TestTLVValidation(t *testing.T) {
	dict := NewDictionary()

	// Test valid TLV attribute
	tlvAttr := &AttributeDefinition{
		Name:     "Valid-TLV",
		ID:       101,
		DataType: DataTypeTLV,
		SubAttributes: map[uint8]*TLVSubAttribute{
			1: {
				Name:     "Sub-Integer",
				Type:     1,
				DataType: DataTypeInteger,
				Length:   4,
			},
			2: {
				Name:     "Sub-String",
				Type:     2,
				DataType: DataTypeString,
			},
		},
	}

	err := dict.AddAttribute(tlvAttr)
	assert.NoError(t, err)

	// Test invalid sub-attribute type mismatch
	invalidTLV := &AttributeDefinition{
		Name:     "Invalid-TLV",
		ID:       102,
		DataType: DataTypeTLV,
		SubAttributes: map[uint8]*TLVSubAttribute{
			1: {
				Name:     "Wrong-Type",
				Type:     2, // Mismatch: key is 1, but Type is 2
				DataType: DataTypeString,
			},
		},
	}

	err = dict.AddAttribute(invalidTLV)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sub-attribute type mismatch")

	// Test nil sub-attribute
	invalidTLV2 := &AttributeDefinition{
		Name:     "Invalid-TLV2",
		ID:       103,
		DataType: DataTypeTLV,
		SubAttributes: map[uint8]*TLVSubAttribute{
			1: nil,
		},
	}

	err = dict.AddAttribute(invalidTLV2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sub-attribute type 1 is nil")
}

func TestTLVSubAttributeValidation(t *testing.T) {
	dict := NewDictionary()

	// Test valid sub-attribute data types
	validSubAttrs := []*TLVSubAttribute{
		{Name: "String", Type: 1, DataType: DataTypeString},
		{Name: "Integer", Type: 2, DataType: DataTypeInteger, Length: 4},
		{Name: "IPv4", Type: 3, DataType: DataTypeIPAddr, Length: 4},
		{Name: "IPv6", Type: 4, DataType: DataTypeIPv6Addr, Length: 16},
		{Name: "Octets", Type: 5, DataType: DataTypeOctets},
	}

	tlvAttr := &AttributeDefinition{
		Name:          "Valid-Sub-Attrs",
		ID:            104,
		DataType:      DataTypeTLV,
		SubAttributes: make(map[uint8]*TLVSubAttribute),
	}

	for _, subAttr := range validSubAttrs {
		tlvAttr.SubAttributes[subAttr.Type] = subAttr
	}

	err := dict.AddAttribute(tlvAttr)
	assert.NoError(t, err)

	// Test nested TLV (should fail)
	nestedTLV := &AttributeDefinition{
		Name:     "Nested-TLV",
		ID:       105,
		DataType: DataTypeTLV,
		SubAttributes: map[uint8]*TLVSubAttribute{
			1: {
				Name:     "Nested",
				Type:     1,
				DataType: DataTypeTLV, // Nested TLV not allowed
			},
		},
	}

	err = dict.AddAttribute(nestedTLV)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nested TLV sub-attributes are not supported")
}

func TestAddSubAttributeErrors(t *testing.T) {
	// Test adding sub-attribute to non-TLV attribute
	regularAttr := &AttributeDefinition{
		Name:     "Regular-Attr",
		ID:       106,
		DataType: DataTypeString,
	}

	subAttr := &TLVSubAttribute{
		Name:     "Sub",
		Type:     1,
		DataType: DataTypeString,
	}

	err := regularAttr.AddSubAttribute(subAttr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "can only add sub-attributes to TLV attributes")

	// Test adding nil sub-attribute
	tlvAttr := &AttributeDefinition{
		Name:     "TLV-Attr",
		ID:       107,
		DataType: DataTypeTLV,
	}

	err = tlvAttr.AddSubAttribute(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sub-attribute cannot be nil")

	// Test adding duplicate sub-attribute
	err = tlvAttr.AddSubAttribute(subAttr)
	assert.NoError(t, err)

	duplicateSubAttr := &TLVSubAttribute{
		Name:     "Duplicate",
		Type:     1, // Same type as existing
		DataType: DataTypeInteger,
	}

	err = tlvAttr.AddSubAttribute(duplicateSubAttr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sub-attribute type 1 already exists")
}

func TestTLVLengthValidation(t *testing.T) {
	dict := NewDictionary()

	// Test TLV with valid length
	validTLV := &AttributeDefinition{
		Name:     "Valid-Length-TLV",
		ID:       108,
		DataType: DataTypeTLV,
		Length:   100, // Valid length
	}

	err := dict.AddAttribute(validTLV)
	assert.NoError(t, err)

	// Test TLV with invalid length (too long)
	invalidTLV := &AttributeDefinition{
		Name:     "Invalid-Length-TLV",
		ID:       109,
		DataType: DataTypeTLV,
		Length:   300, // Too long
	}

	err = dict.AddAttribute(invalidTLV)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLV attribute length cannot exceed 253 bytes")
}

func TestSubAttributeLengthValidation(t *testing.T) {
	dict := NewDictionary()

	// Test sub-attribute with invalid string length
	invalidStringSubAttr := &TLVSubAttribute{
		Name:     "Invalid-String",
		Type:     1,
		DataType: DataTypeString,
		Length:   300, // Too long
	}

	tlvAttr := &AttributeDefinition{
		Name:          "TLV-With-Invalid-Sub",
		ID:            110,
		DataType:      DataTypeTLV,
		SubAttributes: map[uint8]*TLVSubAttribute{1: invalidStringSubAttr},
	}

	err := dict.AddAttribute(tlvAttr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "string sub-attribute length cannot exceed 253 bytes")

	// Test sub-attribute with invalid integer length
	invalidIntSubAttr := &TLVSubAttribute{
		Name:     "Invalid-Integer",
		Type:     1,
		DataType: DataTypeInteger,
		Length:   6, // Should be 4
	}

	tlvAttr2 := &AttributeDefinition{
		Name:          "TLV-With-Invalid-Int",
		ID:            111,
		DataType:      DataTypeTLV,
		SubAttributes: map[uint8]*TLVSubAttribute{1: invalidIntSubAttr},
	}

	err = dict.AddAttribute(tlvAttr2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "integer sub-attributes must be exactly 4 bytes")
}
