package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLVFormat_Constants(t *testing.T) {
	// Test TLV format constants
	assert.Equal(t, TLVFormat("standard"), TLVFormatStandard)
	assert.Equal(t, TLVFormat("ieee-802.1x"), TLVFormatIEEE8021X)
}

func TestTLVFormat_IsValid(t *testing.T) {
	testCases := []struct {
		format TLVFormat
		valid  bool
	}{
		{TLVFormatStandard, true},
		{TLVFormatIEEE8021X, true},
		{"invalid", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.format), func(t *testing.T) {
			assert.Equal(t, tc.valid, tc.format.IsValid())
		})
	}
}

func TestTLVFormat_String(t *testing.T) {
	assert.Equal(t, "standard", TLVFormatStandard.String())
	assert.Equal(t, "ieee-802.1x", TLVFormatIEEE8021X.String())
}

func TestTLVFormat_GetTypeBits(t *testing.T) {
	assert.Equal(t, 8, TLVFormatStandard.GetTypeBits())
	assert.Equal(t, 7, TLVFormatIEEE8021X.GetTypeBits())
	assert.Equal(t, 8, TLVFormat("invalid").GetTypeBits()) // Default
}

func TestTLVFormat_GetLengthBits(t *testing.T) {
	assert.Equal(t, 8, TLVFormatStandard.GetLengthBits())
	assert.Equal(t, 9, TLVFormatIEEE8021X.GetLengthBits())
	assert.Equal(t, 8, TLVFormat("invalid").GetLengthBits()) // Default
}

func TestTLVFormat_GetMaxTypeValue(t *testing.T) {
	assert.Equal(t, uint16(255), TLVFormatStandard.GetMaxTypeValue())    // 2^8 - 1
	assert.Equal(t, uint16(127), TLVFormatIEEE8021X.GetMaxTypeValue())   // 2^7 - 1
	assert.Equal(t, uint16(255), TLVFormat("invalid").GetMaxTypeValue()) // Default
}

func TestTLVFormat_GetMaxLengthValue(t *testing.T) {
	assert.Equal(t, uint16(255), TLVFormatStandard.GetMaxLengthValue())    // 2^8 - 1
	assert.Equal(t, uint16(511), TLVFormatIEEE8021X.GetMaxLengthValue())   // 2^9 - 1
	assert.Equal(t, uint16(255), TLVFormat("invalid").GetMaxLengthValue()) // Default
}

func TestAttributeDefinition_TLVFormatMethods(t *testing.T) {
	// Test standard TLV attribute
	standardTLV := &AttributeDefinition{
		Name:      "Standard-TLV",
		ID:        100,
		DataType:  DataTypeTLV,
		TLVFormat: TLVFormatStandard,
	}

	assert.True(t, standardTLV.IsTLV())
	assert.True(t, standardTLV.IsStandardTLV())
	assert.False(t, standardTLV.IsIEEE8021XTLV())
	assert.Equal(t, TLVFormatStandard, standardTLV.GetTLVFormat())

	// Test IEEE 802.1X TLV attribute
	ieee8021xTLV := &AttributeDefinition{
		Name:      "IEEE-TLV",
		ID:        101,
		DataType:  DataTypeTLV,
		TLVFormat: TLVFormatIEEE8021X,
	}

	assert.True(t, ieee8021xTLV.IsTLV())
	assert.False(t, ieee8021xTLV.IsStandardTLV())
	assert.True(t, ieee8021xTLV.IsIEEE8021XTLV())
	assert.Equal(t, TLVFormatIEEE8021X, ieee8021xTLV.GetTLVFormat())

	// Test TLV with no format specified (should default to standard)
	defaultTLV := &AttributeDefinition{
		Name:     "Default-TLV",
		ID:       102,
		DataType: DataTypeTLV,
		// TLVFormat not specified
	}

	assert.True(t, defaultTLV.IsTLV())
	assert.Equal(t, TLVFormatStandard, defaultTLV.GetTLVFormat())
	assert.True(t, defaultTLV.IsStandardTLV())
	assert.False(t, defaultTLV.IsIEEE8021XTLV())

	// Test non-TLV attribute
	nonTLV := &AttributeDefinition{
		Name:     "Non-TLV",
		ID:       103,
		DataType: DataTypeString,
	}

	assert.False(t, nonTLV.IsTLV())
	assert.False(t, nonTLV.IsStandardTLV())
	assert.False(t, nonTLV.IsIEEE8021XTLV())
	assert.Equal(t, TLVFormat(""), nonTLV.GetTLVFormat())
}

func TestTLVFormatValidation(t *testing.T) {
	dict := NewDictionary()

	// Test valid standard TLV
	standardTLV := &AttributeDefinition{
		Name:      "Standard-TLV",
		ID:        100,
		DataType:  DataTypeTLV,
		TLVFormat: TLVFormatStandard,
	}

	err := dict.AddAttribute(standardTLV)
	assert.NoError(t, err)

	// Test valid IEEE 802.1X TLV
	ieee8021xTLV := &AttributeDefinition{
		Name:      "IEEE-TLV",
		ID:        101,
		DataType:  DataTypeTLV,
		TLVFormat: TLVFormatIEEE8021X,
	}

	err = dict.AddAttribute(ieee8021xTLV)
	assert.NoError(t, err)

	// Test TLV with no format (should default to standard)
	defaultTLV := &AttributeDefinition{
		Name:     "Default-TLV",
		ID:       102,
		DataType: DataTypeTLV,
		// TLVFormat not specified
	}

	err = dict.AddAttribute(defaultTLV)
	assert.NoError(t, err)
	// Verify it was set to standard format
	assert.Equal(t, TLVFormatStandard, defaultTLV.TLVFormat)

	// Test invalid TLV format
	invalidTLV := &AttributeDefinition{
		Name:      "Invalid-TLV",
		ID:        103,
		DataType:  DataTypeTLV,
		TLVFormat: "invalid-format",
	}

	err = dict.AddAttribute(invalidTLV)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported TLV format")

	// Test TLV format on non-TLV attribute (should be ignored)
	nonTLVWithFormat := &AttributeDefinition{
		Name:      "Non-TLV-With-Format",
		ID:        104,
		DataType:  DataTypeString,
		TLVFormat: TLVFormatIEEE8021X, // This should be ignored
	}

	err = dict.AddAttribute(nonTLVWithFormat)
	assert.NoError(t, err) // Should not fail for non-TLV attributes
}

func TestTLVFormatIntegration(t *testing.T) {
	dict := NewDictionary()

	// Add a standard TLV with sub-attributes
	standardTLV := &AttributeDefinition{
		Name:      "Standard-TLV-With-Subs",
		ID:        100,
		DataType:  DataTypeTLV,
		TLVFormat: TLVFormatStandard,
		SubAttributes: map[uint8]*TLVSubAttribute{
			1: {
				Name:     "Sub-String",
				Type:     1,
				DataType: DataTypeString,
			},
			255: { // Max value for 8-bit Type
				Name:     "Sub-Max-Type",
				Type:     255,
				DataType: DataTypeInteger,
			},
		},
	}

	err := dict.AddAttribute(standardTLV)
	assert.NoError(t, err)

	// Add an IEEE 802.1X TLV with sub-attributes
	ieee8021xTLV := &AttributeDefinition{
		Name:      "IEEE-TLV-With-Subs",
		ID:        101,
		DataType:  DataTypeTLV,
		TLVFormat: TLVFormatIEEE8021X,
		SubAttributes: map[uint8]*TLVSubAttribute{
			1: {
				Name:     "IEEE-Sub-String",
				Type:     1,
				DataType: DataTypeString,
			},
			127: { // Max value for 7-bit Type
				Name:     "IEEE-Sub-Max-Type",
				Type:     127,
				DataType: DataTypeInteger,
			},
		},
	}

	err = dict.AddAttribute(ieee8021xTLV)
	assert.NoError(t, err)

	// Verify attributes are retrievable and have correct formats
	retrieved, exists := dict.GetAttributeByName("Standard-TLV-With-Subs")
	assert.True(t, exists)
	assert.True(t, retrieved.IsStandardTLV())
	assert.True(t, retrieved.HasSubAttributes())

	retrieved, exists = dict.GetAttributeByName("IEEE-TLV-With-Subs")
	assert.True(t, exists)
	assert.True(t, retrieved.IsIEEE8021XTLV())
	assert.True(t, retrieved.HasSubAttributes())

	// Test sub-attribute retrieval
	subAttr, exists := retrieved.GetSubAttribute(1)
	assert.True(t, exists)
	assert.Equal(t, "IEEE-Sub-String", subAttr.Name)

	subAttr, exists = retrieved.GetSubAttributeByName("IEEE-Sub-Max-Type")
	assert.True(t, exists)
	assert.Equal(t, uint8(127), subAttr.Type)
}
