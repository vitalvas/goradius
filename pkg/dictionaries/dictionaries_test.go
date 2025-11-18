package dictionaries

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vitalvas/goradius/pkg/dictionary"
)

func TestStandardRFCAttributes(t *testing.T) {
	assert.NotNil(t, StandardRFCAttributes)
	assert.NotEmpty(t, StandardRFCAttributes)

	// Check some well-known attributes
	nameMap := make(map[string]*dictionary.AttributeDefinition)
	idMap := make(map[uint32]*dictionary.AttributeDefinition)

	for _, attr := range StandardRFCAttributes {
		nameMap[attr.Name] = attr
		idMap[attr.ID] = attr
	}

	// Verify User-Name (ID 1)
	userNameAttr, exists := idMap[1]
	assert.True(t, exists, "User-Name attribute should exist")
	if exists {
		assert.Equal(t, "User-Name", userNameAttr.Name)
		assert.Equal(t, dictionary.DataTypeString, userNameAttr.DataType)
	}

	// Verify User-Password (ID 2)
	userPassAttr, exists := idMap[2]
	assert.True(t, exists, "User-Password attribute should exist")
	if exists {
		assert.Equal(t, "User-Password", userPassAttr.Name)
		assert.Equal(t, dictionary.DataTypeString, userPassAttr.DataType)
		assert.Equal(t, dictionary.EncryptionUserPassword, userPassAttr.Encryption)
	}

	// Verify NAS-IP-Address (ID 4)
	nasIPAttr, exists := idMap[4]
	assert.True(t, exists, "NAS-IP-Address attribute should exist")
	if exists {
		assert.Equal(t, "NAS-IP-Address", nasIPAttr.Name)
		assert.Equal(t, dictionary.DataTypeIPAddr, nasIPAttr.DataType)
	}

	// Verify Framed-IP-Address (ID 8)
	framedIPAttr, exists := idMap[8]
	assert.True(t, exists, "Framed-IP-Address attribute should exist")
	if exists {
		assert.Equal(t, "Framed-IP-Address", framedIPAttr.Name)
		assert.Equal(t, dictionary.DataTypeIPAddr, framedIPAttr.DataType)
	}
}

func TestERXVendorDefinition(t *testing.T) {
	assert.NotNil(t, ERXVendorDefinition)
	assert.Equal(t, uint32(4874), ERXVendorDefinition.ID)
	assert.Equal(t, "ERX", ERXVendorDefinition.Name)
	assert.NotEmpty(t, ERXVendorDefinition.Attributes)

	// Check some known ERX attributes
	attrMap := make(map[string]*dictionary.AttributeDefinition)
	for _, attr := range ERXVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify ERX-Service-Activate exists and has tag
	serviceActivate, exists := attrMap["ERX-Service-Activate"]
	assert.True(t, exists, "ERX-Service-Activate should exist")
	if exists {
		assert.True(t, serviceActivate.HasTag, "ERX-Service-Activate should support tags")
		assert.Equal(t, dictionary.DataTypeString, serviceActivate.DataType)
	}

	// Verify ERX-Primary-Dns exists
	primaryDNS, exists := attrMap["ERX-Primary-Dns"]
	assert.True(t, exists, "ERX-Primary-Dns should exist")
	if exists {
		assert.Equal(t, dictionary.DataTypeIPAddr, primaryDNS.DataType)
	}
}

func TestAscendVendorDefinition(t *testing.T) {
	assert.NotNil(t, AscendVendorDefinition)
	assert.Equal(t, uint32(529), AscendVendorDefinition.ID)
	assert.Equal(t, "Ascend", AscendVendorDefinition.Name)
	assert.NotEmpty(t, AscendVendorDefinition.Attributes)

	// Verify vendor has attributes
	assert.Greater(t, len(AscendVendorDefinition.Attributes), 0)
}

func TestNoDuplicateStandardAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range StandardRFCAttributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestNoDuplicateStandardAttributeNames(t *testing.T) {
	seen := make(map[string]uint32)

	for _, attr := range StandardRFCAttributes {
		if existing, exists := seen[attr.Name]; exists {
			t.Errorf("Duplicate attribute name %s: ID %d and %d", attr.Name, existing, attr.ID)
		}
		seen[attr.Name] = attr.ID
	}
}

func TestNoDuplicateERXAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range ERXVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate ERX attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestNoDuplicateAscendAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range AscendVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate Ascend attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestAllAttributesHaveValidDataTypes(t *testing.T) {
	validDataTypes := map[dictionary.DataType]bool{
		dictionary.DataTypeString:     true,
		dictionary.DataTypeOctets:     true,
		dictionary.DataTypeInteger:    true,
		dictionary.DataTypeIPAddr:     true,
		dictionary.DataTypeDate:       true,
		dictionary.DataTypeIPv6Addr:   true,
		dictionary.DataTypeIPv6Prefix: true,
		dictionary.DataTypeIfID:       true,
		dictionary.DataTypeTLV:        true,
		dictionary.DataTypeABinary:    true,
	}

	for _, attr := range StandardRFCAttributes {
		if !validDataTypes[attr.DataType] {
			t.Errorf("Invalid data type for %s: %s", attr.Name, attr.DataType)
		}
	}

	for _, attr := range ERXVendorDefinition.Attributes {
		if !validDataTypes[attr.DataType] {
			t.Errorf("Invalid data type for ERX %s: %s", attr.Name, attr.DataType)
		}
	}

	for _, attr := range AscendVendorDefinition.Attributes {
		if !validDataTypes[attr.DataType] {
			t.Errorf("Invalid data type for Ascend %s: %s", attr.Name, attr.DataType)
		}
	}
}

func TestDictionaryIntegration(t *testing.T) {
	// Test that dictionaries can be loaded into a dictionary
	dict := dictionary.New()

	dict.AddStandardAttributes(StandardRFCAttributes)
	dict.AddVendor(ERXVendorDefinition)
	dict.AddVendor(AscendVendorDefinition)

	// Test standard attribute lookup
	_, exists := dict.LookupStandardByName("User-Name")
	assert.True(t, exists)

	// Test vendor lookup
	_, exists = dict.LookupVendorByID(4874)
	assert.True(t, exists)

	_, exists = dict.LookupVendorByID(529)
	assert.True(t, exists)

	// Test vendor attribute lookup
	_, exists = dict.LookupVendorAttributeByName("ERX", "ERX-Service-Activate")
	assert.True(t, exists)
}

func TestNewDefault(t *testing.T) {
	dict := NewDefault()
	assert.NotNil(t, dict)

	// Verify standard attributes are loaded
	userNameAttr, exists := dict.LookupStandardByName("User-Name")
	assert.True(t, exists, "User-Name should exist in default dictionary")
	assert.Equal(t, uint32(1), userNameAttr.ID)

	// Verify ERX vendor is loaded
	erxVendor, exists := dict.LookupVendorByID(4874)
	assert.True(t, exists, "ERX vendor should exist in default dictionary")
	assert.Equal(t, "ERX", erxVendor.Name)

	// Verify Ascend vendor is loaded
	ascendVendor, exists := dict.LookupVendorByID(529)
	assert.True(t, exists, "Ascend vendor should exist in default dictionary")
	assert.Equal(t, "Ascend", ascendVendor.Name)

	// Verify ERX attribute lookup works
	_, exists = dict.LookupVendorAttributeByName("ERX", "ERX-Service-Activate")
	assert.True(t, exists, "ERX-Service-Activate should exist in default dictionary")

	// Verify Framed-IP-Address exists
	framedIPAttr, exists := dict.LookupStandardByName("Framed-IP-Address")
	assert.True(t, exists, "Framed-IP-Address should exist in default dictionary")
	assert.Equal(t, uint32(8), framedIPAttr.ID)
}

