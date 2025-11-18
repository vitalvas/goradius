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

func TestWISPrVendorDefinition(t *testing.T) {
	assert.NotNil(t, WISPrVendorDefinition)
	assert.Equal(t, uint32(14122), WISPrVendorDefinition.ID)
	assert.Equal(t, "WISPr", WISPrVendorDefinition.Name)
	assert.NotEmpty(t, WISPrVendorDefinition.Attributes)

	// Check known WISPr attributes
	attrMap := make(map[string]*dictionary.AttributeDefinition)
	for _, attr := range WISPrVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify WISPr-Location-Id exists
	locationID, exists := attrMap["WISPr-Location-Id"]
	assert.True(t, exists, "WISPr-Location-Id should exist")
	if exists {
		assert.Equal(t, uint32(1), locationID.ID)
		assert.Equal(t, dictionary.DataTypeString, locationID.DataType)
	}

	// Verify WISPr-Bandwidth-Min-Up exists
	bandwidthMinUp, exists := attrMap["WISPr-Bandwidth-Min-Up"]
	assert.True(t, exists, "WISPr-Bandwidth-Min-Up should exist")
	if exists {
		assert.Equal(t, uint32(5), bandwidthMinUp.ID)
		assert.Equal(t, dictionary.DataTypeInteger, bandwidthMinUp.DataType)
	}

	// Verify all 9 attributes exist
	assert.Len(t, WISPrVendorDefinition.Attributes, 9)
}

func TestMikrotikVendorDefinition(t *testing.T) {
	assert.NotNil(t, MikrotikVendorDefinition)
	assert.Equal(t, uint32(14988), MikrotikVendorDefinition.ID)
	assert.Equal(t, "Mikrotik", MikrotikVendorDefinition.Name)
	assert.NotEmpty(t, MikrotikVendorDefinition.Attributes)

	// Check known Mikrotik attributes
	attrMap := make(map[string]*dictionary.AttributeDefinition)
	for _, attr := range MikrotikVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify Mikrotik-Recv-Limit exists
	recvLimit, exists := attrMap["Mikrotik-Recv-Limit"]
	assert.True(t, exists, "Mikrotik-Recv-Limit should exist")
	if exists {
		assert.Equal(t, uint32(1), recvLimit.ID)
		assert.Equal(t, dictionary.DataTypeInteger, recvLimit.DataType)
	}

	// Verify Mikrotik-Group exists
	group, exists := attrMap["Mikrotik-Group"]
	assert.True(t, exists, "Mikrotik-Group should exist")
	if exists {
		assert.Equal(t, uint32(3), group.ID)
		assert.Equal(t, dictionary.DataTypeString, group.DataType)
	}

	// Verify Mikrotik-Host-IP exists
	hostIP, exists := attrMap["Mikrotik-Host-IP"]
	assert.True(t, exists, "Mikrotik-Host-IP should exist")
	if exists {
		assert.Equal(t, uint32(10), hostIP.ID)
		assert.Equal(t, dictionary.DataTypeIPAddr, hostIP.DataType)
	}

	// Verify Mikrotik-Wireless-Enc-Algo exists and has values
	encAlgo, exists := attrMap["Mikrotik-Wireless-Enc-Algo"]
	assert.True(t, exists, "Mikrotik-Wireless-Enc-Algo should exist")
	if exists {
		assert.Equal(t, uint32(6), encAlgo.ID)
		assert.Equal(t, dictionary.DataTypeInteger, encAlgo.DataType)

		// Verify values for Mikrotik-Wireless-Enc-Algo
		assert.NotNil(t, encAlgo.Values, "Mikrotik-Wireless-Enc-Algo should have defined values")
		if encAlgo.Values != nil {
			assert.Equal(t, uint32(0), encAlgo.Values["No-encryption"])
			assert.Equal(t, uint32(1), encAlgo.Values["40-bit-WEP"])
			assert.Equal(t, uint32(2), encAlgo.Values["104-bit-WEP"])
			assert.Equal(t, uint32(3), encAlgo.Values["AES-CCM"])
			assert.Equal(t, uint32(4), encAlgo.Values["TKIP"])
		}
	}

	// Verify all 29 attributes exist
	assert.Len(t, MikrotikVendorDefinition.Attributes, 29)
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

func TestNoDuplicateWISPrAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range WISPrVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate WISPr attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestNoDuplicateMikrotikAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range MikrotikVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate Mikrotik attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
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

	for _, attr := range WISPrVendorDefinition.Attributes {
		if !validDataTypes[attr.DataType] {
			t.Errorf("Invalid data type for WISPr %s: %s", attr.Name, attr.DataType)
		}
	}

	for _, attr := range MikrotikVendorDefinition.Attributes {
		if !validDataTypes[attr.DataType] {
			t.Errorf("Invalid data type for Mikrotik %s: %s", attr.Name, attr.DataType)
		}
	}
}

func TestDictionaryIntegration(t *testing.T) {
	// Test that dictionaries can be loaded into a dictionary
	dict := dictionary.New()

	dict.AddStandardAttributes(StandardRFCAttributes)
	dict.AddVendor(ERXVendorDefinition)
	dict.AddVendor(AscendVendorDefinition)
	dict.AddVendor(WISPrVendorDefinition)
	dict.AddVendor(MikrotikVendorDefinition)

	// Test standard attribute lookup
	_, exists := dict.LookupStandardByName("User-Name")
	assert.True(t, exists)

	// Test vendor lookup
	_, exists = dict.LookupVendorByID(4874)
	assert.True(t, exists)

	_, exists = dict.LookupVendorByID(529)
	assert.True(t, exists)

	_, exists = dict.LookupVendorByID(14122)
	assert.True(t, exists)

	_, exists = dict.LookupVendorByID(14988)
	assert.True(t, exists)

	// Test vendor attribute lookup
	_, exists = dict.LookupVendorAttributeByName("ERX", "ERX-Service-Activate")
	assert.True(t, exists)

	_, exists = dict.LookupVendorAttributeByName("WISPr", "WISPr-Location-Id")
	assert.True(t, exists)

	_, exists = dict.LookupVendorAttributeByName("Mikrotik", "Mikrotik-Group")
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

	// Verify WISPr vendor is loaded
	wisprVendor, exists := dict.LookupVendorByID(14122)
	assert.True(t, exists, "WISPr vendor should exist in default dictionary")
	assert.Equal(t, "WISPr", wisprVendor.Name)

	// Verify Mikrotik vendor is loaded
	mikrotikVendor, exists := dict.LookupVendorByID(14988)
	assert.True(t, exists, "Mikrotik vendor should exist in default dictionary")
	assert.Equal(t, "Mikrotik", mikrotikVendor.Name)

	// Verify ERX attribute lookup works
	_, exists = dict.LookupVendorAttributeByName("ERX", "ERX-Service-Activate")
	assert.True(t, exists, "ERX-Service-Activate should exist in default dictionary")

	// Verify WISPr attribute lookup works
	_, exists = dict.LookupVendorAttributeByName("WISPr", "WISPr-Location-Id")
	assert.True(t, exists, "WISPr-Location-Id should exist in default dictionary")

	// Verify Mikrotik attribute lookup works
	_, exists = dict.LookupVendorAttributeByName("Mikrotik", "Mikrotik-Group")
	assert.True(t, exists, "Mikrotik-Group should exist in default dictionary")

	// Verify Framed-IP-Address exists
	framedIPAttr, exists := dict.LookupStandardByName("Framed-IP-Address")
	assert.True(t, exists, "Framed-IP-Address should exist in default dictionary")
	assert.Equal(t, uint32(8), framedIPAttr.ID)
}

