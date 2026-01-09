package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMikrotikVendorDefinition(t *testing.T) {
	assert.NotNil(t, MikrotikVendorDefinition)
	assert.Equal(t, uint32(14988), MikrotikVendorDefinition.ID)
	assert.Equal(t, "Mikrotik", MikrotikVendorDefinition.Name)
	assert.NotEmpty(t, MikrotikVendorDefinition.Attributes)

	// Check known Mikrotik attributes
	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range MikrotikVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify Mikrotik-Recv-Limit exists
	recvLimit, exists := attrMap["Mikrotik-Recv-Limit"]
	assert.True(t, exists, "Mikrotik-Recv-Limit should exist")
	if exists {
		assert.Equal(t, uint32(1), recvLimit.ID)
		assert.Equal(t, DataTypeInteger, recvLimit.DataType)
	}

	// Verify Mikrotik-Group exists
	group, exists := attrMap["Mikrotik-Group"]
	assert.True(t, exists, "Mikrotik-Group should exist")
	if exists {
		assert.Equal(t, uint32(3), group.ID)
		assert.Equal(t, DataTypeString, group.DataType)
	}

	// Verify Mikrotik-Host-IP exists
	hostIP, exists := attrMap["Mikrotik-Host-IP"]
	assert.True(t, exists, "Mikrotik-Host-IP should exist")
	if exists {
		assert.Equal(t, uint32(10), hostIP.ID)
		assert.Equal(t, DataTypeIPAddr, hostIP.DataType)
	}

	// Verify Mikrotik-Wireless-Enc-Algo exists and has values
	encAlgo, exists := attrMap["Mikrotik-Wireless-Enc-Algo"]
	assert.True(t, exists, "Mikrotik-Wireless-Enc-Algo should exist")
	if exists {
		assert.Equal(t, uint32(6), encAlgo.ID)
		assert.Equal(t, DataTypeInteger, encAlgo.DataType)

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

func TestNoDuplicateMikrotikAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range MikrotikVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate Mikrotik attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}
